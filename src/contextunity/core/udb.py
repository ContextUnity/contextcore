"""Closed shared contracts for UniversalDebugBus negative-experience evidence.

The Brain service owns occurrence/case/recovery persistence and queries. This
module owns only the cross-service L4 contracts that producers, SDK adapters,
and the Brain-local application port must agree on. It intentionally contains
no open metadata bag or raw exception/content field.
"""

from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
from json import dumps as canonical_dumps
from math import isclose
from typing import Literal
from uuid import UUID

from contextunity.core.faults import FaultClass
from pydantic import BaseModel, ConfigDict, Field, model_validator

UdbFingerprintVersion = Literal["contextunity.udb-fingerprint/v1"]
"""The stable fingerprint algorithm/version accepted by the initial UDB slice."""

ErrorEvidencePolicyVersion = Literal["contextunity.error-evidence/v1"]
"""The comparable-exposure policy/version accepted by the initial UDB slice."""

UdbOperationKind = Literal[
    "brain_search",
    "brain_read",
    "auto_extract",
    "secure_node",
    "synapse_record",
    "memory_synthesis",
    "embedding_enrichment",
    "model_invocation",
    "tool_invocation",
]
"""Closed operation families represented by the existing Phase 4 producers."""

RecoveryKind = Literal["verified_recovery_probe", "comparable_success"]
"""Only positive evidence that may contribute to a UDB recovery calculation."""

DebugCaseState = Literal["open", "resolved"]
"""The initial DebugCase lifecycle; faults reopen resolved cases transactionally."""

MitigationKind = Literal["retry", "mitigation", "manual_probe"]
"""Actions recorded as negative-path history but never counted as recovery success."""


class UdbComparisonKey(BaseModel):
    """Closed key defining when a fault and success exposure are comparable.

    The policy owner selects the key; callers cannot mark a result comparable
    with a boolean. All fields participate in equality.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(min_length=1, max_length=128)
    operation_kind: UdbOperationKind
    subject_ref: str | None = Field(
        default=None,
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$",
    )
    effect_ref: str | None = Field(
        default=None,
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$",
    )
    capability_class: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9:_-]*(?:[.][a-z0-9:_-]+)*$",
    )


def udb_fingerprint(*, fault_code: str, comparison_key: UdbComparisonKey) -> str:
    """Return the stable v1 digest from explicitly safe, closed inputs only."""
    return sha256(
        canonical_dumps(
            {
                "comparison_key": comparison_key.model_dump(mode="json"),
                "fault_code": fault_code,
                "fingerprint_version": "contextunity.udb-fingerprint/v1",
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


class FaultOccurrence(BaseModel):
    """One immutable, redacted, idempotent negative-experience occurrence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    occurrence_id: UUID
    tenant_id: str = Field(min_length=1, max_length=128)
    producer_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9:_-]*(?:[.][a-z0-9:_-]+)*$",
    )
    idempotency_key: str = Field(
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$",
    )
    fingerprint_version: UdbFingerprintVersion
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    fault_class: FaultClass
    operation_kind: UdbOperationKind
    fault_code: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_-]*(?:[.][a-z0-9_-]+)*$",
    )
    policy_version: ErrorEvidencePolicyVersion = "contextunity.error-evidence/v1"
    comparison_key: UdbComparisonKey
    trace_id: UUID | None = None
    graph_run_id: UUID | None = None
    node_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$",
    )
    step_id: UUID | None = None
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def _validate_comparison_scope(self) -> "FaultOccurrence":
        """Reject caller-supplied comparison keys that widen a tenant/operation."""
        if self.comparison_key.tenant_id != self.tenant_id:
            raise ValueError("comparison_key tenant_id must equal occurrence tenant_id")
        if self.comparison_key.operation_kind != self.operation_kind:
            raise ValueError("comparison_key operation_kind must equal occurrence operation_kind")
        return self


class RecoveryEvidence(BaseModel):
    """Immutable, policy-bound positive evidence for one existing DebugCase."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    recovery_id: UUID
    case_id: UUID
    policy_version: ErrorEvidencePolicyVersion
    comparison_key: UdbComparisonKey
    expected_case_revision: int = Field(ge=1)
    exposure_id: str = Field(
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$",
    )
    kind: RecoveryKind = "verified_recovery_probe"
    verified_at: datetime


class MitigationAttempt(BaseModel):
    """Immutable attempted mitigation; it never increments comparable success."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    attempt_id: UUID
    case_id: UUID
    expected_case_revision: int = Field(ge=1)
    kind: MitigationKind
    idempotency_key: str = Field(
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$",
    )
    attempted_at: datetime


class ResolveDebugCase(BaseModel):
    """Revision-bound explicit case resolution after sufficient recovery evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: UUID
    expected_case_revision: int = Field(ge=1)
    resolution_id: str = Field(
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$",
    )
    resolved_at: datetime


class ReopenDebugCase(BaseModel):
    """Revision-bound explicit reopen linked to a persisted trigger occurrence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: UUID
    expected_case_revision: int = Field(ge=1)
    reopen_id: str = Field(
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$",
    )
    trigger_occurrence_id: UUID
    reopened_at: datetime


class DebugCaseOccurrenceView(BaseModel):
    """Bounded raw-content-free occurrence row for operator correlation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    occurrence_id: UUID
    fault_code: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_-]*(?:[.][a-z0-9_-]+)*$",
    )
    trace_id: UUID | None = None
    graph_run_id: UUID | None = None
    node_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$",
    )
    step_id: UUID | None = None
    occurred_at: datetime


class DebugCaseMitigationView(BaseModel):
    """Bounded mitigation history without replay or idempotency authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    attempt_id: UUID
    expected_case_revision: int = Field(ge=1)
    kind: MitigationKind
    attempted_at: datetime


class DebugCaseRecoveryView(BaseModel):
    """Bounded verified-recovery history without comparison-key duplication."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    recovery_id: UUID
    expected_case_revision: int = Field(ge=1)
    exposure_id: str = Field(
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$",
    )
    kind: RecoveryKind
    verified_at: datetime


class DebugCaseTransitionView(BaseModel):
    """Bounded resolution/reopen history for one tenant-owned case."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    transition_id: str = Field(
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$",
    )
    transition_kind: Literal["resolved", "reopened"]
    expected_case_revision: int = Field(ge=1)
    trigger_occurrence_id: UUID | None = None
    transitioned_at: datetime


class DebugCaseQuery(BaseModel):
    """Bounded tenant query selected by verified context, never payload tenancy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    state: DebugCaseState | None = None
    minimum_fault_count: int = Field(default=1, ge=1)
    trace_id: UUID | None = None
    graph_run_id: UUID | None = None
    limit: int = Field(default=20, ge=1, le=100)


class ErrorEvidencePolicyV1(BaseModel):
    """Versioned comparable-exposure and ``q_error`` policy for UDB v1."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: ErrorEvidencePolicyVersion = "contextunity.error-evidence/v1"
    minimum_success_count: int = Field(default=1, ge=1, le=1_000)

    def is_comparable(self, left: UdbComparisonKey, right: UdbComparisonKey) -> bool:
        """Return whether two closed keys belong to one exposure population."""
        return left == right

    def q_error(self, *, fault_count: int, success_count: int) -> float:
        """Calculate the accepted v1 score without time-based decay."""
        if fault_count < 0 or success_count < 0:
            raise ValueError("fault_count and success_count must be non-negative")
        return (fault_count + 1) / (fault_count + success_count + 2)


class DebugCase(BaseModel):
    """Tenant-scoped aggregate over immutable UDB occurrence/recovery evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: UUID
    tenant_id: str = Field(min_length=1, max_length=128)
    fingerprint_version: UdbFingerprintVersion
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    fault_class: FaultClass
    operation_kind: UdbOperationKind
    policy_version: ErrorEvidencePolicyVersion
    comparison_key: UdbComparisonKey
    state: DebugCaseState
    fault_count: int = Field(ge=1)
    success_count: int = Field(ge=0)
    q_error: float = Field(ge=0.0, le=1.0)
    case_revision: int = Field(ge=1)
    first_occurred_at: datetime
    last_occurred_at: datetime
    resolved_at: datetime | None = None

    @model_validator(mode="after")
    def _validate_aggregate(self) -> "DebugCase":
        """Keep aggregate state reproducible from immutable comparable evidence."""
        if self.comparison_key.tenant_id != self.tenant_id:
            raise ValueError("comparison_key tenant_id must equal case tenant_id")
        if self.comparison_key.operation_kind != self.operation_kind:
            raise ValueError("comparison_key operation_kind must equal case operation_kind")
        if self.last_occurred_at < self.first_occurred_at:
            raise ValueError("last_occurred_at must not precede first_occurred_at")
        if self.state == "resolved" and self.resolved_at is None:
            raise ValueError("resolved DebugCase requires resolved_at")
        if self.state == "open" and self.resolved_at is not None:
            raise ValueError("open DebugCase cannot retain resolved_at")
        expected = ErrorEvidencePolicyV1(version=self.policy_version).q_error(
            fault_count=self.fault_count,
            success_count=self.success_count,
        )
        if not isclose(self.q_error, expected, rel_tol=0.0, abs_tol=1e-12):
            raise ValueError("q_error must match ErrorEvidencePolicy/v1 exposure counts")
        return self


class DebugCaseDetail(BaseModel):
    """One case plus independently bounded, raw-content-free history lists."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case: DebugCase
    occurrences: tuple[DebugCaseOccurrenceView, ...] = Field(default=(), max_length=100)
    mitigations: tuple[DebugCaseMitigationView, ...] = Field(default=(), max_length=100)
    recoveries: tuple[DebugCaseRecoveryView, ...] = Field(default=(), max_length=100)
    transitions: tuple[DebugCaseTransitionView, ...] = Field(default=(), max_length=100)


__all__ = [
    "DebugCase",
    "DebugCaseDetail",
    "DebugCaseMitigationView",
    "DebugCaseOccurrenceView",
    "DebugCaseQuery",
    "DebugCaseRecoveryView",
    "DebugCaseState",
    "DebugCaseTransitionView",
    "ErrorEvidencePolicyV1",
    "ErrorEvidencePolicyVersion",
    "FaultOccurrence",
    "MitigationAttempt",
    "MitigationKind",
    "RecoveryEvidence",
    "ReopenDebugCase",
    "ResolveDebugCase",
    "RecoveryKind",
    "UdbComparisonKey",
    "UdbFingerprintVersion",
    "UdbOperationKind",
    "udb_fingerprint",
]
