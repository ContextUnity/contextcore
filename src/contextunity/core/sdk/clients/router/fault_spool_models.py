"""Sanitized typed payloads for Router's local FaultSpool RPC surface.

These are wire/SDK contracts only.  Router owns the SQLite/WAL implementation,
its C0 configuration, legacy import, and replay lifecycle.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

FaultSpoolDeliveryKind = Literal["occurrence", "recovery"]
FaultSpoolState = Literal["pending", "replayed", "poison", "discarded_by_policy"]


class FaultSpoolAcknowledgement(BaseModel):
    """Bounded durable UDB receipt required for the ``replayed`` transition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: UUID
    case_revision: int = Field(ge=1)
    acknowledged_at: datetime


class FaultSpoolPolicyDisposition(BaseModel):
    """Authorized operator receipt required for a Router policy discard."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    disposition_id: str = Field(
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$",
    )
    actor_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$",
    )
    reason_code: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_-]*(?:[.][a-z0-9_-]+)*$",
    )
    disposed_at: datetime


class FaultSpoolStatus(BaseModel):
    """Tenant-free bounded projection of one Router instance's spool."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pending_count: int = Field(ge=0)
    replayed_count: int = Field(ge=0)
    poison_count: int = Field(ge=0)
    discarded_by_policy_count: int = Field(ge=0)
    oldest_pending_age_seconds: int | None = Field(default=None, ge=0)
    capacity_state: Literal["drained", "available", "near_limit", "full"]
    last_error_code: str | None = Field(default=None, max_length=128)


class FaultSpoolOperatorStatus(BaseModel):
    """Gate-aware, tenant-free status returned by Router to CLI and Forge."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool
    status: FaultSpoolStatus | None = None


class FaultSpoolOperatorRecord(BaseModel):
    """Sanitized Router inspection record with no tenant or delivery payload."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    record_id: UUID
    delivery_kind: FaultSpoolDeliveryKind
    state: FaultSpoolState
    attempt_count: int = Field(ge=0)
    next_attempt_at: datetime
    last_error_code: str | None = Field(default=None, max_length=128)
    acknowledgement: FaultSpoolAcknowledgement | None = None
    policy_disposition: FaultSpoolPolicyDisposition | None = None


class FaultSpoolRecordOutcome(BaseModel):
    """Typed terminal or pending outcome for one Router replay attempt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    record_id: UUID
    state: FaultSpoolState
    last_error_code: str | None = Field(default=None, max_length=128)


class FaultSpoolBatchResult(BaseModel):
    """Bounded Router replay result; a lease conflict is explicit."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    lease_acquired: bool
    claimed_count: int = Field(ge=0, le=1_000)
    outcomes: tuple[FaultSpoolRecordOutcome, ...] = Field(default_factory=tuple, max_length=1_000)
    status: FaultSpoolStatus


class FaultSpoolTerminalPurgeResult(BaseModel):
    """Immutable evidence for one authorized bounded terminal-retention action."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    purge_id: UUID
    actor_id: str = Field(min_length=1, max_length=128)
    purged_count: int = Field(ge=0, le=10_000)
    retention_seconds: int = Field(ge=60)
    purged_at: datetime


__all__ = [
    "FaultSpoolAcknowledgement",
    "FaultSpoolBatchResult",
    "FaultSpoolDeliveryKind",
    "FaultSpoolOperatorRecord",
    "FaultSpoolOperatorStatus",
    "FaultSpoolPolicyDisposition",
    "FaultSpoolRecordOutcome",
    "FaultSpoolState",
    "FaultSpoolStatus",
    "FaultSpoolTerminalPurgeResult",
]
