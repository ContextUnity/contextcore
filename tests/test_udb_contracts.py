"""Closed UniversalDebugBus contract tests.

The UDB lifecycle is implemented in Brain, but these shared models freeze the
cross-service occurrence/recovery boundary before an SDK or storage adapter is
added.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from contextunity.core.udb import (
    DebugCase,
    ErrorEvidencePolicyV1,
    FaultOccurrence,
    MitigationAttempt,
    RecoveryEvidence,
    UdbComparisonKey,
)
from pydantic import ValidationError


def _comparison_key() -> UdbComparisonKey:
    return UdbComparisonKey(
        tenant_id="acme",
        operation_kind="brain_search",
        subject_ref="cell:ab12",
        effect_ref=None,
        capability_class="brain:search",
    )


def _occurrence() -> FaultOccurrence:
    return FaultOccurrence(
        occurrence_id=uuid4(),
        tenant_id="acme",
        producer_id="router:node-a",
        idempotency_key="run-1:brain-search:1",
        fingerprint_version="contextunity.udb-fingerprint/v1",
        fingerprint="a" * 64,
        fault_class="upstream_fault",
        operation_kind="brain_search",
        fault_code="brain.search.unavailable",
        comparison_key=_comparison_key(),
        trace_id=uuid4(),
        graph_run_id=uuid4(),
        node_id="retrieve",
    )


def test_fault_occurrence_is_closed_and_binds_comparable_scope() -> None:
    occurrence = _occurrence()

    assert occurrence.comparison_key.tenant_id == occurrence.tenant_id
    assert occurrence.fault_code == "brain.search.unavailable"

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        FaultOccurrence.model_validate(
            {
                **occurrence.model_dump(mode="json"),
                "raw_exception": "database password=secret",
            }
        )


def test_fault_occurrence_rejects_raw_content_in_evidence_refs_or_identity() -> None:
    with pytest.raises(ValidationError, match="subject_ref"):
        UdbComparisonKey(
            tenant_id="acme",
            operation_kind="brain_search",
            subject_ref="raw user prompt with spaces",
            capability_class="brain:search",
        )
    with pytest.raises(ValidationError, match="idempotency_key"):
        FaultOccurrence.model_validate(
            {
                **_occurrence().model_dump(mode="json"),
                "idempotency_key": "raw user prompt with spaces",
            }
        )


def test_fault_occurrence_rejects_cross_tenant_comparison_key() -> None:
    with pytest.raises(ValidationError, match="comparison_key tenant_id"):
        FaultOccurrence.model_validate(
            {
                **_occurrence().model_dump(mode="json"),
                "comparison_key": {
                    **_comparison_key().model_dump(mode="json"),
                    "tenant_id": "other-tenant",
                },
            }
        )


def test_recovery_requires_same_policy_and_comparison_key() -> None:
    occurrence = _occurrence()
    recovery = RecoveryEvidence(
        recovery_id=uuid4(),
        case_id=uuid4(),
        policy_version="contextunity.error-evidence/v1",
        comparison_key=occurrence.comparison_key,
        expected_case_revision=2,
        exposure_id="probe-1",
        verified_at="2026-07-16T12:00:00+00:00",
    )

    policy = ErrorEvidencePolicyV1()
    assert policy.q_error(fault_count=2, success_count=1) == pytest.approx(0.6)
    assert policy.is_comparable(occurrence.comparison_key, recovery.comparison_key)

    with pytest.raises(ValidationError, match="policy_version"):
        RecoveryEvidence(
            recovery_id=uuid4(),
            case_id=uuid4(),
            policy_version="contextunity.error-evidence/v2",
            comparison_key=occurrence.comparison_key,
            expected_case_revision=2,
            exposure_id="probe-2",
            verified_at="2026-07-16T12:00:00+00:00",
        )


def test_debug_case_and_mutation_contracts_are_revision_bound() -> None:
    occurrence = _occurrence()
    case = DebugCase(
        case_id=uuid4(),
        tenant_id=occurrence.tenant_id,
        fingerprint_version=occurrence.fingerprint_version,
        fingerprint=occurrence.fingerprint,
        fault_class=occurrence.fault_class,
        operation_kind=occurrence.operation_kind,
        policy_version="contextunity.error-evidence/v1",
        comparison_key=occurrence.comparison_key,
        state="open",
        fault_count=2,
        success_count=1,
        q_error=0.6,
        case_revision=3,
        first_occurred_at="2026-07-16T12:00:00+00:00",
        last_occurred_at="2026-07-16T12:01:00+00:00",
    )
    assert case.q_error == pytest.approx(0.6)

    mitigation = MitigationAttempt(
        attempt_id=uuid4(),
        case_id=case.case_id,
        expected_case_revision=case.case_revision,
        kind="retry",
        idempotency_key="retry-1",
        attempted_at="2026-07-16T12:02:00+00:00",
    )
    assert mitigation.expected_case_revision == 3

    with pytest.raises(ValidationError, match="q_error"):
        DebugCase.model_validate({**case.model_dump(mode="json"), "q_error": 0.5})

    with pytest.raises(ValidationError, match="expected_case_revision"):
        RecoveryEvidence.model_validate(
            {
                "recovery_id": str(uuid4()),
                "case_id": str(case.case_id),
                "policy_version": "contextunity.error-evidence/v1",
                "comparison_key": occurrence.comparison_key.model_dump(mode="json"),
                "exposure_id": "probe-without-revision",
                "verified_at": "2026-07-16T12:03:00+00:00",
            }
        )
