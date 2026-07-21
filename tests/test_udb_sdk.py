"""Typed Brain SDK coverage for the live UDB RPC subset."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from contextunity.core import contextunit_pb2
from contextunity.core.sdk.clients import BrainClient
from contextunity.core.sdk.contextunit import ContextUnit
from contextunity.core.udb import (
    DebugCase,
    DebugCaseDetail,
    DebugCaseMitigationView,
    DebugCaseOccurrenceView,
    DebugCaseQuery,
    DebugCaseRecoveryView,
    DebugCaseTransitionView,
    FaultOccurrence,
    UdbComparisonKey,
)
from google.protobuf.json_format import MessageToDict


def _occurrence() -> FaultOccurrence:
    return FaultOccurrence(
        occurrence_id=uuid4(),
        tenant_id="acme",
        producer_id="router:test",
        idempotency_key="run:1",
        fingerprint_version="contextunity.udb-fingerprint/v1",
        fingerprint="a" * 64,
        fault_class="upstream_fault",
        operation_kind="brain_search",
        fault_code="brain.search.unavailable",
        comparison_key=UdbComparisonKey(
            tenant_id="acme",
            operation_kind="brain_search",
            capability_class="brain:search",
        ),
        occurred_at=datetime(2026, 7, 16, 12, 0, tzinfo=UTC),
    )


def _case(occurrence: FaultOccurrence) -> DebugCase:
    return DebugCase(
        case_id=occurrence.occurrence_id,
        tenant_id=occurrence.tenant_id,
        fingerprint_version=occurrence.fingerprint_version,
        fingerprint=occurrence.fingerprint,
        fault_class=occurrence.fault_class,
        operation_kind=occurrence.operation_kind,
        policy_version=occurrence.policy_version,
        comparison_key=occurrence.comparison_key,
        state="open",
        fault_count=1,
        success_count=0,
        q_error=2 / 3,
        case_revision=1,
        first_occurred_at=occurrence.occurred_at,
        last_occurred_at=occurrence.occurred_at,
    )


@pytest.mark.asyncio
async def test_brain_sdk_reports_closed_occurrence_and_parses_case() -> None:
    occurrence = _occurrence()
    expected = _case(occurrence)
    captured: dict[str, object] = {}

    class _Stub:
        async def ReportFaultOccurrence(self, request, metadata=None):
            captured["payload"] = MessageToDict(request.payload)
            return ContextUnit(payload={"case": expected.model_dump(mode="json")}).to_protobuf(contextunit_pb2)

    client = BrainClient.__new__(BrainClient)
    client._stub = _Stub()
    client._cu_pb2 = contextunit_pb2
    client._get_metadata = lambda: ()

    result = await client.report_fault_occurrence(occurrence)

    assert result == expected
    assert captured["payload"] == {"occurrence": occurrence.model_dump(mode="json")}


@pytest.mark.asyncio
async def test_brain_sdk_consumes_bounded_debug_case_stream() -> None:
    occurrence = _occurrence()
    expected = _case(occurrence)
    captured: dict[str, object] = {}

    class _Stub:
        async def QueryDebugCases(self, request, metadata=None):
            captured["payload"] = MessageToDict(request.payload)
            for _ in range(2):
                yield ContextUnit(payload={"case": expected.model_dump(mode="json")}).to_protobuf(contextunit_pb2)

    client = BrainClient.__new__(BrainClient)
    client._stub = _Stub()
    client._cu_pb2 = contextunit_pb2
    client._get_metadata = lambda: ()

    result = await client.query_debug_cases(DebugCaseQuery(limit=2))

    assert result == [expected, expected]
    assert captured["payload"] == {
        "query": {
            "state": None,
            "minimum_fault_count": 1.0,
            "trace_id": None,
            "graph_run_id": None,
            "limit": 2.0,
        }
    }


@pytest.mark.asyncio
async def test_brain_sdk_gets_bounded_debug_case_detail_with_typed_trace_refs() -> None:
    occurrence = _occurrence().model_copy(update={"trace_id": uuid4(), "graph_run_id": uuid4()})
    case = _case(occurrence)
    detail = DebugCaseDetail(
        case=case,
        occurrences=(
            DebugCaseOccurrenceView(
                occurrence_id=occurrence.occurrence_id,
                fault_code=occurrence.fault_code,
                trace_id=occurrence.trace_id,
                graph_run_id=occurrence.graph_run_id,
                node_id=None,
                step_id=None,
                occurred_at=occurrence.occurred_at,
            ),
        ),
        mitigations=(
            DebugCaseMitigationView(
                attempt_id=uuid4(),
                expected_case_revision=1,
                kind="retry",
                attempted_at=datetime(2026, 7, 16, 12, 1, tzinfo=UTC),
            ),
        ),
        recoveries=(
            DebugCaseRecoveryView(
                recovery_id=uuid4(),
                expected_case_revision=2,
                exposure_id="run:1:recovery",
                kind="comparable_success",
                verified_at=datetime(2026, 7, 16, 12, 2, tzinfo=UTC),
            ),
        ),
        transitions=(
            DebugCaseTransitionView(
                transition_id="run:1:resolved",
                transition_kind="resolved",
                expected_case_revision=3,
                trigger_occurrence_id=None,
                transitioned_at=datetime(2026, 7, 16, 12, 3, tzinfo=UTC),
            ),
        ),
    )
    captured: dict[str, object] = {}

    class _Stub:
        async def GetDebugCase(self, request, metadata=None):
            captured["payload"] = MessageToDict(request.payload)
            return ContextUnit(payload={"detail": detail.model_dump(mode="json")}).to_protobuf(contextunit_pb2)

    client = BrainClient.__new__(BrainClient)
    client._stub = _Stub()
    client._cu_pb2 = contextunit_pb2
    client._get_metadata = lambda: ()

    result = await client.get_debug_case_detail(case.case_id, history_limit=5)

    assert result == detail
    assert captured["payload"] == {
        "case_id": str(case.case_id),
        "include_history": True,
        "history_limit": 5.0,
    }


@pytest.mark.asyncio
async def test_trace_inspection_is_typed_and_drops_legacy_sensitive_fields() -> None:
    from contextunity.core.trace_inspection import TraceInspection

    trace_id = uuid4()

    class _Stub:
        async def AdminGetTraceDetails(self, request, metadata=None):
            return ContextUnit(
                payload={
                    "trace": {
                        "id": str(trace_id),
                        "tenant_id": "acme",
                        "agent_id": "agent-a",
                        "graph_name": "rag",
                        "timing_ms": 12,
                        "terminal_status": "succeeded",
                        "metadata": {"secret": "must-not-render"},
                        "prompt_evidence": {"raw": "must-not-render"},
                        "tool_calls": [{"arguments": "must-not-render"}],
                        "steps": [{"name": "must-not-render"}],
                    }
                }
            ).to_protobuf(contextunit_pb2)

    client = BrainClient.__new__(BrainClient)
    client._stub = _Stub()
    client._cu_pb2 = contextunit_pb2
    client._get_metadata = lambda: ()

    result = await client.get_trace_inspection(str(trace_id))

    assert result == TraceInspection(
        id=trace_id,
        tenant_id="acme",
        agent_id="agent-a",
        graph_name="rag",
        timing_ms=12,
        terminal_status="succeeded",
    )
    assert set(result.model_dump(mode="json")) == {
        "id",
        "tenant_id",
        "agent_id",
        "graph_name",
        "graph_run_id",
        "timing_ms",
        "terminal_status",
        "created_at",
    }


@pytest.mark.asyncio
async def test_admin_trace_search_rejects_noncanonical_status_before_rpc() -> None:
    client = BrainClient.__new__(BrainClient)
    with pytest.raises(ValueError, match="terminal Trace status"):
        await client.admin_search_traces(status="")
    with pytest.raises(ValueError, match="terminal Trace status"):
        await client.admin_search_traces(status="unknown")
