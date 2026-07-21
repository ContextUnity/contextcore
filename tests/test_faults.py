"""Tests for the shared fault taxonomy. Covers the exception-classification
scenario table:

| Scenario           | Expected class    |
|--------------------|--------------------|
| LLM invalid output | agent_fault        |
| DB timeout         | infra_fault        |
| External API 429   | upstream_fault     |
| Tenant mismatch    | policy_fault       |
| Expired ref        | reference_fault    |
"""

from __future__ import annotations

import pytest
from contextunity.core.faults import (
    AGENT_FAULT,
    FAULT_CLASSES,
    INFRA_FAULT,
    POLICY_FAULT,
    REFERENCE_FAULT,
    UPSTREAM_FAULT,
    classify_exception,
    fault_event,
    is_fault_class,
    penalizes_agent_q,
)
from contextunity.core.passbyref import ReferenceExpiredError
from pydantic import BaseModel, ValidationError


class _StrictModel(BaseModel):
    n: int


class _FakeHttpError(Exception):
    """Duck-typed stand-in for an httpx/requests-style client error — no
    dependency on a specific HTTP library, matching how real third-party
    exceptions expose a status code."""

    def __init__(self, status_code: int) -> None:
        super().__init__(f"HTTP {status_code}")
        self.status_code = status_code


class _FakeHttpErrorWithResponse(Exception):
    """Some HTTP libraries put the status on `.response.status_code` instead
    of directly on the exception."""

    class _Response:
        def __init__(self, status_code: int) -> None:
            self.status_code = status_code

    def __init__(self, status_code: int) -> None:
        super().__init__(f"HTTP {status_code}")
        self.response = self._Response(status_code)


class _FakeTenantMismatchError(Exception):
    """Stand-in for a service-owned typed error that already declares its own
    class (e.g. Brain's ``SynapseTenantMismatchError``) — ``packages/core``
    must not import a downstream service's exceptions in its own tests, so
    this fake proves the "trust an already-declared fault_class" rule
    without that dependency-direction violation."""

    fault_class = "policy_fault"


class TestFaultClasses:
    def test_exactly_five_classes(self):
        assert len(FAULT_CLASSES) == 5
        assert set(FAULT_CLASSES) == {
            "agent_fault",
            "infra_fault",
            "upstream_fault",
            "policy_fault",
            "reference_fault",
        }

    def test_named_constants_match_tuple(self):
        assert (AGENT_FAULT, INFRA_FAULT, UPSTREAM_FAULT, POLICY_FAULT, REFERENCE_FAULT) == FAULT_CLASSES

    def test_is_fault_class(self):
        for name in FAULT_CLASSES:
            assert is_fault_class(name)
        assert not is_fault_class("bogus")
        assert not is_fault_class(None)
        assert not is_fault_class(42)


class TestPenalizesAgentQ:
    def test_only_agent_fault_penalizes(self):
        assert penalizes_agent_q("agent_fault") is True
        for other in ("infra_fault", "upstream_fault", "policy_fault", "reference_fault"):
            assert penalizes_agent_q(other) is False

    def test_none_does_not_penalize(self):
        assert penalizes_agent_q(None) is False


class TestClassifyExceptionScenarioTable:
    """One test per row of the module docstring's scenario table."""

    def test_llm_invalid_output_is_agent_fault(self):
        with pytest.raises(ValidationError) as exc:
            _StrictModel(n="not-an-int")
        assert classify_exception(exc.value) == "agent_fault"

    def test_db_timeout_is_infra_fault(self):
        assert classify_exception(TimeoutError("connection timed out")) == "infra_fault"

    def test_external_api_429_is_upstream_fault(self):
        assert classify_exception(_FakeHttpError(429)) == "upstream_fault"

    def test_expired_ref_is_reference_fault(self):
        error = ReferenceExpiredError("ref expired", ref_kind="blackboard")
        assert classify_exception(error) == "reference_fault"


class TestClassifyExceptionGenericRules:
    def test_declared_fault_class_is_trusted_directly(self):
        assert classify_exception(_FakeTenantMismatchError()) == "policy_fault"

    def test_permission_error_is_policy_fault(self):
        assert classify_exception(PermissionError("denied")) == "policy_fault"

    def test_401_and_403_are_policy_fault(self):
        assert classify_exception(_FakeHttpError(401)) == "policy_fault"
        assert classify_exception(_FakeHttpError(403)) == "policy_fault"

    def test_5xx_is_upstream_fault(self):
        assert classify_exception(_FakeHttpError(500)) == "upstream_fault"
        assert classify_exception(_FakeHttpError(503)) == "upstream_fault"

    def test_status_code_on_nested_response_attribute(self):
        assert classify_exception(_FakeHttpErrorWithResponse(429)) == "upstream_fault"
        assert classify_exception(_FakeHttpErrorWithResponse(403)) == "policy_fault"

    def test_security_error_is_policy_fault(self):
        """SecurityError (token missing/invalid/tenant-access-denied) must
        never fall through to the agent_fault default — permission denials
        are never the agent's own logic failing."""
        from contextunity.core.exceptions import SecurityError

        assert classify_exception(SecurityError("Tenant access denied: _doc")) == "policy_fault"

    def test_connection_and_memory_errors_are_infra_fault(self):
        assert classify_exception(ConnectionError("db unreachable")) == "infra_fault"
        assert classify_exception(ConnectionRefusedError("refused")) == "infra_fault"
        assert classify_exception(MemoryError("oom")) == "infra_fault"
        assert classify_exception(OSError("disk full")) == "infra_fault"

    def test_value_and_type_errors_are_agent_fault(self):
        assert classify_exception(ValueError("bad input")) == "agent_fault"
        assert classify_exception(TypeError("wrong type")) == "agent_fault"

    def test_unknown_exception_defaults_to_agent_fault(self):
        class _SomeNewExceptionNobodyClassifiedYet(Exception):
            pass

        assert classify_exception(_SomeNewExceptionNobodyClassifiedYet("???")) == "agent_fault"

    def test_status_code_takes_priority_over_declared_fault_class_absence(self):
        # No .fault_class attribute at all — falls through to status-code duck typing.
        err = _FakeHttpError(429)
        assert not hasattr(err, "fault_class")
        assert classify_exception(err) == "upstream_fault"


class TestFaultEvent:
    def test_shape_matches_envelope(self):
        event = fault_event(
            ValueError("bad tool output"),
            event_type="brain.synapse.record.failed",
            error_code="synapse.validation_failed",
            tenant_id="acme_backend",
            graph_run_id="run-123",
            node_id="planner_1",
            provenance=["router.compiler", "brain.synapse"],
        )
        assert event["event_type"] == "brain.synapse.record.failed"
        assert event["fault_class"] == "agent_fault"
        assert event["tenant_id"] == "acme_backend"
        assert event["graph_run_id"] == "run-123"
        assert event["node_id"] == "planner_1"
        assert event["error_code"] == "synapse.validation_failed"
        assert event["retryable"] is False
        assert event["provenance"] == ["router.compiler", "brain.synapse"]
        assert "ts" in event and isinstance(event["ts"], str)

    def test_explicit_fault_class_overrides_classification(self):
        # Federated tool call: a bare ConnectionError would classify as
        # infra_fault by default, but a federated handler failure is an
        # upstream_fault regardless of the underlying exception type.
        event = fault_event(
            ConnectionError("federated handler unreachable"),
            event_type="router.federated.tool_failed",
            error_code="federated.unavailable",
            fault_class="upstream_fault",
            retryable=True,
        )
        assert event["fault_class"] == "upstream_fault"
        assert event["retryable"] is True

    def test_federated_llm_wrong_tool_choice_is_agent_fault_by_default(self):
        # Contrast with the case above: when the LLM supplies invalid
        # arguments to a federated tool (a data-level, not connection-level,
        # problem), the resulting validation error classifies as agent_fault
        # with no override needed — the classifier's default already gets
        # this half of the federated distinction right.
        with pytest.raises(ValidationError) as exc:
            _StrictModel(n="not-a-valid-tool-argument")
        event = fault_event(
            exc.value,
            event_type="router.federated.tool_failed",
            error_code="federated.invalid_arguments",
        )
        assert event["fault_class"] == "agent_fault"


class TestFaultEventDlq0Composition:
    """Proves fault_event() output composes with the existing DLQ-0 writer
    end-to-end — mirrors test_dlq.py's
    test_passbyref_error_is_replayable_end_to_end, but for a generic
    (non-PassByRef) fault, so the DLQ-0 fallback path used when DebugBus
    storage is unavailable is proven rather than assumed."""

    @pytest.mark.asyncio
    async def test_fault_event_is_replayable_via_local_file_dlq_writer(self, tmp_path):
        from contextunity.core.dlq import LocalFileDlqWriter

        writer = LocalFileDlqWriter(tmp_path / "dlq0.jsonl")
        event = fault_event(
            TimeoutError("db connection timed out"),
            event_type="brain.synapse.record.failed",
            error_code="infra.db_timeout",
            tenant_id="acme_backend",
            graph_run_id="run-123",
            retryable=True,
        )

        await writer.write(event)
        replayed = [e async for e in writer.replay()]

        assert len(replayed) == 1
        assert replayed[0]["event_type"] == "brain.synapse.record.failed"
        assert replayed[0]["fault_class"] == "infra_fault"
        assert replayed[0]["graph_run_id"] == "run-123"
        assert replayed[0]["retryable"] is True

    def test_defaults_are_none_or_empty_not_missing(self):
        event = fault_event(ValueError("x"), event_type="x.failed", error_code="x.error")
        assert event["tenant_id"] is None
        assert event["graph_run_id"] is None
        assert event["provenance"] == []
        assert event["service"] is None
        assert event["component"] is None
        assert event["phase"] is None
        assert event["metadata"] == {}

    def test_dlq0_blueprint_fields(self):
        event = fault_event(
            ValueError("x"),
            event_type="brain.synapse.record.failed",
            error_code="reference.hash_mismatch",
            service="ContextBrain",
            component="synapses",
            phase=2,
            metadata={"model_id": "gpt-x", "tool_binding": "platform:search"},
        )
        assert event["service"] == "ContextBrain"
        assert event["component"] == "synapses"
        assert event["phase"] == 2
        assert event["metadata"] == {"model_id": "gpt-x", "tool_binding": "platform:search"}
