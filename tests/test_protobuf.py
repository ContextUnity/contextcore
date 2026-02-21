"""Tests for ContextUnit protobuf conversion.

These tests verify the ContextUnit ↔ protobuf round-trip contract.
All proto stubs live at `contextcore.*_pb2` (e.g. contextcore.context_unit_pb2).
"""

from __future__ import annotations

from uuid import uuid4

from contextcore import ContextUnit, CotStep, SecurityScopes, UnitMetrics, context_unit_pb2
from google.protobuf.struct_pb2 import Struct


class TestProtobufConversion:
    """Tests for ContextUnit protobuf serialization/deserialization."""

    def test_to_protobuf_basic(self) -> None:
        """Test basic ContextUnit to protobuf conversion."""
        uid = uuid4()
        tid = uuid4()
        unit = ContextUnit(
            unit_id=uid,
            trace_id=tid,
            payload={"test": "data"},
        )

        unit_pb = unit.to_protobuf(context_unit_pb2)
        assert unit_pb is not None
        assert unit_pb.unit_id == str(uid)
        assert unit_pb.trace_id == str(tid)

    def test_from_protobuf_basic(self) -> None:
        """Test basic protobuf to ContextUnit conversion."""
        uid = str(uuid4())
        tid = str(uuid4())

        unit_pb = context_unit_pb2.ContextUnit(
            unit_id=uid,
            trace_id=tid,
            modality=0,  # TEXT
            payload=Struct(),
        )
        unit_pb.payload.update({"test": "data"})

        unit = ContextUnit.from_protobuf(unit_pb)
        assert unit is not None
        assert str(unit.unit_id) == uid
        assert str(unit.trace_id) == tid
        assert unit.payload.get("test") == "data"

    def test_to_protobuf_with_provenance(self) -> None:
        """Test ContextUnit with provenance to protobuf."""
        unit = ContextUnit(provenance=["source1", "source2", "source3"])

        unit_pb = unit.to_protobuf(context_unit_pb2)
        assert len(unit_pb.provenance) == 3
        assert "source1" in unit_pb.provenance
        assert "source2" in unit_pb.provenance
        assert "source3" in unit_pb.provenance

    def test_to_protobuf_with_chain_of_thought(self) -> None:
        """Test ContextUnit with chain of thought to protobuf."""
        unit = ContextUnit()
        unit.chain_of_thought.append(CotStep(agent="test_agent", action="test_action", status="completed"))

        unit_pb = unit.to_protobuf(context_unit_pb2)
        assert len(unit_pb.chain_of_thought) == 1
        assert unit_pb.chain_of_thought[0].agent == "test_agent"
        assert unit_pb.chain_of_thought[0].action == "test_action"
        assert unit_pb.chain_of_thought[0].status == "completed"

    def test_to_protobuf_with_security_scopes(self) -> None:
        """Test ContextUnit with security scopes to protobuf."""
        unit = ContextUnit(
            security=SecurityScopes(
                read=["read:data", "read:config"],
                write=["write:data"],
            )
        )

        unit_pb = unit.to_protobuf(context_unit_pb2)
        assert unit_pb.security is not None
        assert len(unit_pb.security.read) == 2
        assert "read:data" in unit_pb.security.read
        assert "read:config" in unit_pb.security.read
        assert len(unit_pb.security.write) == 1
        assert "write:data" in unit_pb.security.write

    def test_to_protobuf_with_metrics(self) -> None:
        """Test ContextUnit with metrics to protobuf."""
        unit = ContextUnit(
            metrics=UnitMetrics(
                latency_ms=100,
                cost_usd=0.05,
                tokens_used=1000,
            )
        )

        unit_pb = unit.to_protobuf(context_unit_pb2)
        assert unit_pb.metrics is not None
        assert unit_pb.metrics.latency_ms == 100
        assert unit_pb.metrics.cost_usd == 0.05
        assert unit_pb.metrics.tokens_used == 1000

    def test_round_trip_conversion(self) -> None:
        """Test round-trip: ContextUnit → protobuf → ContextUnit."""
        original = ContextUnit(
            unit_id=uuid4(),
            trace_id=uuid4(),
            payload={"test": "data", "number": 42},
            provenance=["source1", "source2"],
            modality="text",
        )
        original.chain_of_thought.append(CotStep(agent="agent1", action="action1", status="completed"))

        # ContextUnit → protobuf
        unit_pb = original.to_protobuf(context_unit_pb2)

        # protobuf → ContextUnit
        restored = ContextUnit.from_protobuf(unit_pb)

        assert restored.unit_id == original.unit_id
        assert restored.trace_id == original.trace_id
        assert restored.modality == original.modality
        assert restored.payload.get("test") == "data"
        assert len(restored.provenance) == 2
        assert len(restored.chain_of_thought) == 1
        assert restored.chain_of_thought[0].agent == "agent1"

    def test_to_protobuf_empty_payload(self) -> None:
        """Test ContextUnit with empty payload to protobuf."""
        unit = ContextUnit(payload={})

        unit_pb = unit.to_protobuf(context_unit_pb2)
        assert unit_pb.payload is not None

    def test_to_protobuf_nested_payload(self) -> None:
        """Test ContextUnit with nested payload to protobuf."""
        unit = ContextUnit(
            payload={
                "nested": {"key": "value", "number": 123},
                "list": [1, 2, 3],
            }
        )

        unit_pb = unit.to_protobuf(context_unit_pb2)
        assert unit_pb.payload is not None
        # Verify nested structure survives serialization
        payload_dict = dict(unit_pb.payload)
        assert "nested" in payload_dict

    def test_to_protobuf_payload_with_none_values(self) -> None:
        """Test that None values in payload don't cause SerializeToString errors.

        Regression test: protobuf Struct cannot handle None values natively
        in all Python protobuf implementations—_sanitize_for_protobuf must
        convert them to empty strings.
        """
        unit = ContextUnit(
            payload={
                "tenant_id": "default",
                "user_id": None,
                "agent_id": None,
                "nested": {"key": None, "list_with_none": [1, None, "text"]},
                "metadata": {
                    "deep": {"value": None},
                },
            }
        )
        # This must not raise TypeError
        unit_pb = unit.to_protobuf(context_unit_pb2)
        assert unit_pb is not None
        # Verify round-trip
        restored = ContextUnit.from_protobuf(unit_pb)
        assert restored.payload["tenant_id"] == "default"
        # None values become empty strings
        assert restored.payload["user_id"] == ""
        assert restored.payload["agent_id"] == ""

    def test_to_protobuf_payload_with_non_primitive_types(self) -> None:
        """Test that UUID, datetime, bytes, set are converted to strings.

        These types are not natively supported by protobuf Struct.
        """
        from datetime import datetime, timezone

        unit = ContextUnit(
            payload={
                "uuid_field": uuid4(),
                "datetime_field": datetime.now(timezone.utc),
                "bytes_field": b"binary data",
                "set_field": {"a", "b", "c"},
            }
        )
        # Must not raise
        unit_pb = unit.to_protobuf(context_unit_pb2)
        assert unit_pb is not None

        restored = ContextUnit.from_protobuf(unit_pb)
        # UUID/datetime/bytes should be string representations
        assert isinstance(restored.payload["uuid_field"], str)
        assert isinstance(restored.payload["datetime_field"], str)
        assert isinstance(restored.payload["bytes_field"], str)
        # set → list of strings
        assert isinstance(restored.payload["set_field"], list)
        assert len(restored.payload["set_field"]) == 3

    def test_to_protobuf_trace_like_payload(self) -> None:
        """Test with a payload that mimics a real trace log structure.

        This is the structure built by reflect_dispatcher.
        """
        unit = ContextUnit(
            payload={
                "tenant_id": "myproject",
                "agent_id": "router:dispatcher",
                "session_id": "sess-123",
                "tool_calls": [
                    {"tool": "search", "args": {"query": "test"}, "status": "ok"},
                    {"tool": "execute_sql", "args": {"sql": "SELECT 1"}, "status": "ok"},
                ],
                "token_usage": {"input_tokens": 0, "output_tokens": 0},
                "timing_ms": 1234,
                "security_flags": {
                    "events": [],
                    "token_id": "tok-123",
                    "user_id": "",
                    "permissions": ["*"],
                },
                "metadata": {
                    "steps": [
                        {
                            "step": 0,
                            "type": "user",
                            "content": "Hello",
                            "tokens": {"input": 10, "output": 0},
                        },
                        {
                            "step": 1,
                            "type": "tool_call",
                            "tool": "search",
                            "tool_call_id": "call_123",
                            "args": {"query": "test"},
                            "tokens": {},
                        },
                    ],
                },
                "provenance": ["agent:dispatcher", "tool:search"],
            }
        )
        # Must serialize without errors
        unit_pb = unit.to_protobuf(context_unit_pb2)
        assert unit_pb is not None
        # Must also fully serialize to wire bytes
        wire = unit_pb.SerializeToString()
        assert len(wire) > 0
