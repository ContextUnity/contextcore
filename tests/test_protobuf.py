"""Tests for ContextUnit protobuf conversion."""

from __future__ import annotations

from uuid import uuid4

import pytest

from contextcore import ContextUnit, CotStep, SecurityScopes, UnitMetrics


class TestProtobufConversion:
    """Tests for ContextUnit protobuf serialization/deserialization."""

    def test_to_protobuf_basic(self) -> None:
        """Test basic ContextUnit to protobuf conversion."""
        unit = ContextUnit(
            unit_id=uuid4(),
            trace_id=uuid4(),
            payload={"test": "data"},
        )

        # Try to convert to protobuf (may fail if protos not generated)
        try:
            from contextcore.generated import context_unit_pb2

            unit_pb = unit.to_protobuf(context_unit_pb2)
            assert unit_pb is not None
            assert unit_pb.unit_id == str(unit.unit_id)
            assert unit_pb.trace_id == str(unit.trace_id)
        except ImportError:
            pytest.skip("Protobuf files not generated")

    def test_from_protobuf_basic(self) -> None:
        """Test basic protobuf to ContextUnit conversion."""
        try:
            from contextcore.generated import context_unit_pb2
            from google.protobuf.struct_pb2 import Struct
            from google.protobuf.timestamp_pb2 import Timestamp

            # Create a protobuf message
            unit_pb = context_unit_pb2.ContextUnit(
                unit_id=str(uuid4()),
                trace_id=str(uuid4()),
                modality=0,  # TEXT
                payload=Struct(),
            )
            unit_pb.payload.update({"test": "data"})

            # Convert from protobuf
            unit = ContextUnit.from_protobuf(unit_pb)
            assert unit is not None
            assert unit.payload.get("test") == "data"
        except ImportError:
            pytest.skip("Protobuf files not generated")

    def test_to_protobuf_with_provenance(self) -> None:
        """Test ContextUnit with provenance to protobuf."""
        unit = ContextUnit(
            provenance=["source1", "source2", "source3"],
        )

        try:
            from contextcore.generated import context_unit_pb2

            unit_pb = unit.to_protobuf(context_unit_pb2)
            assert len(unit_pb.provenance) == 3
            assert "source1" in unit_pb.provenance
        except ImportError:
            pytest.skip("Protobuf files not generated")

    def test_to_protobuf_with_chain_of_thought(self) -> None:
        """Test ContextUnit with chain of thought to protobuf."""
        unit = ContextUnit()
        unit.chain_of_thought.append(
            CotStep(agent="test_agent", action="test_action", status="completed")
        )

        try:
            from contextcore.generated import context_unit_pb2

            unit_pb = unit.to_protobuf(context_unit_pb2)
            # Chain of thought should be preserved
            assert len(unit_pb.chain_of_thought) == 1
        except ImportError:
            pytest.skip("Protobuf files not generated")

    def test_to_protobuf_with_security_scopes(self) -> None:
        """Test ContextUnit with security scopes to protobuf."""
        unit = ContextUnit(
            security=SecurityScopes(
                read=["read:data", "read:config"],
                write=["write:data"],
            )
        )

        try:
            from contextcore.generated import context_unit_pb2

            unit_pb = unit.to_protobuf(context_unit_pb2)
            # Security scopes should be preserved
            assert unit_pb.security is not None
            assert len(unit_pb.security.read) == 2
            assert "read:data" in unit_pb.security.read
        except ImportError:
            pytest.skip("Protobuf files not generated")

    def test_to_protobuf_with_metrics(self) -> None:
        """Test ContextUnit with metrics to protobuf."""
        unit = ContextUnit(
            metrics=UnitMetrics(
                latency_ms=100,
                cost_usd=0.05,
                tokens_used=1000,
            )
        )

        try:
            from contextcore.generated import context_unit_pb2

            unit_pb = unit.to_protobuf(context_unit_pb2)
            # Metrics should be preserved
            assert unit_pb.metrics is not None
            assert unit_pb.metrics.latency_ms == 100
            assert unit_pb.metrics.cost_usd == 0.05
        except ImportError:
            pytest.skip("Protobuf files not generated")

    def test_round_trip_conversion(self) -> None:
        """Test round-trip conversion: ContextUnit -> protobuf -> ContextUnit."""
        original = ContextUnit(
            unit_id=uuid4(),
            trace_id=uuid4(),
            payload={"test": "data", "number": 42},
            provenance=["source1", "source2"],
            modality="text",
        )
        original.chain_of_thought.append(
            CotStep(agent="agent1", action="action1", status="completed")
        )

        try:
            from contextcore.generated import context_unit_pb2

            # Convert to protobuf
            unit_pb = original.to_protobuf(context_unit_pb2)

            # Convert back
            restored = ContextUnit.from_protobuf(unit_pb)

            # Verify key fields
            assert restored.unit_id == original.unit_id
            assert restored.trace_id == original.trace_id
            assert restored.modality == original.modality
            assert restored.payload.get("test") == "data"
            assert len(restored.provenance) == 2
            assert len(restored.chain_of_thought) == 1
            assert restored.chain_of_thought[0].agent == "agent1"
        except ImportError:
            pytest.skip("Protobuf files not generated")

    def test_to_protobuf_empty_payload(self) -> None:
        """Test ContextUnit with empty payload to protobuf."""
        unit = ContextUnit(payload={})

        try:
            from contextcore.generated import context_unit_pb2

            unit_pb = unit.to_protobuf(context_unit_pb2)
            assert unit_pb.payload is not None
        except ImportError:
            pytest.skip("Protobuf files not generated")

    def test_to_protobuf_nested_payload(self) -> None:
        """Test ContextUnit with nested payload to protobuf."""
        unit = ContextUnit(
            payload={
                "nested": {
                    "key": "value",
                    "number": 123,
                },
                "list": [1, 2, 3],
            }
        )

        try:
            from contextcore.generated import context_unit_pb2

            unit_pb = unit.to_protobuf(context_unit_pb2)
            # Nested structures should be preserved in protobuf Struct
            assert unit_pb.payload is not None
        except ImportError:
            pytest.skip("Protobuf files not generated")
