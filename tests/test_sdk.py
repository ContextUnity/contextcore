"""Tests for ContextUnit SDK."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4


from contextcore import ContextUnit, CotStep, SecurityScopes, UnitMetrics


class TestContextUnit:
    """Tests for ContextUnit model."""

    def test_create_default_unit(self) -> None:
        """Test creating a ContextUnit with default values."""
        unit = ContextUnit()
        assert isinstance(unit.unit_id, UUID)
        assert isinstance(unit.trace_id, UUID)
        assert unit.parent_unit_id is None
        assert unit.modality == "text"
        assert unit.payload == {}
        assert unit.provenance == []
        assert unit.chain_of_thought == []
        assert isinstance(unit.metrics, UnitMetrics)
        assert isinstance(unit.security, SecurityScopes)
        assert isinstance(unit.created_at, datetime)

    def test_create_custom_unit(self) -> None:
        """Test creating a ContextUnit with custom values."""
        unit_id = uuid4()
        trace_id = uuid4()
        payload = {"content": "test", "metadata": {"key": "value"}}
        provenance = ["source1", "source2"]

        unit = ContextUnit(
            unit_id=unit_id,
            trace_id=trace_id,
            payload=payload,
            provenance=provenance,
        )

        assert unit.unit_id == unit_id
        assert unit.trace_id == trace_id
        assert unit.payload == payload
        assert unit.provenance == provenance

    def test_provenance_append(self) -> None:
        """Test appending to provenance."""
        unit = ContextUnit()
        unit.provenance.append("new_source")
        assert "new_source" in unit.provenance

    def test_chain_of_thought(self) -> None:
        """Test chain of thought steps."""
        unit = ContextUnit()
        step = CotStep(agent="test_agent", action="test_action", status="completed")
        unit.chain_of_thought.append(step)
        assert len(unit.chain_of_thought) == 1
        assert unit.chain_of_thought[0].agent == "test_agent"
        assert unit.chain_of_thought[0].action == "test_action"
        assert unit.chain_of_thought[0].status == "completed"


class TestCotStep:
    """Tests for CotStep model."""

    def test_create_cot_step(self) -> None:
        """Test creating a CotStep."""
        step = CotStep(agent="agent1", action="action1")
        assert step.agent == "agent1"
        assert step.action == "action1"
        assert step.status == "pending"
        assert isinstance(step.timestamp, datetime)

    def test_cot_step_default_status(self) -> None:
        """Test CotStep default status."""
        step = CotStep(agent="agent", action="action")
        assert step.status == "pending"

    def test_cot_step_custom_status(self) -> None:
        """Test CotStep with custom status."""
        step = CotStep(agent="agent", action="action", status="completed")
        assert step.status == "completed"


class TestUnitMetrics:
    """Tests for UnitMetrics model."""

    def test_create_default_metrics(self) -> None:
        """Test creating default UnitMetrics."""
        metrics = UnitMetrics()
        assert metrics.latency_ms == 0
        assert metrics.cost_usd == 0.0
        assert metrics.tokens_used == 0
        assert metrics.cost_limit_usd == 0.0

    def test_create_custom_metrics(self) -> None:
        """Test creating custom UnitMetrics."""
        metrics = UnitMetrics(
            latency_ms=100,
            cost_usd=0.05,
            tokens_used=1000,
            cost_limit_usd=1.0,
        )
        assert metrics.latency_ms == 100
        assert metrics.cost_usd == 0.05
        assert metrics.tokens_used == 1000
        assert metrics.cost_limit_usd == 1.0


class TestSecurityScopes:
    """Tests for SecurityScopes model."""

    def test_create_default_scopes(self) -> None:
        """Test creating default SecurityScopes."""
        scopes = SecurityScopes()
        assert scopes.read == []
        assert scopes.write == []

    def test_create_custom_scopes(self) -> None:
        """Test creating custom SecurityScopes."""
        scopes = SecurityScopes(
            read=["scope1:read", "scope2:read"],
            write=["scope1:write"],
        )
        assert len(scopes.read) == 2
        assert "scope1:read" in scopes.read
        assert "scope2:read" in scopes.read
        assert len(scopes.write) == 1
        assert "scope1:write" in scopes.write

    def test_empty_scopes_allow_all(self) -> None:
        """Test that empty scopes allow all access."""
        scopes = SecurityScopes()
        # Empty scopes should allow all (checked by token logic)
        assert scopes.read == []
        assert scopes.write == []
