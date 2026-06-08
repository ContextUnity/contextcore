"""Tests for ContextUnit SDK core models.

Verifies ContextUnit, CotStep, UnitMetrics, and SecurityScopes
construction and domain behavior.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import pytest
from contextunity.core import ContextUnit, CotStep, SecurityScopes, UnitMetrics


class TestContextUnit:
    """Tests for ContextUnit model."""

    def test_create_default_unit(self) -> None:
        """Default ContextUnit has correct types and empty collections."""
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
        """Custom values are preserved."""
        unit_id = uuid4()
        trace_id = uuid4()
        payload = {"content": "test", "metadata": {"key": "value"}}
        unit = ContextUnit(
            unit_id=unit_id,
            trace_id=trace_id,
            payload=payload,
            provenance=["sdk:test"],
        )

        assert unit.unit_id == unit_id
        assert unit.trace_id == trace_id
        assert unit.payload == payload
        assert unit.provenance == ["sdk:test"]

    def test_chain_of_thought_append(self) -> None:
        """CotStep can be appended and retrieved."""
        unit = ContextUnit()
        step = CotStep(agent="test_agent", action="test_action", status="completed")
        unit.chain_of_thought.append(step)
        assert len(unit.chain_of_thought) == 1
        assert unit.chain_of_thought[0].agent == "test_agent"
        assert unit.chain_of_thought[0].action == "test_action"
        assert unit.chain_of_thought[0].status == "completed"


@pytest.mark.parametrize(
    ("status_kwarg", "expected"),
    [
        ({}, "pending"),
        ({"status": "completed"}, "completed"),
    ],
    ids=["default-pending", "custom-completed"],
)
def test_cot_step_status(status_kwarg, expected) -> None:
    """CotStep defaults to 'pending', accepts custom status."""
    step = CotStep(agent="agent", action="action", **status_kwarg)
    assert step.status == expected
    assert isinstance(step.timestamp, datetime)


class TestUnitMetrics:
    """Tests for UnitMetrics model."""

    def test_create_custom_metrics(self) -> None:
        """Custom metrics are preserved."""
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


def test_security_scopes_custom() -> None:
    """SecurityScopes preserves read/write lists."""
    scopes = SecurityScopes(
        read=["scope1:read", "scope2:read"],
        write=["scope1:write"],
    )
    assert scopes.read == ["scope1:read", "scope2:read"]
    assert scopes.write == ["scope1:write"]


pytestmark = pytest.mark.unit
