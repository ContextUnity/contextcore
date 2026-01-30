"""ContextUnit - The universal data contract for ContextUnity protocol.

All gRPC communication uses ContextUnit as the envelope.
Domain-specific data is passed via the payload field.
"""

from __future__ import annotations

# IMPORTANT: Import google well-known types FIRST, before any other imports
# that might trigger loading of our pb2 files through circular imports.
try:
    from google.protobuf import struct_pb2 as _struct_pb2  # noqa: F401
    from google.protobuf import timestamp_pb2 as _timestamp_pb2  # noqa: F401
except ImportError:
    pass  # protobuf not installed, gRPC features won't work

from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from .models import CotStep, SecurityScopes, UnitMetrics


class ContextUnit(BaseModel):
    """Core data structure for ContextUnity protocol - universal data contract.

    All gRPC communication in ContextUnity uses ContextUnit.
    Domain-specific data is passed via the payload field.

    Example:
        unit = ContextUnit(
            payload={"tenant_id": "abc", "query_text": "climate solutions"},
            provenance=["router:rag_agent"],
        )
        response_pb = await stub.Search(unit.to_protobuf(context_unit_pb2))
        result = ContextUnit.from_protobuf(response_pb)
    """

    unit_id: UUID = Field(default_factory=uuid4)
    trace_id: UUID = Field(default_factory=uuid4)
    parent_unit_id: UUID | None = None

    modality: str = "text"
    payload: dict[str, Any] = Field(default_factory=dict)

    provenance: list[str] = Field(default_factory=list)
    chain_of_thought: list[CotStep] = Field(default_factory=list)

    metrics: UnitMetrics = Field(default_factory=UnitMetrics)
    security: SecurityScopes = Field(default_factory=SecurityScopes)

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_protobuf(self, pb_module):
        """Converts Pydantic model to Protobuf message."""
        from google.protobuf.struct_pb2 import Struct
        from google.protobuf.timestamp_pb2 import Timestamp

        payload_struct = Struct()
        payload_struct.update(self.payload)

        created_at_pb = Timestamp()
        created_at_pb.FromDatetime(self.created_at)

        # Convert chain_of_thought to protobuf CotStep messages
        cot_steps = []
        for step in self.chain_of_thought:
            step_timestamp = Timestamp()
            step_timestamp.FromDatetime(step.timestamp)
            cot_pb = pb_module.CotStep(
                agent=step.agent,
                action=step.action,
                status=step.status,
                timestamp=step_timestamp,
            )
            cot_steps.append(cot_pb)

        # Convert metrics to protobuf
        metrics_pb = None
        if self.metrics:
            metrics_pb = pb_module.UnitMetrics(
                latency_ms=self.metrics.latency_ms,
                cost_usd=self.metrics.cost_usd,
                tokens_used=self.metrics.tokens_used,
                cost_limit_usd=self.metrics.cost_limit_usd,
            )

        # Convert security scopes to protobuf
        security_pb = None
        if self.security:
            security_pb = pb_module.SecurityScopes(
                read=list(self.security.read),
                write=list(self.security.write),
            )

        unit_pb = pb_module.ContextUnit(
            unit_id=str(self.unit_id),
            trace_id=str(self.trace_id),
            parent_unit_id=str(self.parent_unit_id) if self.parent_unit_id else "",
            modality=0,  # Need mapping for enum
            payload=payload_struct,
            provenance=self.provenance,
            chain_of_thought=cot_steps,
            metrics=metrics_pb,
            security=security_pb,
            created_at=created_at_pb,
        )
        return unit_pb

    @classmethod
    def from_protobuf(cls, unit_pb) -> "ContextUnit":
        """Converts Protobuf message to Pydantic model."""
        # Convert chain_of_thought from protobuf
        cot_steps = []
        for step_pb in unit_pb.chain_of_thought:
            cot_steps.append(
                CotStep(
                    agent=step_pb.agent,
                    action=step_pb.action,
                    status=step_pb.status,
                    timestamp=step_pb.timestamp.ToDatetime(),
                )
            )

        # Convert metrics from protobuf
        metrics = None
        if unit_pb.metrics:
            metrics = UnitMetrics(
                latency_ms=unit_pb.metrics.latency_ms,
                cost_usd=unit_pb.metrics.cost_usd,
                tokens_used=unit_pb.metrics.tokens_used,
                cost_limit_usd=unit_pb.metrics.cost_limit_usd,
            )

        # Convert security scopes from protobuf
        security = None
        if unit_pb.security:
            security = SecurityScopes(
                read=list(unit_pb.security.read),
                write=list(unit_pb.security.write),
            )

        return cls(
            unit_id=UUID(unit_pb.unit_id) if unit_pb.unit_id else uuid4(),
            trace_id=UUID(unit_pb.trace_id) if unit_pb.trace_id else uuid4(),
            parent_unit_id=UUID(unit_pb.parent_unit_id)
            if unit_pb.parent_unit_id
            else None,
            payload=dict(unit_pb.payload),
            provenance=list(unit_pb.provenance),
            chain_of_thought=cot_steps,
            metrics=metrics,
            security=security,
            created_at=unit_pb.created_at.ToDatetime()
            if unit_pb.created_at.seconds
            else datetime.now(timezone.utc),
        )


__all__ = ["ContextUnit"]
