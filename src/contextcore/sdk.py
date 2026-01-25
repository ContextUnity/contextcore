"""ContextUnit SDK - Core data structures for ContextUnity protocol."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

class CotStep(BaseModel):
    agent: str
    action: str
    status: str = "pending"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UnitMetrics(BaseModel):
    """Metrics for tracking unit processing costs and performance."""

    latency_ms: int = 0
    cost_usd: float = 0.0
    tokens_used: int = 0
    cost_limit_usd: float = 0.0

class SecurityScopes(BaseModel):
    read: list[str] = Field(default_factory=list)
    write: list[str] = Field(default_factory=list)

class ContextUnit(BaseModel):
    """Core data structure for ContextUnity protocol - atomic unit of data exchange."""

    unit_id: UUID = Field(default_factory=uuid4)
    trace_id: UUID = Field(default_factory=uuid4)
    parent_unit_id: UUID | None = None
    
    modality: str = "text"
    payload: dict[str, Any] = Field(default_factory=dict)
    
    provenance: list[str] = Field(default_factory=list)
    chain_of_thought: list["CotStep"] = Field(default_factory=list)
    
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
            modality=0, # Need mapping for enum
            payload=payload_struct,
            provenance=self.provenance,
            chain_of_thought=cot_steps,
            metrics=metrics_pb,
            security=security_pb,
            created_at=created_at_pb
        )
        return unit_pb

    @classmethod
    def from_protobuf(cls, unit_pb):
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
            unit_id=UUID(unit_pb.unit_id),
            trace_id=UUID(unit_pb.trace_id),
            parent_unit_id=UUID(unit_pb.parent_unit_id) if unit_pb.parent_unit_id else None,
            payload=dict(unit_pb.payload),
            provenance=list(unit_pb.provenance),
            chain_of_thought=cot_steps,
            metrics=metrics,
            security=security,
            created_at=unit_pb.created_at.ToDatetime()
        )

import grpc
try:
    from contextcore import brain_pb2, brain_pb2_grpc
except ImportError:
    # Handle cases where protos aren't generated yet
    brain_pb2, brain_pb2_grpc = None, None

class BrainClient:
    """
    Client for interacting with ContextBrain gRPC service.
    """
    def __init__(self, host: str = "localhost:50051"):
        self.channel = grpc.insecure_channel(host)
        if brain_pb2_grpc:
            self.stub = brain_pb2_grpc.BrainServiceStub(self.channel)
        else:
            self.stub = None

    async def query_memory(self, unit: ContextUnit) -> List[ContextUnit]:
        """Query semantic memory."""
        if not self.stub:
            raise ImportError("Protos not generated")
        unit_pb = unit.to_protobuf(brain_pb2)
        response_stream = self.stub.QueryMemory(unit_pb)
        
        results = []
        async for res_pb in response_stream:
            results.append(ContextUnit.from_protobuf(res_pb))
        return results

    async def memorize(self, unit: ContextUnit) -> ContextUnit:
        """Store unit in memory."""
        if not self.stub:
            raise ImportError("Protos not generated")
        unit_pb = unit.to_protobuf(brain_pb2)
        res_pb = await self.stub.Memorize(unit_pb)
        return ContextUnit.from_protobuf(res_pb)

    async def add_episode(self, unit: ContextUnit) -> ContextUnit:
        """Record conversation event."""
        if not self.stub: raise ImportError("Protos not generated")
        unit_pb = unit.to_protobuf(brain_pb2)
        res_pb = await self.stub.AddEpisode(unit_pb)
        return ContextUnit.from_protobuf(res_pb)

    async def upsert_fact(self, unit: ContextUnit) -> ContextUnit:
        """Record user fact."""
        if not self.stub: raise ImportError("Protos not generated")
        unit_pb = unit.to_protobuf(brain_pb2)
        res_pb = await self.stub.UpsertFact(unit_pb)
        return ContextUnit.from_protobuf(res_pb)

    async def upsert_taxonomy(self, unit: ContextUnit) -> ContextUnit:
        """Sync taxonomy entry to DB."""
        if not self.stub: raise ImportError("Protos not generated")
        unit_pb = unit.to_protobuf(brain_pb2)
        res_pb = await self.stub.UpsertTaxonomy(unit_pb)
        return ContextUnit.from_protobuf(res_pb)

    async def get_taxonomy(self, unit: ContextUnit) -> List[ContextUnit]:
        """Fetch taxonomy entries for a domain."""
        if not self.stub: raise ImportError("Protos not generated")
        unit_pb = unit.to_protobuf(brain_pb2)
        stream = self.stub.GetTaxonomy(unit_pb)
        results = []
        async for res_pb in stream:
            results.append(ContextUnit.from_protobuf(res_pb))
        return results
