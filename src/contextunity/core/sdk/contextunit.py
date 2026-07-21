"""ContextUnit - The universal data contract for ContextUnity protocol.

All gRPC communication uses ContextUnit as the envelope.
Domain-specific data is passed via the payload field.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Protocol, TypeAlias
from uuid import UUID, uuid4

from contextunity.core.types import ContextUnitPayload, is_object_mapping, is_object_sequence, is_object_set
from pydantic import BaseModel, Field

from .models import CotStep, SecurityScopes, UnitMetrics

if TYPE_CHECKING:
    from contextunity.core import contextunit_pb2 as _cu_pb2
    from google.protobuf.timestamp_pb2 import Timestamp

#: Protobuf ``Struct``-safe value tree (None/null, bool, int, float, str,
#: list, dict). ``Struct.update`` accepts these directly.
StructSafe: TypeAlias = "None | str | bool | int | float | list[StructSafe] | dict[str, StructSafe]"


class ContextUnitProtoModule(Protocol):
    """Structural contract for the generated ``contextunit_pb2`` module.

    Declaring the subset of the module the SDK uses lets ``to_protobuf``
    accept the module as a fully-typed value instead of an opaque
    ``ModuleType`` whose attributes resolve to ``Any``.
    """

    TEXT: _cu_pb2.Modality.ValueType
    AUDIO: _cu_pb2.Modality.ValueType
    SPATIAL: _cu_pb2.Modality.ValueType
    IMAGE: _cu_pb2.Modality.ValueType
    ContextUnit: type[_cu_pb2.ContextUnit]
    CotStep: type[_cu_pb2.CotStep]
    UnitMetrics: type[_cu_pb2.UnitMetrics]
    SecurityScopes: type[_cu_pb2.SecurityScopes]


class TimestampLike(Protocol):
    """Structural contract for protobuf Timestamp values."""

    def ToDatetime(self) -> datetime: ...

    def FromDatetime(self, dt: datetime) -> None: ...


class StructLike(Protocol):
    """Structural contract for protobuf Struct values."""

    def update(self, mapping: dict[str, StructSafe]) -> None: ...


_PROTO_TO_MODALITY: dict[int, str] = {
    0: "text",
    1: "audio",
    2: "spatial",
    3: "image",
}


def _sanitize_value(obj: object) -> StructSafe:
    """Recursively convert a payload value to a protobuf ``Struct``-safe type.

    Protobuf ``Struct.update`` only supports: None/null, bool, int, float,
    str, list, and dict. Anything else (UUID, datetime, bytes, set, Pydantic
    models, etc.) is converted to its string representation.

    None values are preserved as protobuf ``null`` values.
    """
    if obj is None:
        return None
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, (int, float)):
        return obj
    if isinstance(obj, str):
        return obj
    if is_object_mapping(obj):
        return {str(k): _sanitize_value(v) for k, v in obj.items()}
    if is_object_sequence(obj):
        return [_sanitize_value(v) for v in obj]
    if is_object_set(obj):
        return [_sanitize_value(v) for v in sorted(obj, key=str)]
    # Everything else (UUID, datetime, bytes, Pydantic, etc.) → str
    return str(obj)


def _sanitize_mapping(payload: ContextUnitPayload) -> dict[str, StructSafe]:
    """Sanitize an entire payload mapping into ``Struct``-safe entries."""
    return {key: _sanitize_value(value) for key, value in payload.items()}


def _modality_to_proto_value(modality: str, pb_module: ContextUnitProtoModule) -> _cu_pb2.Modality.ValueType:
    """Map wire-safe modality strings to the generated protobuf enum value."""
    key = (modality or "text").lower()
    if key == "audio":
        return pb_module.AUDIO
    if key == "spatial":
        return pb_module.SPATIAL
    if key == "image":
        return pb_module.IMAGE
    return pb_module.TEXT


def _modality_from_proto_value(value: int) -> str:
    """Convert protobuf enum value back to the SDK's lowercase modality string."""
    return _PROTO_TO_MODALITY.get(value, "text")


def _timestamp_from_protobuf(value: TimestampLike) -> datetime:
    """Convert protobuf Timestamp to an aware datetime when the field is set."""
    dt = value.ToDatetime()
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _timestamp_to_protobuf(dt: datetime) -> Timestamp:
    """Convert an aware datetime to protobuf Timestamp."""
    from google.protobuf.timestamp_pb2 import Timestamp

    created_at_pb = Timestamp()
    _fill_timestamp(created_at_pb, dt)
    return created_at_pb


def _fill_timestamp(value: TimestampLike, dt: datetime) -> None:
    value.FromDatetime(dt)


class ContextUnit(BaseModel):
    """Core data structure for ContextUnity protocol - universal data contract.

    All gRPC communication in ContextUnity uses ContextUnit.
    Domain-specific data is passed via the payload field.

    Example:
        unit = ContextUnit(
            payload={"tenant_id": "abc", "query_text": "climate solutions"},
        )
        async for response_pb in stub.SearchCells(unit.to_protobuf(contextunit_pb2)):
            result = ContextUnit.from_protobuf(response_pb)
    """

    unit_id: UUID = Field(default_factory=uuid4)
    trace_id: UUID = Field(default_factory=uuid4)
    parent_unit_id: UUID | None = None

    modality: str = "text"
    payload: ContextUnitPayload = Field(default_factory=dict)
    provenance: list[str] = Field(default_factory=list)

    chain_of_thought: list[CotStep] = Field(default_factory=list)

    metrics: UnitMetrics = Field(default_factory=UnitMetrics)
    security: SecurityScopes = Field(default_factory=SecurityScopes)

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_protobuf(self, pb_module: ContextUnitProtoModule) -> _cu_pb2.ContextUnit:
        """Convert the Pydantic ContextUnit model to its generated protobuf message counterpart.

        Args:
            pb_module: The generated protobuf module containing ContextUnit.

        Returns:
            The populated generated protobuf ContextUnit message.
        """
        from google.protobuf.struct_pb2 import Struct

        payload_struct = Struct()
        payload_struct.update(_sanitize_mapping(self.payload))

        created_at_pb = _timestamp_to_protobuf(self.created_at)

        # Convert chain_of_thought to protobuf CotStep messages
        cot_steps: list[_cu_pb2.CotStep] = []
        for step in self.chain_of_thought:
            step_timestamp = _timestamp_to_protobuf(step.timestamp)
            cot_pb = pb_module.CotStep(
                agent=step.agent,
                action=step.action,
                status=step.status,
                timestamp=step_timestamp,
            )
            cot_steps.append(cot_pb)

        # Convert metrics to protobuf — always create (Pydantic provides defaults)
        metrics_pb = pb_module.UnitMetrics(
            latency_ms=self.metrics.latency_ms if self.metrics else 0,
            cost_usd=self.metrics.cost_usd if self.metrics else 0.0,
            tokens_used=self.metrics.tokens_used if self.metrics else 0,
            cost_limit_usd=self.metrics.cost_limit_usd if self.metrics else 0.0,
        )

        # Convert security scopes to protobuf — always create
        security_pb = pb_module.SecurityScopes(
            read=list(self.security.read) if self.security else [],
            write=list(self.security.write) if self.security else [],
        )

        unit_pb = pb_module.ContextUnit(
            unit_id=str(self.unit_id),
            trace_id=str(self.trace_id),
            parent_unit_id=str(self.parent_unit_id) if self.parent_unit_id else "",
            modality=_modality_to_proto_value(self.modality, pb_module),
            payload=payload_struct,
            provenance=list(self.provenance),
            chain_of_thought=cot_steps,
            metrics=metrics_pb,
            security=security_pb,
            created_at=created_at_pb,
        )
        return unit_pb

    @classmethod
    def from_protobuf(cls, unit_pb: _cu_pb2.ContextUnit) -> ContextUnit:
        """Convert a generated protobuf ContextUnit message back to a Pydantic ContextUnit model.

        Args:
            unit_pb: The generated protobuf ContextUnit message to deserialize from.

        Returns:
            ContextUnit: The instantiated Pydantic ContextUnit model.
        """
        # Convert chain_of_thought from protobuf
        cot_steps: list[CotStep] = [
            CotStep(
                agent=step_pb.agent,
                action=step_pb.action,
                status=step_pb.status,
                timestamp=_timestamp_from_protobuf(step_pb.timestamp),
            )
            for step_pb in unit_pb.chain_of_thought
        ]

        # Convert metrics from protobuf
        metrics: UnitMetrics | None = None
        if unit_pb.HasField("metrics"):
            metrics = UnitMetrics(
                latency_ms=unit_pb.metrics.latency_ms,
                cost_usd=unit_pb.metrics.cost_usd,
                tokens_used=unit_pb.metrics.tokens_used,
                cost_limit_usd=unit_pb.metrics.cost_limit_usd,
            )

        # Convert security scopes from protobuf
        security: SecurityScopes | None = None
        if unit_pb.HasField("security"):
            security = SecurityScopes(
                read=list(unit_pb.security.read),
                write=list(unit_pb.security.write),
            )

        from contextunity.core.sdk.payload import wire_payload_from_proto_unit

        payload = wire_payload_from_proto_unit(unit_pb)

        created_at = (
            _timestamp_from_protobuf(unit_pb.created_at)
            if unit_pb.HasField("created_at")
            else datetime.now(timezone.utc)
        )

        unit = cls(
            unit_id=UUID(unit_pb.unit_id) if unit_pb.unit_id else uuid4(),
            trace_id=UUID(unit_pb.trace_id) if unit_pb.trace_id else uuid4(),
            parent_unit_id=UUID(unit_pb.parent_unit_id) if unit_pb.parent_unit_id else None,
            modality=_modality_from_proto_value(unit_pb.modality),
            payload=payload,
            provenance=list(unit_pb.provenance),
            chain_of_thought=cot_steps,
            created_at=created_at,
        )
        if metrics is not None:
            unit.metrics = metrics
        if security is not None:
            unit.security = security
        return unit

    @classmethod
    def from_protobuf_bytes(cls, data: bytes, pb_module: ContextUnitProtoModule) -> ContextUnit:
        """Deserialize raw protobuf bytes directly to a Pydantic ContextUnit model.

        This is the conformant way to deserialize bytes without creating
        a bare pb2 constructor in production code.

        Args:
            data: The serialized protobuf bytes.
            pb_module: The generated protobuf module containing ContextUnit.

        Returns:
            ContextUnit: The deserialized Pydantic ContextUnit model.
        """
        pb = pb_module.ContextUnit()
        _ = pb.ParseFromString(data)
        return cls.from_protobuf(pb)


__all__ = ["ContextUnit"]
