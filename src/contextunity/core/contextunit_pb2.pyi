import datetime
from collections.abc import Iterable as _Iterable
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar
from typing import Optional as _Optional
from typing import Union as _Union

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import struct_pb2 as _struct_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper

DESCRIPTOR: _descriptor.FileDescriptor

class Modality(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TEXT: _ClassVar[Modality]
    AUDIO: _ClassVar[Modality]
    SPATIAL: _ClassVar[Modality]
    IMAGE: _ClassVar[Modality]

TEXT: Modality
AUDIO: Modality
SPATIAL: Modality
IMAGE: Modality

class UnitMetrics(_message.Message):
    __slots__ = ("latency_ms", "cost_usd", "tokens_used", "cost_limit_usd")
    LATENCY_MS_FIELD_NUMBER: _ClassVar[int]
    COST_USD_FIELD_NUMBER: _ClassVar[int]
    TOKENS_USED_FIELD_NUMBER: _ClassVar[int]
    COST_LIMIT_USD_FIELD_NUMBER: _ClassVar[int]
    latency_ms: int
    cost_usd: float
    tokens_used: int
    cost_limit_usd: float
    def __init__(
        self,
        latency_ms: _Optional[int] = ...,
        cost_usd: _Optional[float] = ...,
        tokens_used: _Optional[int] = ...,
        cost_limit_usd: _Optional[float] = ...,
    ) -> None: ...

class SecurityScopes(_message.Message):
    __slots__ = ("read", "write")
    READ_FIELD_NUMBER: _ClassVar[int]
    WRITE_FIELD_NUMBER: _ClassVar[int]
    read: _containers.RepeatedScalarFieldContainer[str]
    write: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, read: _Optional[_Iterable[str]] = ..., write: _Optional[_Iterable[str]] = ...) -> None: ...

class CotStep(_message.Message):
    __slots__ = ("agent", "action", "status", "timestamp")
    AGENT_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    agent: str
    action: str
    status: str
    timestamp: _timestamp_pb2.Timestamp
    def __init__(
        self,
        agent: _Optional[str] = ...,
        action: _Optional[str] = ...,
        status: _Optional[str] = ...,
        timestamp: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...,
    ) -> None: ...

class ContextUnit(_message.Message):
    __slots__ = (
        "unit_id",
        "trace_id",
        "parent_unit_id",
        "modality",
        "payload",
        "chain_of_thought",
        "metrics",
        "security",
        "created_at",
    )
    UNIT_ID_FIELD_NUMBER: _ClassVar[int]
    TRACE_ID_FIELD_NUMBER: _ClassVar[int]
    PARENT_UNIT_ID_FIELD_NUMBER: _ClassVar[int]
    MODALITY_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    CHAIN_OF_THOUGHT_FIELD_NUMBER: _ClassVar[int]
    METRICS_FIELD_NUMBER: _ClassVar[int]
    SECURITY_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    unit_id: str
    trace_id: str
    parent_unit_id: str
    modality: Modality
    payload: _struct_pb2.Struct
    chain_of_thought: _containers.RepeatedCompositeFieldContainer[CotStep]
    metrics: UnitMetrics
    security: SecurityScopes
    created_at: _timestamp_pb2.Timestamp
    def __init__(
        self,
        unit_id: _Optional[str] = ...,
        trace_id: _Optional[str] = ...,
        parent_unit_id: _Optional[str] = ...,
        modality: _Optional[_Union[Modality, str]] = ...,
        payload: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ...,
        chain_of_thought: _Optional[_Iterable[_Union[CotStep, _Mapping]]] = ...,
        metrics: _Optional[_Union[UnitMetrics, _Mapping]] = ...,
        security: _Optional[_Union[SecurityScopes, _Mapping]] = ...,
        created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...,
    ) -> None: ...
