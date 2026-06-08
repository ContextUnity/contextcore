"""Shared SDK typing aliases.

Centralizes lightweight JSON/payload aliases used across bootstrap, identity,
and streaming helpers to keep contracts consistent.
"""

from __future__ import annotations

from collections.abc import Awaitable, Iterator, Mapping
from typing import TYPE_CHECKING, ClassVar, Protocol, TypeAlias, TypeVar, runtime_checkable

from contextunity.core.manifest.models import WorkerBindingsBundle
from contextunity.core.types import (
    ContextUnitPayload,
    JsonDict,
    JsonPrimitive,
    JsonValue,
    is_object_dict,
    is_object_list,
    is_object_set,
    is_object_tuple,
)
from pydantic import BaseModel, ConfigDict

if TYPE_CHECKING:
    import grpc.aio
    from contextunity.core import contextunit_pb2
    from contextunity.core.sdk.streaming.bidi import FederatedToolCallContext
    from contextunity.core.tokens import ContextToken

    UnaryContextUnitRpc: TypeAlias = grpc.aio.UnaryUnaryMultiCallable[
        contextunit_pb2.ContextUnit,
        contextunit_pb2.ContextUnit,
    ]
else:
    import grpc.aio
    from contextunity.core import contextunit_pb2

    UnaryContextUnitRpc = grpc.aio.UnaryUnaryMultiCallable[
        contextunit_pb2.ContextUnit,
        contextunit_pb2.ContextUnit,
    ]

T_co = TypeVar("T_co", covariant=True)
_RequestT = TypeVar("_RequestT")
_ResponseT = TypeVar("_ResponseT")

ToolPayload: TypeAlias = ContextUnitPayload
ToolResult: TypeAlias = ContextUnitPayload
PromptMap: TypeAlias = Mapping[str, str | JsonDict]

WorkerBindings = WorkerBindingsBundle


@runtime_checkable
class TokenProviderFactory(Protocol):
    """Lazy factory that mints a fresh ``ContextToken`` per gRPC call."""

    def __call__(self) -> ContextToken: ...


@runtime_checkable
class FederatedToolCallable(Protocol):
    """Project tool function registered via ``@federated_tool`` or ``@tool``."""

    def __call__(self, *args: object, **kwargs: object) -> object: ...


@runtime_checkable
class AsyncFederatedToolCallable(Protocol):
    """Async toolkit bridge wrapper around a federated ``@tool`` method."""

    async def __call__(self, *args: object, **kwargs: object) -> object: ...


type FederatedToolHandler = FederatedToolCallable | AsyncFederatedToolCallable


@runtime_checkable
class SyncIteratorFactory(Protocol[T_co]):
    """Factory returning a blocking iterator (used by sync stream bridges)."""

    def __call__(self) -> Iterator[T_co]: ...


@runtime_checkable
class ManifestRegistrationCallback(Protocol):
    """Bootstrap reconnect hook returning ``(stream_secret, shield_url)``."""

    def __call__(self) -> tuple[str, str]: ...


@runtime_checkable
class TokenStringProvider(Protocol):
    """Lazy factory returning a bearer token string or structured ``ContextToken``."""

    def __call__(self) -> "ContextToken | str": ...


@runtime_checkable
class ReplaceableClientCallDetails(Protocol):
    """gRPC client call details supporting metadata replacement."""

    metadata: object | None

    def _replace(self, **kwargs: object) -> "grpc.aio.ClientCallDetails": ...


@runtime_checkable
class GrpcUnaryUnaryClientContinuation(Protocol[_RequestT, _ResponseT]):
    """Next handler in the async client interceptor chain."""

    def __call__(
        self,
        client_call_details: "grpc.aio.ClientCallDetails",
        request: _RequestT,
        /,
    ) -> Awaitable["grpc.aio.UnaryUnaryCall[_RequestT, _ResponseT]"]: ...


class ToolHandler(Protocol):
    """Protocol for unified federated tool execution handlers."""

    def __call__(
        self,
        tool_name: str,
        args: ContextUnitPayload,
        auth_ctx: FederatedToolCallContext,
    ) -> ContextUnitPayload: ...


# ---- StructData typing -------------------------------------------------------
#
# Canonical JSON types live in ``contextunity.core.types``; SDK re-exports them
# under the StructData* names for router/brain integration boundaries.

StructDataPrimitive = JsonPrimitive
StructDataValue = JsonValue
StructData = JsonDict


def coerce_struct_data(value: object) -> JsonValue:
    """Best-effort conversion into JSON-serializable StructDataValue.

    Used at integration boundaries where external SDKs return loosely-typed
    Python objects. Intentionally conservative.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if is_object_dict(value):
        out: StructData = {}
        for key, item in value.items():
            out[str(key)] = coerce_struct_data(item)
        return out
    if is_object_list(value):
        return [coerce_struct_data(item) for item in value]
    if is_object_tuple(value):
        return [coerce_struct_data(item) for item in value]
    if is_object_set(value):
        return [coerce_struct_data(item) for item in sorted(value, key=str)]
    # Fallback: stringify unknown objects (keeps JSON serializable)
    return str(value)


# ---- Payload base model -------------------------------------------------------


class StrictPayloadModel(BaseModel):
    """Base model for gRPC payload contracts.

    ``extra='forbid'`` prevents payload injection attacks.
    All service payload models should inherit from this class.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid")


# ---- gRPC metadata typing ----------------------------------------------------

GrpcMetadataEntry: TypeAlias = tuple[str, str | bytes]
# Sync/async gRPC stubs expect an immutable tuple of pairs (``grpc._Metadata``).
GrpcMetadata: TypeAlias = tuple[GrpcMetadataEntry, ...]


__all__ = [
    "ContextUnitPayload",
    "JsonPrimitive",
    "JsonValue",
    "JsonDict",
    "ToolPayload",
    "ToolResult",
    "PromptMap",
    "WorkerBindingsBundle",
    "WorkerBindings",
    "TokenProviderFactory",
    "FederatedToolCallable",
    "AsyncFederatedToolCallable",
    "FederatedToolHandler",
    "SyncIteratorFactory",
    "ManifestRegistrationCallback",
    "TokenStringProvider",
    "ReplaceableClientCallDetails",
    "GrpcUnaryUnaryClientContinuation",
    "UnaryContextUnitRpc",
    "ToolHandler",
    "StructDataPrimitive",
    "StructDataValue",
    "StructData",
    "coerce_struct_data",
    "StrictPayloadModel",
    "GrpcMetadataEntry",
    "GrpcMetadata",
]
