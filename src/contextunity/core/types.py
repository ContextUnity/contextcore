"""Platform-wide type aliases for JSON payloads, gRPC contracts, and log context.

These types are intentionally loose at external boundaries
and should be narrowed by validators before business logic consumes them.
"""

from __future__ import annotations

import math
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine, Iterable, Mapping
from typing import TYPE_CHECKING, Protocol, TypeAlias, TypeGuard, TypeVar, runtime_checkable

if TYPE_CHECKING:
    import grpc

# -----------------------------------------------------------------------------
# Wire / parse boundary (L1 — output of parsing.py only)
# -----------------------------------------------------------------------------
WireValue: TypeAlias = object
"""Value freshly decoded from JSON, YAML, or TOML before domain narrowing."""

# -----------------------------------------------------------------------------
# JSON-like value tree (L2 — JSON-serializable recursive tree)
# -----------------------------------------------------------------------------
JsonPrimitive: TypeAlias = str | int | float | bool | None
type JsonValue = JsonPrimitive | list[JsonValue] | dict[str, JsonValue]
"""Recursive JSON-compatible value.

Defined as a PEP 695 ``type`` alias (``TypeAliasType``) rather than a plain
``TypeAlias`` so that the recursive self-reference resolves against this
module's namespace. This lets Pydantic models declared in *other* modules
(e.g. router ``ModelRequest``) rebuild fields typed as ``JsonValue`` /
``StructDataValue`` without needing ``JsonValue`` imported at the use site.
"""

JsonDict: TypeAlias = dict[str, JsonValue]
"""Mutable JSON object mapping (manifests, prompt maps)."""

# Convenience aliases for common payload shapes
JsonArray: TypeAlias = list[JsonValue]
JsonObject: TypeAlias = dict[str, JsonValue]

# -----------------------------------------------------------------------------
# Config (L2 — validated JSON config tree)
# -----------------------------------------------------------------------------
ConfigMapping: TypeAlias = JsonDict
"""Alias for nested config after L2 JSON validation (YAML/TOML load boundary)."""

# -----------------------------------------------------------------------------
# ContextUnity domain payloads (used in ContextUnit, log context, etc.)
# -----------------------------------------------------------------------------
ContextUnitPayload: TypeAlias = dict[str, object]
"""Open ContextUnit gRPC payload (protobuf Struct wire before sanitize/coerce)."""

LogContext: TypeAlias = Mapping[str, JsonValue]
"""Structured logging context for JSON-safe fields — not stdlib ``logging.extra``."""


def is_object_dict(value: object) -> TypeGuard[dict[str, object]]:
    """Narrow an arbitrary value to a string-keyed object dict."""
    return isinstance(value, dict)


def is_json_dict(value: object) -> TypeGuard[JsonDict]:
    """Narrow wire data to a JSON object mapping (recursive L2 validation)."""
    return is_object_dict(value) and is_json_value(value)


def is_json_value(value: object) -> TypeGuard[JsonValue]:
    """Recursively narrow wire data to a JSON-serializable value tree."""
    if value is None or isinstance(value, (str, bool)):
        return True
    if isinstance(value, float):
        return not (math.isnan(value) or math.isinf(value))
    if isinstance(value, int):
        return True
    if is_object_list(value):
        return all(is_json_value(item) for item in value)
    if is_object_dict(value):
        for key in value:
            if type(key) is not str:
                return False
        return all(is_json_value(item) for item in value.values())
    return False


def is_object_mapping(value: object) -> TypeGuard[Mapping[object, object]]:
    """Narrow an arbitrary value to a mapping."""
    return isinstance(value, Mapping)


def is_object_set(value: object) -> TypeGuard[set[object] | frozenset[object]]:
    """Narrow an arbitrary value to a set or frozenset."""
    return isinstance(value, (set, frozenset))


def is_object_sequence(value: object) -> TypeGuard[tuple[object, ...] | list[object]]:
    """Narrow an arbitrary value to a list or tuple."""
    return isinstance(value, (list, tuple))


def is_object_list(value: object) -> TypeGuard[list[object]]:
    """Narrow an arbitrary value to a list of objects."""
    return isinstance(value, list)


def is_object_pair(value: object) -> TypeGuard[tuple[object, object]]:
    """Narrow an arbitrary value to a two-element object tuple."""
    return isinstance(value, tuple) and value.__len__() == 2


def is_object_tuple(value: object) -> TypeGuard[tuple[object, ...]]:
    """Narrow an arbitrary value to a tuple of objects."""
    return isinstance(value, tuple)


def is_object_iterable(value: object) -> TypeGuard[Iterable[object]]:
    """Narrow an arbitrary value to a non-string iterable of objects."""
    return isinstance(value, Iterable) and not isinstance(value, (str, bytes))


# -----------------------------------------------------------------------------
# gRPC handler signatures (replaces Callable[..., Any])
# -----------------------------------------------------------------------------

GrpcRequest: TypeAlias = object
"""Opaque gRPC request — converted via from_protobuf."""

GrpcResponse: TypeAlias = object
"""Opaque gRPC response — converted via to_protobuf."""

# Servicer method shapes used by ``@grpc_error_handler`` wrappers (self-bound).
GrpcHandler: TypeAlias = Callable[..., Coroutine[object, object, GrpcResponse]]
GrpcStreamHandler: TypeAlias = Callable[..., AsyncIterator[GrpcResponse]]


@runtime_checkable
class GrpcServicerContext(Protocol):
    """Protocol for gRPC servicer context - defines the interface we actually use.

    This is what gRPC interceptors and error handlers work with. The full
    grpc.ServicerContext is wider (has more methods), but we only use this subset.

    Do **not** require ``get_trailing_metadata`` — neither ``grpc.ServicerContext`` nor
    ``grpc.aio.ServicerContext`` expose it; including it breaks ``@runtime_checkable``
    ``isinstance`` checks and masks real handler errors in ``@grpc_error_handler``.
    """

    def set_trailing_metadata(self, metadata: tuple[tuple[str, str], ...]) -> None: ...
    async def abort(self, code: object, details: str) -> None: ...
    def set_code(self, code: object) -> None: ...
    def set_details(self, details: str) -> None: ...
    def invocation_metadata(self) -> Iterable[tuple[str, str | bytes]]: ...


# -----------------------------------------------------------------------------
# Third-party opaque values (used sparingly, with justification)
# -----------------------------------------------------------------------------
ProtobufMessage: TypeAlias = object
"""Opaque protobuf message — converted via to_protobuf/from_protobuf."""


R_co = TypeVar("R_co", covariant=True)
StreamItem_co = TypeVar("StreamItem_co", covariant=True)
T_co = TypeVar("T_co", covariant=True)


@runtime_checkable
class ConfigFactory(Protocol[T_co]):
    """Lazy factory for service configuration singletons."""

    def __call__(self) -> T_co: ...


@runtime_checkable
class AsyncShutdownHook(Protocol):
    """Hook invoked before gRPC server shutdown."""

    async def __call__(self) -> None: ...


_T_err = TypeVar("_T_err")


@runtime_checkable
class ErrorClassDecorator(Protocol[_T_err]):
    """Decorator that registers an exception subclass under a stable code."""

    def __call__(self, cls: type[_T_err]) -> type[_T_err]: ...


@runtime_checkable
class GrpcServiceInterceptorContinuation(Protocol):
    """Next handler in the gRPC server interceptor chain."""

    def __call__(
        self,
        handler_call_details: "grpc.HandlerCallDetails",
        /,
    ) -> Awaitable["grpc.RpcMethodHandler[object, object] | None"]: ...


class GrpcUnaryErrorResponseFactory(Protocol[R_co]):
    """Build a fallback unary RPC response when an error decorator catches an exception.

    Used by ``@grpc_error_handler`` and ``@grpc_sync_error_handler`` instead of aborting
    the RPC when the servicer can still return a structured error payload.
    """

    def __call__(
        self,
        request: GrpcRequest,
        context: GrpcServicerContext,
        exc: Exception,
    ) -> R_co: ...


class GrpcStreamErrorResponseFactory(Protocol[StreamItem_co]):
    """Build one fallback stream item when a streaming error decorator catches an exception.

    Used by ``@grpc_stream_error_handler`` to yield a terminal error event before closing.
    """

    def __call__(
        self,
        request: GrpcRequest,
        context: GrpcServicerContext,
        exc: Exception,
    ) -> StreamItem_co: ...


__all__ = [
    "WireValue",
    "JsonPrimitive",
    "JsonValue",
    "JsonDict",
    "JsonArray",
    "JsonObject",
    "ConfigMapping",
    "ContextUnitPayload",
    "LogContext",
    "is_object_dict",
    "is_json_dict",
    "is_json_value",
    "is_object_mapping",
    "is_object_set",
    "is_object_sequence",
    "is_object_list",
    "is_object_pair",
    "is_object_tuple",
    "is_object_iterable",
    "GrpcRequest",
    "GrpcResponse",
    "GrpcHandler",
    "GrpcStreamHandler",
    "GrpcServicerContext",
    "GrpcUnaryErrorResponseFactory",
    "GrpcStreamErrorResponseFactory",
    "ConfigFactory",
    "AsyncShutdownHook",
    "ErrorClassDecorator",
    "GrpcServiceInterceptorContinuation",
    "ProtobufMessage",
]
