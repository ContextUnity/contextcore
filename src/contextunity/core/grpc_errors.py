"""gRPC error handling decorators for ContextUnity services.

Provides ``@grpc_error_handler`` (async unary), ``@grpc_stream_error_handler``
(async streaming), and ``@grpc_sync_error_handler`` (synchronous unary)
decorators that catch ``ContextUnityError`` and map them to appropriate gRPC
status codes via the ``ErrorRegistry``.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable, Coroutine
from typing import TYPE_CHECKING, ParamSpec, TypeVar, overload

if TYPE_CHECKING:
    import grpc

from .exceptions import ContextUnityError
from .logging import get_contextunit_logger
from .types import (
    GrpcRequest,
    GrpcServicerContext,
    GrpcStreamErrorResponseFactory,
    GrpcUnaryErrorResponseFactory,
)

logger = get_contextunit_logger(__name__)

P = ParamSpec("P")
R = TypeVar("R")
StreamItem = TypeVar("StreamItem")

# ---------------------------------------------------------------------------
# Error-code → gRPC-status mapping
# ---------------------------------------------------------------------------

#: Maps ContextUnityError codes to gRPC status codes.
#: Kept as a module-level constant; ``grpc`` is imported lazily at first use.
_ERROR_CODE_MAP: dict[str, str] = {
    "UNAUTHENTICATED": "UNAUTHENTICATED",
    "PERMISSION_DENIED": "PERMISSION_DENIED",
    "CONFIGURATION_ERROR": "FAILED_PRECONDITION",
    "SHIELD_DECRYPTION_ERROR": "FAILED_PRECONDITION",
    "SECURITY_ERROR": "PERMISSION_DENIED",
    "TAMPER_DETECTED": "ABORTED",
    # policy_fault: cross-tenant/spoofing rejection is a permission denial,
    # not a generic internal error (would otherwise fall through the BRAIN
    # prefix to INTERNAL, per _SERVICE_PREFIX_MAP below).
    "BRAIN_VALIDATION_ERROR": "INVALID_ARGUMENT",
    "BRAIN_SYNAPSES_DISABLED": "FAILED_PRECONDITION",
    "BRAIN_SYNAPSE_TENANT_MISMATCH": "PERMISSION_DENIED",
    "BRAIN_CELL_NOT_FOUND": "NOT_FOUND",
    "RETRIEVAL_ERROR": "NOT_FOUND",
    "PROVIDER_ERROR": "UNAVAILABLE",
    "STORAGE_ERROR": "UNAVAILABLE",
    "DB_CONNECTION_ERROR": "UNAVAILABLE",
    "PLATFORM_SERVICE_ERROR": "UNAVAILABLE",
    # Service-owned exception codes (registered by services at import time)
    "ROUTER_TOOL_TIMEOUT": "DEADLINE_EXCEEDED",
    "ROUTER_LLM_ERROR": "INTERNAL",
    "ROUTER_CATALOG_ERROR": "FAILED_PRECONDITION",
    "ROUTER_GRAPH_BUILDER_ERROR": "INTERNAL",
    "ROUTER_INTENT_DETECTION_ERROR": "INTERNAL",
    "ROUTER_STREAM_ERROR": "INTERNAL",
    "ROUTER_PII_ERROR": "INTERNAL",
    "ROUTER_STORAGE_ERROR": "UNAVAILABLE",
    "INGESTION_ERROR": "INVALID_ARGUMENT",
    "TRANSFORMER_ERROR": "INVALID_ARGUMENT",
}

#: Prefix-based fallback for service-specific error codes.
#: When exact code is not in ``_ERROR_CODE_MAP``, the first segment
#: (e.g. ``ROUTER`` from ``ROUTER_LLM_ERROR``) is checked here.
#: This allows services to define their own codes without touching core.
_SERVICE_PREFIX_MAP: dict[str, str] = {
    "ROUTER": "INTERNAL",
    "BRAIN": "INTERNAL",
    "SHIELD": "FAILED_PRECONDITION",
    "COMMERCE": "INTERNAL",
    "WORKSHOP": "INTERNAL",
    "WORKER": "INTERNAL",
}


def _resolve_status_name(code: str) -> str:
    """Resolve a ContextUnityError code to a gRPC status name.

    Tries exact match first, then falls back to service prefix matching.

    Args:
        code: The error code string (e.g. ``"ROUTER_LLM_ERROR"``).

    Returns:
        A gRPC StatusCode name string (e.g. ``"INTERNAL"``).
    """
    exact = _ERROR_CODE_MAP.get(code)
    if exact is not None:
        return exact
    prefix = code.split("_", 1)[0]
    return _SERVICE_PREFIX_MAP.get(prefix, "INTERNAL")


def get_grpc_status_code(error: ContextUnityError) -> grpc.StatusCode:
    """Map a ContextUnityError to its corresponding gRPC StatusCode.

    Uses exact code match first, then falls back to service prefix mapping.

    Args:
        error: The ContextUnityError to extract the code from.

    Returns:
        The matched ``grpc.StatusCode`` instance. Defaults to ``INTERNAL``.
    """
    status_name = _resolve_status_name(error.code)
    return _status_code_from_name(status_name)


def _status_code_from_name(name: str) -> grpc.StatusCode:
    """Resolve a gRPC status *name* to the concrete ``grpc.StatusCode`` enum member."""
    import grpc

    known: dict[str, grpc.StatusCode] = {
        "UNAUTHENTICATED": grpc.StatusCode.UNAUTHENTICATED,
        "PERMISSION_DENIED": grpc.StatusCode.PERMISSION_DENIED,
        "FAILED_PRECONDITION": grpc.StatusCode.FAILED_PRECONDITION,
        "ABORTED": grpc.StatusCode.ABORTED,
        "NOT_FOUND": grpc.StatusCode.NOT_FOUND,
        "UNAVAILABLE": grpc.StatusCode.UNAVAILABLE,
        "DEADLINE_EXCEEDED": grpc.StatusCode.DEADLINE_EXCEEDED,
        "INVALID_ARGUMENT": grpc.StatusCode.INVALID_ARGUMENT,
        "INTERNAL": grpc.StatusCode.INTERNAL,
    }
    return known.get(name, grpc.StatusCode.INTERNAL)


def _classify_exception(exc: Exception) -> tuple[str, str]:
    """Classify an exception into a (gRPC status name, message) tuple.

    Handles ContextUnityError instances, ValueError, PermissionError, and generic Python exceptions.

    Args:
        exc: The raised exception instance.

    Returns:
        tuple[str, str]: A tuple of (gRPC status name string, serialized error message).
    """
    if isinstance(exc, ContextUnityError):
        status = _resolve_status_name(exc.code)
        return status, f"[{exc.code}] {exc.message}"

    if isinstance(exc, ValueError):
        return "INVALID_ARGUMENT", str(exc) or "Validation error"
    if isinstance(exc, PermissionError):
        return "PERMISSION_DENIED", str(exc) or "Permission denied"
    return "INTERNAL", f"Unexpected {type(exc).__name__}: {exc}"


def _log_and_set_metadata(
    method_name: str,
    context: GrpcServicerContext,
    exc: Exception,
    error_message: str,
) -> None:
    """Log the exception details and attach error codes to the gRPC trailing metadata.

    Allows downstream gRPC clients (like the ContextUnity SDK client) to extract
    the original platform-specific error code without parsing the message string.

    Args:
        method_name: Name of the gRPC method where the error occurred.
        context: The active gRPC servicer context.
        exc: The raised exception.
        error_message: The formatted error message.
    """
    if isinstance(exc, ContextUnityError):
        logger.error(
            "%s failed: %s",
            method_name,
            error_message,
            extra={
                "error_code": exc.code,
                "error_details": exc.details,
            },
        )
        context.set_trailing_metadata((("error-code", exc.code),))
    else:
        logger.exception("%s unexpected error: %s", method_name, exc)


def _extract_request_context(args: tuple[object, ...]) -> tuple[GrpcRequest, GrpcServicerContext]:
    """Extract request and context from a standard ``(self, request, context)`` call."""
    if len(args) < 3:
        raise TypeError("gRPC handler must be called as (self, request, context)")
    request = args[1]
    context = args[2]
    if not isinstance(context, GrpcServicerContext):
        raise TypeError("gRPC context must implement GrpcServicerContext")
    return request, context


# ---------------------------------------------------------------------------
# Async unary decorator
# ---------------------------------------------------------------------------


@overload
def grpc_error_handler(
    method: None = None,
    *,
    response_factory: GrpcUnaryErrorResponseFactory[R] | None = None,
) -> Callable[[Callable[P, Coroutine[object, object, R]]], Callable[P, Coroutine[object, object, R]]]: ...


@overload
def grpc_error_handler(
    method: Callable[P, Coroutine[object, object, R]],
    *,
    response_factory: GrpcUnaryErrorResponseFactory[R] | None = None,
) -> Callable[P, Coroutine[object, object, R]]: ...


def grpc_error_handler(
    method: Callable[P, Coroutine[object, object, R]] | None = None,
    *,
    response_factory: GrpcUnaryErrorResponseFactory[R] | None = None,
) -> (
    Callable[[Callable[P, Coroutine[object, object, R]]], Callable[P, Coroutine[object, object, R]]]
    | Callable[P, Coroutine[object, object, R]]
):
    """Decorator for unary gRPC service methods to handle exceptions cleanly.

    Catches raised exceptions, maps them to standard gRPC statuses, sets trailing metadata
    headers with ContextUnity-specific error codes, and aborts the RPC context.

    If a ``response_factory`` is provided, instead of aborting the context, it sets the status
    code and returns a fallback response object generated by the factory.

    Can be used bare (``@grpc_error_handler``) or with keyword arguments
    (``@grpc_error_handler(response_factory=...)``)::

        @grpc_error_handler
        async def MyRpc(self, request, context): ...

    Args:
        method: The async unary gRPC servicer method to wrap.
        response_factory: Optional factory callable to return a custom fallback response.

    Returns:
        The wrapped gRPC servicer method or a decorator function.
    """
    if method is None:
        return lambda m: grpc_error_handler(m, response_factory=response_factory)

    original = method

    async def _wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return await original(*args, **kwargs)
        except asyncio.CancelledError:
            logger.info(
                "Request %s cancelled (client disconnected or server shutting down)",
                original.__name__,
            )
            raise
        except Exception as exc:
            import grpc

            if isinstance(exc, grpc.RpcError):
                raise

            status_name, error_message = _classify_exception(exc)
            status_code = _status_code_from_name(status_name)
            request, context = _extract_request_context(args)
            _log_and_set_metadata(original.__name__, context, exc, error_message)

            if response_factory:
                context.set_code(status_code)
                context.set_details(error_message)
                return response_factory(request, context, exc)

            await context.abort(status_code, error_message)
            raise asyncio.CancelledError(f"Aborted via {type(exc).__name__}")

    _wrapper.__name__ = original.__name__
    _wrapper.__qualname__ = original.__qualname__
    _wrapper.__doc__ = original.__doc__
    _wrapper.__module__ = original.__module__
    setattr(_wrapper, "__wrapped__", original)
    return _wrapper


# ---------------------------------------------------------------------------
# Async streaming decorator
# ---------------------------------------------------------------------------


@overload
def grpc_stream_error_handler(
    method: None = None,
    *,
    response_factory: GrpcStreamErrorResponseFactory[StreamItem] | None = None,
) -> Callable[
    [Callable[P, AsyncIterator[StreamItem]]],
    Callable[P, AsyncIterator[StreamItem]],
]: ...


@overload
def grpc_stream_error_handler(
    method: Callable[P, AsyncIterator[StreamItem]],
    *,
    response_factory: GrpcStreamErrorResponseFactory[StreamItem] | None = None,
) -> Callable[P, AsyncIterator[StreamItem]]: ...


def grpc_stream_error_handler(
    method: Callable[P, AsyncIterator[StreamItem]] | None = None,
    *,
    response_factory: GrpcStreamErrorResponseFactory[StreamItem] | None = None,
) -> (
    Callable[[Callable[P, AsyncIterator[StreamItem]]], Callable[P, AsyncIterator[StreamItem]]]
    | Callable[P, AsyncIterator[StreamItem]]
):
    """Decorator for streaming gRPC service methods to handle exceptions cleanly.

    Similar to ``@grpc_error_handler``, but wraps async generators and yields values.

    Args:
        method: The async streaming gRPC servicer method to wrap.
        response_factory: Optional factory callable to yield a fallback response item.

    Returns:
        The wrapped streaming gRPC method or a decorator function.
    """
    if method is None:
        return lambda m: grpc_stream_error_handler(m, response_factory=response_factory)

    original = method

    async def _wrapper(*args: P.args, **kwargs: P.kwargs) -> AsyncIterator[StreamItem]:
        try:
            async for item in original(*args, **kwargs):
                yield item
        except asyncio.CancelledError:
            logger.info(
                "Stream %s cancelled (client disconnected or server shutting down)",
                original.__name__,
            )
            raise
        except Exception as exc:
            import grpc

            if isinstance(exc, grpc.RpcError):
                raise

            status_name, error_message = _classify_exception(exc)
            status_code = _status_code_from_name(status_name)
            request, context = _extract_request_context(args)
            _log_and_set_metadata(original.__name__, context, exc, error_message)

            if response_factory:
                context.set_code(status_code)
                context.set_details(error_message)
                yield response_factory(request, context, exc)
                return

            await context.abort(status_code, error_message)
            raise asyncio.CancelledError(f"Aborted via {type(exc).__name__}")

    _wrapper.__name__ = original.__name__
    _wrapper.__qualname__ = original.__qualname__
    _wrapper.__doc__ = original.__doc__
    _wrapper.__module__ = original.__module__
    setattr(_wrapper, "__wrapped__", original)
    return _wrapper


# ---------------------------------------------------------------------------
# Synchronous unary decorator
# ---------------------------------------------------------------------------


@overload
def grpc_sync_error_handler(
    method: None = None,
    *,
    response_factory: GrpcUnaryErrorResponseFactory[R] | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R | None]]: ...


@overload
def grpc_sync_error_handler(
    method: Callable[P, R],
    *,
    response_factory: GrpcUnaryErrorResponseFactory[R] | None = None,
) -> Callable[P, R | None]: ...


def grpc_sync_error_handler(
    method: Callable[P, R] | None = None,
    *,
    response_factory: GrpcUnaryErrorResponseFactory[R] | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R | None]] | Callable[P, R | None]:
    """Decorator for synchronous unary gRPC service methods to handle exceptions cleanly.

    Identical to ``@grpc_error_handler`` but for non-async servicers (e.g. Zero).
    Catches raised exceptions, maps them to standard gRPC statuses, and aborts the context.

    Args:
        method: The synchronous unary gRPC servicer method to wrap.
        response_factory: Optional factory callable to return a custom fallback response.

    Returns:
        The wrapped synchronous gRPC servicer method or a decorator function.
    """
    if method is None:
        return lambda m: grpc_sync_error_handler(m, response_factory=response_factory)

    original = method

    def _wrapper(*args: P.args, **kwargs: P.kwargs) -> R | None:
        try:
            return original(*args, **kwargs)
        except Exception as exc:
            import grpc

            if isinstance(exc, grpc.RpcError):
                raise

            status_name, error_message = _classify_exception(exc)
            status_code = _status_code_from_name(status_name)
            request, context = _extract_request_context(args)
            _log_and_set_metadata(original.__name__, context, exc, error_message)

            if response_factory:
                context.set_code(status_code)
                context.set_details(error_message)
                return response_factory(request, context, exc)

            context.set_code(status_code)
            context.set_details(error_message)
            return None

    _wrapper.__name__ = original.__name__
    _wrapper.__qualname__ = original.__qualname__
    _wrapper.__doc__ = original.__doc__
    _wrapper.__module__ = original.__module__
    setattr(_wrapper, "__wrapped__", original)
    return _wrapper
