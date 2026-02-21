"""Unified exception hierarchy for ContextUnity.

All services inherit from ContextUnityError. This module provides:
- Base exception hierarchy with stable error codes
- ErrorRegistry for protocol mapping
- gRPC error handler decorators (unary + streaming)

Usage in services:
    from contextcore.exceptions import (
        ContextUnityError,
        ConfigurationError,
        SecurityError,
        grpc_error_handler,
    )

Services may define thin subclasses for service-specific errors:
    class ContextbrainError(ContextUnityError):
        pass
"""

from __future__ import annotations

import functools
import logging
from typing import Any, Callable, TypeVar, cast

__all__ = [
    # Base hierarchy
    "ContextUnityError",
    "ConfigurationError",
    "RetrievalError",
    "IntentDetectionError",
    "ProviderError",
    "SecurityError",
    "ConnectorError",
    "ModelError",
    "IngestionError",
    "GraphBuilderError",
    "TransformerError",
    "StorageError",
    "DatabaseConnectionError",
    # Registry
    "ErrorRegistry",
    "error_registry",
    "register_error",
    # gRPC helpers
    "get_grpc_status_code",
    "grpc_error_handler",
    "grpc_stream_error_handler",
]

logger = logging.getLogger(__name__)


# ---- Exception Hierarchy ----------------------------------------------------


class ContextUnityError(Exception):
    """Base exception for all ContextUnity services.

    Attributes:
        code: Stable error code string for protocol mapping (e.g. "SECURITY_ERROR").
        message: Human-readable error description.
        details: Additional context as keyword arguments.
    """

    code: str = "INTERNAL_ERROR"
    message: str = "An internal error occurred"

    def __init__(self, message: str | None = None, code: str | None = None, **kwargs: Any) -> None:
        self.message = message or self.message
        self.code = code or self.code
        self.details = kwargs
        super().__init__(self.message)


class ConfigurationError(ContextUnityError):
    """Invalid or missing configuration."""

    code: str = "CONFIGURATION_ERROR"


class RetrievalError(ContextUnityError):
    """Retrieval pipeline failure."""

    code: str = "RETRIEVAL_ERROR"


class IntentDetectionError(ContextUnityError):
    """Intent classification failure."""

    code: str = "INTENT_ERROR"


class ProviderError(ContextUnityError):
    """Storage/Provider layer failure."""

    code: str = "PROVIDER_ERROR"


class SecurityError(ContextUnityError):
    """Authorization/security failure (token missing/invalid/expired)."""

    code: str = "SECURITY_ERROR"


class ConnectorError(ContextUnityError):
    """Data connector failure."""

    code: str = "CONNECTOR_ERROR"


class ModelError(ContextUnityError):
    """LLM or Embedding model failure."""

    code: str = "MODEL_ERROR"


class IngestionError(ContextUnityError):
    """Ingestion pipeline failure."""

    code: str = "INGESTION_ERROR"


class GraphBuilderError(ContextUnityError):
    """Graph building failure."""

    code: str = "GRAPH_BUILDER_ERROR"


class TransformerError(ContextUnityError):
    """Data transformation failure."""

    code: str = "TRANSFORMER_ERROR"


class StorageError(ProviderError):
    """Specific error for database or storage operations."""

    code: str = "STORAGE_ERROR"


class DatabaseConnectionError(StorageError):
    """Failed to connect to the database."""

    code: str = "DB_CONNECTION_ERROR"


# ---- Error Registry for Protocol Mapping ------------------------------------

_E = TypeVar("_E", bound=type[ContextUnityError])


class ErrorRegistry:
    """Registry for mapping internal errors to external protocol codes."""

    def __init__(self) -> None:
        self._errors: dict[str, type[ContextUnityError]] = {}

    def register(self, code: str, error_cls: type[ContextUnityError]) -> None:
        self._errors[code] = error_cls

    def get(self, code: str) -> type[ContextUnityError] | None:
        return self._errors.get(code)

    def all(self) -> dict[str, type[ContextUnityError]]:
        return dict(self._errors)


error_registry = ErrorRegistry()


def register_error(code: str) -> Callable[[_E], _E]:
    """Decorator to register a custom error type.

    Usage:
        @register_error("MY_CUSTOM_ERROR")
        class MyCustomError(ContextUnityError):
            code = "MY_CUSTOM_ERROR"
    """

    def decorator(cls: _E) -> _E:
        error_registry.register(code, cls)
        return cls

    return cast(Callable[[_E], _E], decorator)


# Register base errors
error_registry.register("INTERNAL_ERROR", ContextUnityError)
error_registry.register("CONFIGURATION_ERROR", ConfigurationError)
error_registry.register("RETRIEVAL_ERROR", RetrievalError)
error_registry.register("INTENT_ERROR", IntentDetectionError)
error_registry.register("PROVIDER_ERROR", ProviderError)
error_registry.register("SECURITY_ERROR", SecurityError)
error_registry.register("CONNECTOR_ERROR", ConnectorError)
error_registry.register("MODEL_ERROR", ModelError)
error_registry.register("INGESTION_ERROR", IngestionError)
error_registry.register("GRAPH_BUILDER_ERROR", GraphBuilderError)
error_registry.register("TRANSFORMER_ERROR", TransformerError)
error_registry.register("STORAGE_ERROR", StorageError)
error_registry.register("DB_CONNECTION_ERROR", DatabaseConnectionError)


# ---- gRPC Error Handling Utilities ------------------------------------------


def get_grpc_status_code(error: ContextUnityError) -> int:
    """Map ContextUnityError to gRPC status code.

    Returns grpc.StatusCode value for the given error type.
    Import grpc locally to avoid hard dependency at module level.
    """
    import grpc

    error_to_status = {
        "UNAUTHENTICATED": grpc.StatusCode.UNAUTHENTICATED,
        "PERMISSION_DENIED": grpc.StatusCode.PERMISSION_DENIED,
        "CONFIGURATION_ERROR": grpc.StatusCode.FAILED_PRECONDITION,
        "SECURITY_ERROR": grpc.StatusCode.PERMISSION_DENIED,
        "RETRIEVAL_ERROR": grpc.StatusCode.NOT_FOUND,
        "PROVIDER_ERROR": grpc.StatusCode.UNAVAILABLE,
        "STORAGE_ERROR": grpc.StatusCode.UNAVAILABLE,
        "DB_CONNECTION_ERROR": grpc.StatusCode.UNAVAILABLE,
        "CONNECTOR_ERROR": grpc.StatusCode.UNAVAILABLE,
        "MODEL_ERROR": grpc.StatusCode.INTERNAL,
        "INGESTION_ERROR": grpc.StatusCode.INVALID_ARGUMENT,
        "TRANSFORMER_ERROR": grpc.StatusCode.INVALID_ARGUMENT,
        "GRAPH_BUILDER_ERROR": grpc.StatusCode.INTERNAL,
        "INTENT_ERROR": grpc.StatusCode.INTERNAL,
    }
    return error_to_status.get(error.code, grpc.StatusCode.INTERNAL)


def grpc_error_handler(method):
    """Decorator for unary gRPC service methods with proper error handling.

    Catches ContextUnityError and sets appropriate gRPC status codes.
    Logs errors and ensures consistent error response format.

    Usage:
        @grpc_error_handler
        async def MyMethod(self, request, context):
            ...
    """

    @functools.wraps(method)
    async def wrapper(self, request, context):
        try:
            return await method(self, request, context)
        except ContextUnityError as e:
            import grpc

            status_code = get_grpc_status_code(e)
            error_message = f"[{e.code}] {e.message}"

            logger.error(
                "%s failed: %s",
                method.__name__,
                error_message,
                extra={
                    "error_code": e.code,
                    "error_details": e.details,
                },
            )

            context.set_trailing_metadata([("error-code", e.code)])
            await context.abort(status_code, error_message)
            return  # Explicit return — prevent implicit None response

        except Exception as e:
            import grpc

            logger.exception("%s unexpected error: %s", method.__name__, e)
            await context.abort(
                grpc.StatusCode.INTERNAL,
                f"Unexpected {type(e)}: {e}",
            )
            return  # Explicit return — prevent implicit None response

    return wrapper


def grpc_stream_error_handler(method):
    """Decorator for streaming gRPC service methods with proper error handling.

    Works with async generator methods that use 'yield'.
    Catches ContextUnityError and sets appropriate gRPC status codes.

    Usage:
        @grpc_stream_error_handler
        async def MyStreamingMethod(self, request, context):
            yield item1
            yield item2
    """

    @functools.wraps(method)
    async def wrapper(self, request, context):
        try:
            async for item in method(self, request, context):
                yield item
        except ContextUnityError as e:
            import grpc

            status_code = get_grpc_status_code(e)
            error_message = f"[{e.code}] {e.message}"

            logger.error(
                "%s failed: %s",
                method.__name__,
                error_message,
                extra={
                    "error_code": e.code,
                    "error_details": e.details,
                },
            )

            context.set_trailing_metadata([("error-code", e.code)])
            await context.abort(status_code, error_message)
            return  # Explicit return — prevent implicit None response

        except Exception as e:
            import grpc

            logger.exception("%s unexpected error: %s", method.__name__, e)
            await context.abort(
                grpc.StatusCode.INTERNAL,
                f"Unexpected {type(e)}: {e}",
            )
            return  # Explicit return — prevent implicit None response

    return wrapper
