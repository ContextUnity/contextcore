"""Unified exception hierarchy for ContextUnity.
All services inherit from ContextUnityError. This module provides:
- Base exception hierarchy with stable error codes
- ErrorRegistry for protocol mapping
gRPC error handler decorators live in ``grpc_errors.py`` (separate concern).
Usage in services:
    from contextunity.core.exceptions import (
        ContextUnityError,
        ConfigurationError,
        SecurityError,
    )
    from contextunity.core.grpc_errors import grpc_error_handler
Services may define thin subclasses for service-specific errors:
    class ContextbrainError(ContextUnityError):
        pass
"""

from __future__ import annotations

from typing import TypedDict, TypeVar

from .logging import get_contextunit_logger

__all__ = [
    # Base hierarchy (infrastructure — KEEP)
    "ContextUnityError",
    "ErrorDetails",
    "ConfigurationError",
    "ShieldDecryptionError",
    "ProviderError",
    "SecurityError",
    "TamperDetectedError",
    "StorageError",
    "DatabaseConnectionError",
    "PlatformServiceError",
    # Infrastructure
    "RedisNotAvailable",
    "RedisConnectionError",
    "ServiceStartupError",
    # Registry
    "ErrorRegistry",
    "error_registry",
    "register_error",
]

logger = get_contextunit_logger(__name__)

# ---- Exception Hierarchy ----------------------------------------------------


class ErrorDetails(TypedDict, total=False):
    """Well-known optional keys in ``ContextUnityError.details``.

    ``details`` remains an open bag — callers may attach any diagnostic kwargs.
    These names are documented for IDE hints and log/query conventions only.
    """

    path: str
    service: str
    tenant_id: str
    rpc: str
    project_id: str
    cause: str


class ContextUnityError(Exception):
    """Base exception for all ContextUnity services.

    Attributes:
        code: Stable error code string for protocol mapping (e.g. "SECURITY_ERROR").
        message: Human-readable error description.
        details: Arbitrary diagnostic kwargs from ``**kwargs`` — not JSON-guaranteed.
    """

    code: str = "INTERNAL_ERROR"
    message: str = "An internal error occurred"
    details: dict[str, object]  # arbitrary diagnostic kwargs — not JSON-guaranteed

    def __init__(self, message: str | None = None, code: str | None = None, **kwargs: object) -> None:
        """Initialize a ContextUnity error.

        Args:
            message: Optional override for the default error message.
            code: Optional override for the default error code.
            **kwargs: Additional key-value pairs stored in `details` for context.
        """
        self.message = message or self.message
        self.code = code or self.code
        self.details = kwargs
        super().__init__(self.message)


class ConfigurationError(ContextUnityError):
    """Invalid or missing configuration."""

    code: str = "CONFIGURATION_ERROR"


class ShieldDecryptionError(ConfigurationError):
    """Shield database decryption failed due to invalid master key or mismatched secrets."""

    code: str = "SHIELD_DECRYPTION_ERROR"


class ProviderError(ContextUnityError):
    """Storage/Provider layer failure."""

    code: str = "PROVIDER_ERROR"


class SecurityError(ContextUnityError):
    """Authorization/security failure (token missing/invalid/expired)."""

    code: str = "SECURITY_ERROR"


class TamperDetectedError(SecurityError):
    """Prompt integrity violation — signature does not match content."""

    code: str = "TAMPER_DETECTED"


class StorageError(ProviderError):
    """Specific error for database or storage operations."""

    code: str = "STORAGE_ERROR"


class DatabaseConnectionError(StorageError):
    """Failed to connect to the database."""

    code: str = "DB_CONNECTION_ERROR"


class PlatformServiceError(ContextUnityError):
    """Platform service (Brain/Shield/Zero/Worker) call failure."""

    code: str = "PLATFORM_SERVICE_ERROR"


# ---- Infrastructure Exceptions ----------------------------------------------


class RedisNotAvailable(ConfigurationError):
    """Redis package is not installed in this environment.

    Raised by discovery operations when ``redis`` is not importable.
    Caught and degraded gracefully — never propagated to callers.
    """

    code: str = "REDIS_NOT_AVAILABLE"


class RedisConnectionError(StorageError):
    """Redis connection failure (timeout, TLS mismatch, auth error).

    Raised by discovery and persistence layers when a Redis server
    is configured but unreachable.  Includes the safe (masked) URL
    and an automatic TLS hint when ``rediss://`` is used against
    a non-TLS server.
    """

    code: str = "REDIS_CONNECTION_ERROR"

    def __init__(self, cause: Exception, url: str | None = None, **kwargs: object) -> None:
        """Initialize the Redis connection error with context.

        Args:
            cause: The underlying exception raised by the Redis client.
            url: The attempted connection URL (sensitive parts are masked automatically).
            **kwargs: Additional error context.
        """
        hint = ""
        safe_url = ""
        if url is not None:
            safe_url = url.split("@")[-1]
            if url.startswith("rediss://"):
                hint = " (Hint: URL uses rediss:// (TLS) but server may not support TLS — try redis:// instead)"
        message = f"{cause} at {safe_url}{hint}" if safe_url else str(cause)
        super().__init__(message=message, cause=str(cause), safe_url=safe_url)
        self.details.update(kwargs)
        self.__cause__: BaseException | None = cause


class ServiceStartupError(ConfigurationError):
    """A service failed to start during local platform bootstrap.

    Raised by ``LocalSupervisor`` when a gRPC factory or background
    process fails to initialize.
    """

    code: str = "SERVICE_STARTUP_ERROR"


# ---- Error Registry for Protocol Mapping ------------------------------------

_E = TypeVar("_E", bound=ContextUnityError)


class ErrorRegistry:
    """Registry for mapping internal error codes to concrete exception classes."""

    _registry: dict[str, type[ContextUnityError]] = {}

    @classmethod
    def register(cls, code: str, error_class: type[ContextUnityError]) -> None:
        """Register an error code mapping to an exception class.

        Args:
            code: The stable string error code identifier.
            error_class: The exception class corresponding to the error code.
        """
        cls._registry[code] = error_class

    @classmethod
    def get(cls, code: str) -> type[ContextUnityError] | None:
        """Retrieve the exception class mapped to the given error code.

        Args:
            code: The string error code to look up.

        Returns:
            type[ContextUnityError] | None: The exception class, or None if the
                code is not registered.
        """
        return cls._registry.get(code)

    @classmethod
    def from_code(cls, code: str, message: str = "", **details: object) -> ContextUnityError:
        """Instantiate a ContextUnityError subclass using its registered error code.

        Args:
            code: The string error code identifying the target exception subclass.
            message: The human-readable message for the exception instance.
            **details: Additional keyword arguments stored in the exception's
                details dictionary.

        Returns:
            ContextUnityError: An instance of the mapped exception class. If the
                code is unregistered, defaults to a base ContextUnityError.
        """
        exc_class = cls._registry.get(code, ContextUnityError)
        return exc_class(message=message, code=code, **details)

    @classmethod
    def all_codes(cls) -> list[str]:
        """Get all registered error codes.

        Returns:
            list[str]: A list of all registered stable error code strings.
        """
        return list(cls._registry.keys())


# Singleton for convenience
error_registry = ErrorRegistry


class register_error:
    """Class decorator that registers an exception subclass under a stable code.

    Implements :class:`~contextunity.core.types.ErrorClassDecorator`.
    """

    _code: str

    def __init__(self, code: str) -> None:
        """Bind the stable error code used for registry lookup."""
        self._code = code

    def __call__(self, cls: type[_E]) -> type[_E]:
        """Register the decorated exception class with the ErrorRegistry."""
        ErrorRegistry.register(self._code, cls)
        return cls


# ---- Default Registrations --------------------------------------------------

ErrorRegistry.register("INTERNAL_ERROR", ContextUnityError)
ErrorRegistry.register("CONFIGURATION_ERROR", ConfigurationError)
ErrorRegistry.register("SHIELD_DECRYPTION_ERROR", ShieldDecryptionError)
ErrorRegistry.register("PROVIDER_ERROR", ProviderError)
ErrorRegistry.register("SECURITY_ERROR", SecurityError)
ErrorRegistry.register("TAMPER_DETECTED", TamperDetectedError)
ErrorRegistry.register("STORAGE_ERROR", StorageError)
ErrorRegistry.register("DB_CONNECTION_ERROR", DatabaseConnectionError)
ErrorRegistry.register("PLATFORM_SERVICE_ERROR", PlatformServiceError)
ErrorRegistry.register("REDIS_NOT_AVAILABLE", RedisNotAvailable)
ErrorRegistry.register("REDIS_CONNECTION_ERROR", RedisConnectionError)
ErrorRegistry.register("SERVICE_STARTUP_ERROR", ServiceStartupError)
