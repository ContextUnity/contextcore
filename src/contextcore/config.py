"""Shared configuration contract for ContextUnity services.

This module provides Pydantic-validated configuration models that unify
common settings across all context* services (LOG_LEVEL, REDIS_URL, etc.).

All services should use these models as base configuration and extend
them with service-specific settings.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class LogLevel(str, Enum):
    """Standard log levels for all services."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class SharedConfig(BaseModel):
    """Shared configuration contract for all ContextUnity services.

    This model unifies common settings that are used across multiple services.
    Services should extend this model with their own specific settings.
    """

    # Logging
    log_level: LogLevel = Field(
        default=LogLevel.INFO,
        description="Logging level for the service",
    )

    # Redis (for shared memory, caching, etc.)
    redis_url: Optional[str] = Field(
        default=None,
        description="Redis connection URL (e.g., redis://localhost:6379/0)",
    )

    # Observability
    otel_enabled: bool = Field(
        default=False,
        description="Enable OpenTelemetry tracing",
    )
    otel_endpoint: Optional[str] = Field(
        default=None,
        description="OpenTelemetry collector endpoint",
    )

    # Service identification
    service_name: Optional[str] = Field(
        default=None,
        description="Service name for observability (e.g., 'contextbrain', 'contextrouter')",
    )
    service_version: Optional[str] = Field(
        default=None,
        description="Service version for observability",
    )

    # Tenant isolation
    tenant_id: Optional[str] = Field(
        default=None,
        description="Default tenant ID for multi-tenant deployments",
    )

    @field_validator("redis_url")
    @classmethod
    def validate_redis_url(cls, v: Optional[str]) -> Optional[str]:
        """Validate Redis URL format."""
        if v is None:
            return v
        if not v.startswith(("redis://", "rediss://", "unix://")):
            raise ValueError(
                "Redis URL must start with redis://, rediss://, or unix://"
            )
        return v

    @field_validator("log_level", mode="before")
    @classmethod
    def validate_log_level(cls, v: str | LogLevel) -> LogLevel:
        """Convert string to LogLevel enum."""
        if isinstance(v, LogLevel):
            return v
        if isinstance(v, str):
            try:
                return LogLevel[v.upper()]
            except KeyError:
                raise ValueError(
                    f"Invalid log level: {v}. Must be one of {[e.value for e in LogLevel]}"
                )
        raise ValueError(f"Log level must be string or LogLevel enum, got {type(v)}")

    model_config = {
        "use_enum_values": True,
        "extra": "forbid",  # Prevent accidental extra fields
    }


def load_shared_config_from_env() -> SharedConfig:
    """Load shared configuration from environment variables.

    Environment variables:
    - LOG_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    - REDIS_URL: Redis connection URL
    - OTEL_ENABLED: Enable OpenTelemetry (true/false)
    - OTEL_ENDPOINT: OpenTelemetry collector endpoint
    - SERVICE_NAME: Service name for observability
    - SERVICE_VERSION: Service version
    - TENANT_ID: Default tenant ID

    Returns:
        SharedConfig instance with values from environment or defaults.
    """
    import os

    return SharedConfig(
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        redis_url=os.getenv("REDIS_URL"),
        otel_enabled=os.getenv("OTEL_ENABLED", "false").lower()
        in ("true", "1", "yes", "on"),
        otel_endpoint=os.getenv("OTEL_ENDPOINT"),
        service_name=os.getenv("SERVICE_NAME"),
        service_version=os.getenv("SERVICE_VERSION"),
        tenant_id=os.getenv("TENANT_ID"),
    )


__all__ = ["SharedConfig", "LogLevel", "load_shared_config_from_env"]
