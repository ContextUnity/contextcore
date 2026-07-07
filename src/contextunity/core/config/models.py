"""Configuration models — Pydantic schemas for ContextUnity config.
Contains:
- LogLevel enum
- SharedSecurityConfig — secrets container (Tier 1)
- SharedConfig — platform-wide config (SDK consumers)
- ServiceConfig — base for service-specific configs (extra = "ignore")
"""

from __future__ import annotations

from enum import Enum
from typing import ClassVar, override

from pydantic import BaseModel, ConfigDict, Field, field_validator


class LogLevel(str, Enum):
    """Standard log levels for all services."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class RedisConfig(BaseModel):
    """Redis connection and connectivity configuration.

    Transport encryption is determined by the URL scheme: ``rediss://`` = TLS.
    Redis is used for service discovery, ephemeral registration state, caching,
    and session coordination. Project key material (HMAC/session secrets) is
    resolved from env or Shield and is no longer stored in Redis.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore")

    enabled: bool = Field(
        default=True,
        description="Enable Redis connectivity (discovery, caching, session state)",
    )
    url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL (use rediss:// for TLS)",
    )

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        """Validate that the Redis connection URL uses an allowed scheme.

        Args:
            v: The Redis URL string to validate.

        Returns:
            str: The validated URL string.

        Raises:
            ValueError: If the scheme is not one of 'redis://', 'rediss://', or 'unix://'.
        """
        if not v:
            return v
        if not v.startswith(("redis://", "rediss://", "unix://")):
            raise ValueError("Redis host must start with redis://, rediss://, or unix://")
        return v


class SharedSecurityConfig(BaseModel):
    """Security configuration for all ContextUnity services.

    Services extend with service-specific security fields if needed.

    Token signing is ALWAYS active::

        Open Source  → HmacBackend (CU_PROJECT_SECRET, stdlib only)
        Enterprise   → SessionTokenBackend (Shield-signed, Ed25519)
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore")

    # Access policies (defaults, services can override)
    read_permission: str = Field(
        default="data:read",
        description="Default read permission string",
    )
    write_permission: str = Field(
        default="data:write",
        description="Default write permission string",
    )
    redis_secret_key: str = Field(
        default="",
        description="Deprecated. Redis no longer stores project key material.",
    )
    project_secret: str = Field(
        default="",
        description="Project HMAC secret for open-source token signing",
    )


class SharedConfig(BaseModel):
    """Shared configuration contract for all ContextUnity services.

    This model unifies common settings that are used across multiple services.
    Services should extend this model with their own specific settings.

    RULE: All settings MUST come through this config chain.
    Direct os.environ/os.getenv is FORBIDDEN.
    """

    # Logging
    log_level: LogLevel = Field(
        default=LogLevel.INFO,
        description="Logging level for the service",
    )
    log_json: bool = Field(
        default=False,
        description="Use JSON log format (default: plain text)",
    )

    # gRPC options
    grpc_reuse_port: bool = Field(
        default=False,
        description="Enable SO_REUSEPORT for gRPC server (default False for dev, True for prod)",
    )

    # Redis (for shared memory, caching, service discovery)
    redis: RedisConfig = Field(
        default_factory=RedisConfig,
        description="Redis connection configuration",
    )

    # Observability
    service_name: str | None = Field(
        default=None,
        description="Service name for observability (e.g., 'contextunity.brain', 'contextunity.router')",
    )
    service_version: str | None = Field(
        default=None,
        description="Service version for observability",
    )
    cu_platform: str | None = Field(
        default=None,
        description="ContextUnity platform identifier",
    )

    # TLS configurations
    tls_enabled: bool = Field(default=False, description="Enable TLS for gRPC channels")
    tls_ca_cert: str | None = Field(default=None)
    tls_client_cert: str | None = Field(default=None)
    tls_client_key: str | None = Field(default=None)
    tls_server_cert: str | None = Field(default=None)
    tls_server_key: str | None = Field(default=None)
    tls_require_client_auth: bool = Field(default=True)

    # Service discovery endpoints (client-side).
    # Override via CU_*_GRPC_URL env vars for remote deployments.
    router_url: str = Field(default="localhost:50050", description="contextunity.router gRPC endpoint")
    brain_url: str = Field(default="localhost:50051", description="contextunity.brain gRPC endpoint")
    worker_url: str = Field(default="localhost:50052", description="contextunity.worker gRPC endpoint")
    shield_url: str = Field(default="localhost:50054", description="contextunity.shield gRPC endpoint")
    temporal_host: str = Field(default="localhost:7233", description="Temporal server endpoint")

    # Bootstrap / Environment state
    local_mode: bool = Field(default=False, description="Local development mode (SQLite, no external deps)")
    dev_mode: bool = Field(
        default=False,
        description="Developer mode: hot-reload (CLI) and Forge auto-session when CU_PROJECT_SECRET is set",
    )
    manifest_path: str = Field(default="", description="Path to contextunity.project.yaml")
    enable_passbyref: bool = Field(
        default=False,
        description=(
            "Feature flag: convert large wrapped-mode platform tool results "
            "into a Blackboard PassByRef envelope. Off by default; inline "
            "payloads are unchanged when this is False."
        ),
    )
    passbyref_ttl_seconds: int = Field(
        default=900,
        ge=0,
        description=(
            "TTL for Router-created PassByRef Blackboard records. Set 0 to write non-expiring references explicitly."
        ),
    )
    passbyref_threshold_bytes: int = Field(
        default=1024,
        ge=1,
        description=(
            "Serialized-payload size above which a wrapped-mode platform tool "
            "result is converted to a PassByRef envelope (default 1024, "
            "configurable). Mirrors "
            "contextunity.core.passbyref.DEFAULT_PASSBYREF_THRESHOLD_BYTES."
        ),
    )
    blackboard_prune_interval_seconds: float = Field(
        default=300.0,
        ge=0,
        description=(
            "In-process Blackboard TTL prune interval for local/in-process Brain. Set 0 to disable the local janitor."
        ),
    )

    # Security — unified config, replaces per-service SecurityConfig
    security: SharedSecurityConfig = Field(
        default_factory=SharedSecurityConfig,
        description="Unified security configuration",
    )

    @field_validator("log_level", mode="before")
    @classmethod
    def validate_log_level(cls, v: object) -> LogLevel:
        """Convert a string representation of a log level to the LogLevel enum.

        Args:
            v: The input log level as a string or LogLevel enum.

        Returns:
            LogLevel: The corresponding LogLevel enum member.

        Raises:
            ValueError: If the string does not match any valid log level or the input type is incorrect.
        """
        if isinstance(v, LogLevel):
            return v
        if not isinstance(v, str):
            raise ValueError(f"Log level must be string or LogLevel enum, got {type(v)}")
        try:
            return LogLevel[v.upper()]
        except KeyError:
            raise ValueError(f"Invalid log level: {v}. Must be one of {[e.value for e in LogLevel]}") from None

    @override
    def model_post_init(self, __context: object) -> None:
        """Enforce configuration constraints after model initialization.

        Clears the Redis URL if Redis connectivity is disabled.

        Args:
            __context: The Pydantic validation context.
        """
        if not self.redis.enabled:
            self.redis.url = ""

    model_config: ClassVar[ConfigDict] = ConfigDict(use_enum_values=True, extra="forbid")


class ServiceConfig(SharedConfig):
    """Base configuration for ContextUnity services.

    Extends SharedConfig with ``extra = "ignore"`` so services can
    freely add their own fields via subclassing.

    All services (Shield, Worker, Workshop, etc.) SHOULD inherit
    from this class rather than from SharedConfig directly.
    """

    # gRPC server bind settings — each service overrides port default.
    host: str = Field(default="0.0.0.0", description="gRPC server bind address")
    port: int = Field(default=0, description="gRPC listen port (override per service)")

    model_config: ClassVar[ConfigDict] = ConfigDict(use_enum_values=True, extra="ignore")
