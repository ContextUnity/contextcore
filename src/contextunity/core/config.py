"""Shared configuration contract for ContextUnity services.

This module provides Pydantic-validated configuration models that unify
common settings across all context* services (LOG_LEVEL, REDIS_URL, etc.).

All services MUST use these models as base configuration and extend
them with service-specific settings. Direct os.environ/os.getenv usage
is FORBIDDEN for any setting defined here.

Security configuration is unified via SharedSecurityConfig —
services should NOT duplicate SecurityConfig locally.
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


class SharedSecurityConfig(BaseModel):
    """Unified security configuration for ALL ContextUnity services.

    This replaces per-service SecurityConfig duplication.
    Services extend with service-specific security fields if needed.

    Security flow:
        Open Source   → HmacBackend (CU_PROJECT_SECRET, stdlib only)
        Enterprise    → SessionTokenBackend (Shield-signed, Ed25519)

    Token signing is ALWAYS active. HmacBackend is the default.
    Ed25519/KMS backends require contextunity.shield.
    """

    model_config = {"extra": "ignore"}

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
        description="Key used to encrypt project keys in Redis encrypt-then-MAC",
    )
    project_secret: str = Field(
        default="",
        description="Project HMAC secret for open-source token signing",
    )
    shield_master_key: str = Field(
        default="",
        description="Shield master key for admin CLI operations (encrypt/decrypt shield.db, mint admin tokens)",
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

    service_name: Optional[str] = Field(
        default=None,
        description="Service name for observability (e.g., 'contextunity.brain', 'contextunity.router')",
    )
    service_version: Optional[str] = Field(
        default=None,
        description="Service version for observability",
    )
    cu_platform: Optional[str] = Field(
        default=None,
        description="ContextUnity platform identifier",
    )
    langfuse_enabled: bool = Field(
        default=False,
        description="Enable Langfuse OpenTelemetry tracing",
    )
    langfuse_project_id: Optional[str] = Field(
        default=None,
        description="Langfuse project ID",
    )
    langfuse_host: Optional[str] = Field(
        default="https://cloud.langfuse.com",
        description="Langfuse host URL",
    )

    # TLS configurations
    tls_enabled: bool = Field(
        default=False,
        description="Enable TLS for gRPC channels",
    )
    tls_ca_cert: Optional[str] = Field(
        default=None,
    )
    tls_client_cert: Optional[str] = Field(
        default=None,
    )
    tls_client_key: Optional[str] = Field(
        default=None,
    )
    tls_server_cert: Optional[str] = Field(
        default=None,
    )
    tls_server_key: Optional[str] = Field(
        default=None,
    )
    tls_require_client_auth: bool = Field(
        default=True,
    )

    # Service discovery (Redis registration)
    grpc_host: str = Field(
        default="localhost",
        description="Advertised gRPC host for service discovery (e.g., 'localhost', '0.0.0.0', 'brain.prod.local')",
    )

    # Service endpoints (resolved via env → Redis discovery → defaults)
    router_url: str = Field(
        default="localhost:50051",
        description="contextunity.router gRPC endpoint",
    )
    brain_url: str = Field(
        default="localhost:50051",
        description="contextunity.brain gRPC endpoint",
    )
    shield_url: str = Field(
        default="localhost:50054",
        description="contextunity.shield gRPC endpoint",
    )
    worker_url: str = Field(
        default="localhost:50052",
        description="contextunity.worker gRPC endpoint",
    )
    brain_mode: str = Field(
        default="grpc",
        description="contextunity.brain execution mode",
    )
    worker_mode: str = Field(
        default="grpc",
        description="contextunity.worker execution mode",
    )
    temporal_host: str = Field(
        default="localhost:7233",
        description="Temporal server endpoint",
    )

    # Bootstrap / Environment state
    manifest_path: str = Field(
        default="",
        description="Path to contextunity.project.yaml",
    )

    # Security — unified config, replaces per-service SecurityConfig
    security: SharedSecurityConfig = Field(
        default_factory=SharedSecurityConfig,
        description="Unified security configuration",
    )

    @field_validator("redis_url")
    @classmethod
    def validate_redis_url(cls, v: Optional[str]) -> Optional[str]:
        """Validate Redis URL format."""
        if v is None:
            return v
        if not v.startswith(("redis://", "rediss://", "unix://")):
            raise ValueError("Redis URL must start with redis://, rediss://, or unix://")
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
                raise ValueError(f"Invalid log level: {v}. Must be one of {[e.value for e in LogLevel]}")
        raise ValueError(f"Log level must be string or LogLevel enum, got {type(v)}")

    model_config = {
        "use_enum_values": True,
        "extra": "forbid",  # Prevent accidental extra fields
    }


def _read_credential(cred_name: str, fallback_value: str | None = None) -> str:
    """Read secret from systemd LoadCredential path, fallback to env."""
    import os

    # Guard against path traversal (cred_name must be a simple filename)
    if os.sep in cred_name or cred_name.startswith("."):
        return fallback_value or ""

    cred_path = os.environ.get("CREDENTIALS_DIRECTORY")
    if cred_path:
        full_path = os.path.join(cred_path, cred_name)
        if os.path.exists(full_path):
            with open(full_path) as f:
                return f.read().strip()
    return fallback_value or ""


def load_shared_config_from_env() -> SharedConfig:
    """Load shared configuration from environment variables.

    This is the ONLY place where os.getenv is allowed for shared settings.
    All other code MUST use the config object.

    Environment variables:
    - LOG_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    - LOG_JSON: Use JSON log format (true/false, default: false)
    - REDIS_URL: Redis connection URL
    - OTEL_ENABLED: Enable OpenTelemetry (true/false)
    - OTEL_ENDPOINT: OpenTelemetry collector endpoint
    - SERVICE_NAME: Service name for observability
    - SERVICE_VERSION: Service version
    - GRPC_REUSE_PORT: Enable SO_REUSEPORT (true/false)

    Returns:
        SharedConfig instance with values from environment or defaults.
    """
    import os

    # Security defaults (systemd-creds first, then env)
    security = SharedSecurityConfig(
        redis_secret_key=_read_credential("redis_secret_key", os.getenv("REDIS_SECRET_KEY", "")),
        project_secret=_read_credential("cu_project_secret", os.getenv("CU_PROJECT_SECRET", "")),
        shield_master_key=_read_credential("shield_master_key", os.getenv("SHIELD_MASTER_KEY", "")),
    )

    return SharedConfig(
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        log_json=os.getenv("LOG_JSON", "false").lower() in ("true", "1", "yes"),
        grpc_reuse_port=os.getenv("GRPC_REUSE_PORT", "false").lower() in ("true", "1", "yes", "on"),
        redis_url=os.getenv("REDIS_URL"),
        otel_enabled=os.getenv("OTEL_ENABLED", "false").lower() in ("true", "1", "yes", "on"),
        otel_endpoint=os.getenv("OTEL_ENDPOINT"),
        service_name=os.getenv("SERVICE_NAME"),
        service_version=os.getenv("SERVICE_VERSION"),
        cu_platform=os.getenv("CU_PLATFORM"),
        langfuse_enabled=os.getenv("LANGFUSE_ENABLED", "false").lower() in ("true", "1", "yes", "on"),
        langfuse_project_id=os.getenv("LANGFUSE_PROJECT_ID"),
        langfuse_host=os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com"),
        tls_enabled=os.getenv("GRPC_TLS_ENABLED", "false").lower() in ("true", "1", "yes", "on"),
        tls_ca_cert=os.getenv("GRPC_TLS_CA_CERT"),
        tls_client_cert=os.getenv("GRPC_TLS_CLIENT_CERT"),
        tls_client_key=os.getenv("GRPC_TLS_CLIENT_KEY"),
        tls_server_cert=os.getenv("GRPC_TLS_SERVER_CERT"),
        tls_server_key=os.getenv("GRPC_TLS_SERVER_KEY"),
        tls_require_client_auth=os.getenv("GRPC_TLS_REQUIRE_CLIENT_AUTH", "true").lower() not in ("false", "0", "no"),
        grpc_host=os.getenv("GRPC_HOST", "localhost"),
        router_url=os.getenv("CU_ROUTER_GRPC_URL", "localhost:50051"),
        brain_url=os.getenv("CU_BRAIN_GRPC_URL", "localhost:50051"),
        shield_url=os.getenv("CU_SHIELD_GRPC_URL", "localhost:50054"),
        worker_url=os.getenv("CU_WORKER_GRPC_URL", "localhost:50052"),
        brain_mode=os.getenv("CU_BRAIN_MODE", "grpc"),
        worker_mode=os.getenv("CU_WORKER_MODE", "grpc"),
        temporal_host=os.getenv("TEMPORAL_HOST", "localhost:7233"),
        manifest_path=os.getenv("CU_MANIFEST_PATH", ""),
        security=security,
    )


# Singleton cached config
_core_config: SharedConfig | None = None


def get_core_config() -> SharedConfig:
    """Get or create the singleton SharedConfig.

    Loads from environment on first call, caches for subsequent calls.
    SDK clients (RouterClient, BrainClient) use this to resolve endpoints.
    """
    global _core_config
    if _core_config is None:
        _core_config = load_shared_config_from_env()
    return _core_config


__all__ = [
    "SharedConfig",
    "SharedSecurityConfig",
    "LogLevel",
    "load_shared_config_from_env",
    "get_core_config",
    "_read_credential",
]
