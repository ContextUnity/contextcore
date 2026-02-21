"""Shared configuration contract for ContextUnity services.

This module provides Pydantic-validated configuration models that unify
common settings across all context* services (LOG_LEVEL, REDIS_URL, etc.).

All services MUST use these models as base configuration and extend
them with service-specific settings. Direct os.environ/os.getenv usage
is FORBIDDEN for any setting defined here (see contextcore-rules.md #4).

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


class SigningBackendType(str, Enum):
    """Supported signing backends.

    - ED25519: Asymmetric local keys (ContextShield Pro)
    - KMS: Cloud KMS/HSM (ContextShield Enterprise)
    - HMAC: Symmetric shared secret (ContextUnity Basic - OpenSource)
    """

    ED25519 = "ed25519"
    KMS = "kms"
    HMAC = "hmac"


class SharedSecurityConfig(BaseModel):
    """Unified security configuration for ALL ContextUnity services.

    This replaces per-service SecurityConfig duplication.
    Services extend with service-specific security fields if needed.

    Security flow:
        Router (Mind)  → SIGNS tokens  (needs private key)
        Brain (Memory) → VERIFIES only (needs public key)
        Worker (Hands) → VERIFIES only (needs public key)

    Requires contextshield for Ed25519/KMS backends.
    Without contextshield, tokens are unsigned (dev mode).

    Environment variables:
        SECURITY_ENABLED             — enable/disable security enforcement
        SIGNING_BACKEND              — ed25519 | kms
        SIGNING_KEY_ID               — active kid for token signing
        SIGNING_ALLOWED_KIDS         — comma-separated allowlist for rotation
        SIGNING_PRIVATE_KEY_PATH     — Ed25519 private key (signer only)
        SIGNING_PUBLIC_KEY_PATH      — Ed25519 public key (verifier)
        KMS_KEY_RESOURCE             — Cloud KMS key resource name
        TOKEN_TTL_SECONDS            — default token TTL
        TOKEN_ISSUER                 — issuer identifier
    """

    model_config = {"extra": "ignore"}

    enabled: bool = Field(
        default=False,
        description="Enable security enforcement. Disabled = all access allowed.",
    )

    # Signing backend selection
    signing_backend: SigningBackendType = Field(
        default=SigningBackendType.ED25519,
        description="Signing backend type: ed25519 (production), kms (enterprise)",
    )
    signing_key_id: str = Field(
        default="ed25519-001",
        description="Active key identifier (kid) for token signing",
    )
    signing_allowed_kids: list[str] = Field(
        default_factory=list,
        description=("Allowed kid values for verification (rotation support). Empty = accept any kid."),
    )

    # Key material references (NOT raw key values!)
    private_key_path: str = Field(
        default="",
        description="Ed25519 private key file path (signer only)",
    )
    public_key_path: str = Field(
        default="",
        description="Ed25519 public key file path (Phase 1, verifier)",
    )
    kms_key_resource: str = Field(
        default="",
        description="Cloud KMS key resource name",
    )
    shared_secret: str = Field(
        default="",
        description="Symmetric shared secret for HMAC backend (open source mode)",
    )

    # Token defaults
    token_ttl_seconds: int = Field(
        default=3600,
        description="Default token TTL in seconds (1 hour)",
    )
    token_issuer: str = Field(
        default="",
        description="Token issuer identifier (e.g. 'contextrouter')",
    )

    # Access policies (defaults, services can override)
    read_permission: str = Field(
        default="data:read",
        description="Default read permission string",
    )
    write_permission: str = Field(
        default="data:write",
        description="Default write permission string",
    )


class SharedConfig(BaseModel):
    """Shared configuration contract for all ContextUnity services.

    This model unifies common settings that are used across multiple services.
    Services should extend this model with their own specific settings.

    RULE: All settings MUST come through this config chain.
    Direct os.environ/os.getenv is FORBIDDEN (contextcore-rules.md #4).
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
    - TENANT_ID: Default tenant ID
    - SECURITY_ENABLED: Enable security enforcement
    - SIGNING_BACKEND: ed25519 | kms
    - SIGNING_KEY_ID: Active key identifier
    - SIGNING_ALLOWED_KIDS: Comma-separated kid allowlist
    - SIGNING_PRIVATE_KEY_PATH: Ed25519 private key path (signer only)
    - SIGNING_PUBLIC_KEY_PATH: Ed25519 public key path
    - KMS_KEY_RESOURCE: Cloud KMS key resource
    - TOKEN_TTL_SECONDS: Default token TTL
    - TOKEN_ISSUER: Token issuer

    Returns:
        SharedConfig instance with values from environment or defaults.
    """
    import os

    # Parse allowed kids list
    allowed_kids_raw = os.getenv("SIGNING_ALLOWED_KIDS", "")
    allowed_kids = [k.strip() for k in allowed_kids_raw.split(",") if k.strip()]

    security = SharedSecurityConfig(
        enabled=os.getenv("SECURITY_ENABLED", "false").lower() in ("true", "1", "yes"),
        signing_backend=os.getenv("SIGNING_BACKEND", "ed25519"),
        signing_key_id=os.getenv("SIGNING_KEY_ID", "ed25519-001"),
        signing_allowed_kids=allowed_kids,
        private_key_path=os.getenv("SIGNING_PRIVATE_KEY_PATH", ""),
        public_key_path=os.getenv("SIGNING_PUBLIC_KEY_PATH", ""),
        kms_key_resource=os.getenv("KMS_KEY_RESOURCE", ""),
        shared_secret=os.getenv("SIGNING_SHARED_SECRET", ""),
        token_ttl_seconds=int(os.getenv("TOKEN_TTL_SECONDS", "3600")),
        token_issuer=os.getenv("TOKEN_ISSUER", ""),
    )

    return SharedConfig(
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        log_json=os.getenv("LOG_JSON", "false").lower() in ("true", "1", "yes"),
        redis_url=os.getenv("REDIS_URL"),
        otel_enabled=os.getenv("OTEL_ENABLED", "false").lower() in ("true", "1", "yes", "on"),
        otel_endpoint=os.getenv("OTEL_ENDPOINT"),
        service_name=os.getenv("SERVICE_NAME"),
        service_version=os.getenv("SERVICE_VERSION"),
        tenant_id=os.getenv("TENANT_ID"),
        security=security,
    )


__all__ = [
    "SharedConfig",
    "SharedSecurityConfig",
    "SigningBackendType",
    "LogLevel",
    "load_shared_config_from_env",
]
