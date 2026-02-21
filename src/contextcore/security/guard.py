"""Security guard — configuration, guard result, and unified check entrypoint.

Provides:
- ``SecurityConfig`` — dataclass for security switches (token, shield, fail-open).
- ``GuardResult`` — result from security checks (allowed/blocked).
- ``SecurityGuard`` — unified guard that combines token validation and Shield firewall.
"""

from __future__ import annotations

import importlib.util
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

import grpc

from ..token_utils import extract_token_from_grpc_metadata
from ..tokens import ContextToken

logger = logging.getLogger(__name__)

# Auto-detect contextshield availability at module load
_SHIELD_AVAILABLE = importlib.util.find_spec("contextshield") is not None


# ── Configuration ────────────────────────────────────────────────


@dataclass
class SecurityConfig:
    """Security configuration for the integration layer.

    Attributes:
        security_enabled: Master switch — token validation on/off.
        shield_enabled: Shield firewall on/off (requires contextshield).
        fail_open: If True, allow requests when Shield errors occur (dev mode).
        log_allowed: Log allowed requests for debugging.
        skip_methods: gRPC methods that bypass all security checks (e.g. health).

    Environment variables (auto-read on init):
        SECURITY_ENABLED       — master switch (default: false)
        CONTEXTSHIELD_ENABLED  — shield firewall (default: true)
        CONTEXTSHIELD_FAIL_OPEN — allow on errors (default: false)
    """

    security_enabled: bool = field(default=False, repr=True)
    shield_enabled: bool = field(default=True, repr=True)
    fail_open: bool = field(default=False, repr=True)
    log_allowed: bool = False
    skip_methods: list[str] = field(default_factory=lambda: ["grpc.health.v1.Health"])

    def __post_init__(self) -> None:
        """Auto-read from env vars if fields are at their defaults.

        ⚠️ BOOTSTRAP EXCEPTION: os.environ is read directly here because
        SecurityConfig is a dataclass that may be instantiated before
        the DI container or SharedConfig is available.
        This is the ONLY permitted direct env read in contextcore security,
        alongside EnforcementMode.from_env() in interceptors.py.
        All other code must use load_shared_config_from_env() / SharedConfig.
        See: contextcore-rules.md #4
        """
        import os

        _TRUTHY = {"true", "1", "yes", "on"}

        env_sec = os.environ.get("SECURITY_ENABLED")
        if env_sec is not None:
            self.security_enabled = env_sec.lower() in _TRUTHY

        env_shield = os.environ.get("CONTEXTSHIELD_ENABLED")
        if env_shield is not None:
            self.shield_enabled = env_shield.lower() in _TRUTHY

        env_fail = os.environ.get("CONTEXTSHIELD_FAIL_OPEN")
        if env_fail is not None:
            self.fail_open = env_fail.lower() in _TRUTHY


# ── Guard Result ─────────────────────────────────────────────────


@dataclass
class GuardResult:
    """Result from security checks."""

    allowed: bool = True
    reason: str = ""
    shield_active: bool = False
    processing_ms: float = 0.0

    @property
    def blocked(self) -> bool:
        return not self.allowed


# ── Security Guard ───────────────────────────────────────────────


class SecurityGuard:
    """Unified security guard for all ContextUnity services.

    Provides:
    1. Token validation (from contextcore, always available)
    2. Shield firewall (from contextshield, auto-activated if installed)

    Graceful degradation:
        - No contextshield → token-only validation, no firewall
        - contextshield installed → full firewall + token validation
        - security_enabled=False → no checks at all (dev mode)
    """

    def __init__(self, config: SecurityConfig | None = None) -> None:
        self._config = config or SecurityConfig()
        self._shield_middleware = None

        # Auto-activate Shield if installed and enabled
        if self._config.shield_enabled and _SHIELD_AVAILABLE:
            self._init_shield()

    def _init_shield(self) -> None:
        """Try to initialize Shield middleware (graceful)."""
        try:
            from contextshield.middleware import (  # type: ignore[import-not-found]
                MiddlewareConfig,
                ShieldMiddleware,
            )

            shield_config = MiddlewareConfig(
                shield_enabled=True,
                fail_open=self._config.fail_open,
                log_allowed=self._config.log_allowed,
            )
            self._shield_middleware = ShieldMiddleware(config=shield_config)
            logger.info(
                "ContextShield firewall activated (address=in-process(local_memory), port=none, fail_open=%s)",
                self._config.fail_open,
            )
        except Exception as e:
            logger.warning("Failed to initialize Shield middleware: %s", e)
            self._shield_middleware = None

    @property
    def shield_active(self) -> bool:
        """Whether Shield firewall is active."""
        return self._shield_middleware is not None

    def validate_token(
        self,
        context: grpc.ServicerContext,
        *,
        require: bool = True,
    ) -> Optional[ContextToken]:
        """Extract and validate ContextToken from gRPC metadata.

        Args:
            context: gRPC servicer context.
            require: If True, abort with UNAUTHENTICATED when token missing.

        Returns:
            ContextToken or None (if not required and missing).
        """
        if not self._config.security_enabled:
            return None  # Security disabled, no validation

        token = extract_token_from_grpc_metadata(context)

        if token is None:
            if require:
                context.abort(
                    grpc.StatusCode.UNAUTHENTICATED,
                    "Missing ContextToken",
                )
            return None

        if token.is_expired():
            context.abort(
                grpc.StatusCode.UNAUTHENTICATED,
                "ContextToken expired",
            )
            return None

        return token

    async def check_input(
        self,
        user_input: str,
        *,
        context_text: str = "",
        rag_chunks: list[dict] | None = None,
        request_id: str = "",
        tenant: str = "",
    ) -> GuardResult:
        """Run Shield firewall on user input (if available).

        When contextshield is not installed, always returns allowed.

        Args:
            user_input: The user's message to check.
            context_text: System/conversation context.
            rag_chunks: RAG chunks for validation.
            request_id: Request ID for logging.
            tenant: Tenant identifier.

        Returns:
            GuardResult with allow/block decision.
        """
        start = time.monotonic()
        result = GuardResult(shield_active=self.shield_active)

        if not self.shield_active:
            result.processing_ms = (time.monotonic() - start) * 1000
            return result

        try:
            middleware_result = await self._shield_middleware.pre_llm_guard(
                user_input,
                context=context_text,
                rag_chunks=rag_chunks,
                request_id=request_id,
                tenant=tenant,
            )
            result.allowed = middleware_result.allowed
            result.reason = middleware_result.reason
            result.processing_ms = middleware_result.processing_ms
        except Exception as e:
            logger.error("Shield check failed: %s", e)
            if not self._config.fail_open:
                result.allowed = False
                result.reason = f"Shield error: {e}"
            result.processing_ms = (time.monotonic() - start) * 1000

        return result


__all__ = [
    "GuardResult",
    "SecurityConfig",
    "SecurityGuard",
    "_SHIELD_AVAILABLE",
]
