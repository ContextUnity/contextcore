"""Unified security integration for ContextUnity services.

This package provides a single integration point that services use for:
1. **Token validation** (always available via contextcore)
2. **Shield firewall** (auto-activates when contextshield is installed)
3. **gRPC interceptors** (unified, parameterised permission enforcement)

Usage (in any service)::

    from contextcore.security import get_security_interceptors

    server = grpc.aio.server(interceptors=get_security_interceptors())

    # Or use the guard directly in a handler:
    from contextcore.security import get_security_guard

    async def MyMethod(self, request, context):
        token = security_guard.validate_token(context)
        result = await security_guard.check_input(user_input)
        if result.blocked:
            context.abort(grpc.StatusCode.PERMISSION_DENIED, result.reason)

Configuration (env vars)::

    CONTEXT_SECURITY_ENABLED=true       # Master switch (default: false)
    CONTEXTSHIELD_ENABLED=true          # Shield firewall (default: true if installed)
    CONTEXTSHIELD_FAIL_OPEN=false       # Allow on Shield errors (default: false)
"""

from __future__ import annotations

from typing import Any

import grpc

from .guard import (
    _SHIELD_AVAILABLE,
    GuardResult,
    SecurityConfig,
    SecurityGuard,
)
from .interceptors import (
    EnforcementMode,
    ServicePermissionInterceptor,
    TokenValidationInterceptor,
    _extract_rpc_name,
    _should_skip,
    check_permission,
)

# ── Singleton factory ────────────────────────────────────────────

_guard: SecurityGuard | None = None


def get_security_guard(config: SecurityConfig | None = None) -> SecurityGuard:
    """Get or create the singleton SecurityGuard.

    Args:
        config: Security configuration (used only on first call).

    Returns:
        SecurityGuard instance.
    """
    global _guard
    if _guard is None:
        _guard = SecurityGuard(config)
    return _guard


def reset_security_guard() -> None:
    """Reset the singleton (for testing)."""
    global _guard
    _guard = None


def get_security_interceptors(
    config: SecurityConfig | None = None,
) -> list[grpc.aio.ServerInterceptor]:
    """Get gRPC server interceptors for security.

    Returns a list of interceptors to pass to ``grpc.aio.server()``.
    Currently returns ``TokenValidationInterceptor``.

    Args:
        config: Security configuration.

    Returns:
        List of gRPC interceptors.

    Usage::

        server = grpc.aio.server(interceptors=get_security_interceptors())
    """
    cfg = config or SecurityConfig()
    interceptors: list[grpc.aio.ServerInterceptor] = []

    if cfg.security_enabled:
        interceptors.append(TokenValidationInterceptor(cfg))

    return interceptors


def shield_status() -> dict[str, Any]:
    """Get current Shield integration status.

    Returns:
        Dict with shield_installed, shield_active, security_enabled.
    """
    guard = get_security_guard()
    return {
        "shield_installed": _SHIELD_AVAILABLE,
        "shield_active": guard.shield_active,
        "security_enabled": guard._config.security_enabled,
        "fail_open": guard._config.fail_open,
    }


__all__ = [
    # Config
    "SecurityConfig",
    # Guard
    "GuardResult",
    "SecurityGuard",
    "get_security_guard",
    "reset_security_guard",
    # Permission check
    "check_permission",
    # Interceptors
    "EnforcementMode",
    "ServicePermissionInterceptor",
    "TokenValidationInterceptor",
    "_extract_rpc_name",
    "_should_skip",
    "get_security_interceptors",
    # Status
    "shield_status",
]
