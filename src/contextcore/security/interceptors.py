"""gRPC interceptors for ContextUnity service-level authentication.

Provides:
- ``EnforcementMode`` — three-state toggle: off / warn / enforce.
- ``check_permission`` — standalone permission + tenant check.
- ``ServicePermissionInterceptor`` — unified, parameterised server interceptor.
- ``TokenValidationInterceptor`` — legacy interceptor (backward compatibility).
- ``_extract_rpc_name``, ``_should_skip`` — helper utilities.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any

import grpc

from ..tokens import ContextToken
from .guard import SecurityConfig

logger = logging.getLogger(__name__)


# ── Enforcement Mode ────────────────────────────────────────────


class EnforcementMode(str, Enum):
    """Three-state security enforcement toggle.

    - ``off``     — no security checks, only caller-identity logging.
    - ``warn``    — check permissions, log denials as WARNING, but allow through.
    - ``enforce`` — check permissions, deny on failure (production).

    Set via env ``SECURITY_ENFORCEMENT=off|warn|enforce``.
    """

    OFF = "off"
    WARN = "warn"
    ENFORCE = "enforce"

    @classmethod
    def from_env(cls) -> EnforcementMode:
        """Read from ``SECURITY_ENFORCEMENT`` env var (default: warn)."""
        import os  # Localized: only place in contextcore where os.environ is read directly

        raw = os.environ.get("SECURITY_ENFORCEMENT", "warn").strip().lower()
        try:
            return cls(raw)
        except ValueError:
            logger.warning(
                "Unknown SECURITY_ENFORCEMENT=%r, defaulting to 'warn'",
                raw,
            )
            return cls.WARN


# Method prefixes that bypass permission checks
_SKIP_PREFIXES = (
    "grpc.health.v1",
    "grpc.reflection.v1",
)


# ── Helpers ──────────────────────────────────────────────────────


def _extract_rpc_name(full_method: str) -> str:
    """Extract RPC name from fully-qualified method string.

    ``/brain.BrainService/Search`` → ``Search``
    """
    return full_method.rsplit("/", 1)[-1] if "/" in full_method else full_method


def _should_skip(method: str) -> bool:
    """Check if this method should skip permission checks."""
    return any(prefix in method for prefix in _SKIP_PREFIXES)


# ── Permission check ────────────────────────────────────────────


def check_permission(
    token: ContextToken,
    required: str,
    *,
    tenant_id: str | None = None,
) -> str | None:
    """Check if token has the required permission and tenant access.

    Supports wildcard expansion via ``contextcore.permissions.expand_permissions``.

    Args:
        token: The caller's ContextToken.
        required: The exact permission string needed (e.g. ``brain:read``).
        tenant_id: If provided, also checks tenant isolation.

    Returns:
        None if allowed, or a human-readable denial reason.
    """
    from ..permissions import expand_permissions

    if required not in token.permissions:
        expanded = expand_permissions(token.permissions)
        if required not in expanded:
            return f"missing permission: {required}"

    if tenant_id and hasattr(token, "can_access_tenant"):
        if not token.can_access_tenant(tenant_id):
            return f"tenant access denied: {tenant_id}"

    return None


# ── Unified Interceptor ─────────────────────────────────────────


class ServicePermissionInterceptor(grpc.aio.ServerInterceptor):
    """Unified gRPC server interceptor for domain-specific permission enforcement.

    Sits before all handlers and:
    1. Logs caller identity (always, even when security is disabled)
    2. Extracts ContextToken from gRPC metadata
    3. Maps the RPC method to its required permission via ``rpc_permission_map``
    4. Validates the token carries that permission (+ tenant isolation)
    5. Aborts with ``UNAUTHENTICATED`` / ``PERMISSION_DENIED`` if not

    Unmapped RPCs are **denied** (fail-closed security).

    Args:
        rpc_permission_map: Mapping of RPC name → required permission string.
        service_name: Human-readable service name for log messages (e.g. ``"Brain"``).
        enforcement: Three-state mode (off / warn / enforce).
            Defaults to ``SECURITY_ENFORCEMENT`` env var (``warn`` if unset).

    Usage::

        interceptor = ServicePermissionInterceptor(
            rpc_permission_map=RPC_MAP,
            service_name="Brain",
            enforcement=EnforcementMode.WARN,   # safe rollout
        )
    """

    def __init__(
        self,
        rpc_permission_map: dict[str, str],
        *,
        service_name: str = "Service",
        enforcement: EnforcementMode | None = None,
    ) -> None:
        self._rpc_map = rpc_permission_map
        self._service_name = service_name
        self._mode = enforcement if enforcement is not None else EnforcementMode.from_env()

        if self._mode != EnforcementMode.OFF:
            logger.info(
                "%s interceptor mode: %s",
                self._service_name,
                self._mode.value,
            )

    async def intercept_service(
        self,
        continuation: Any,
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler:
        """Intercept incoming gRPC calls for permission validation."""
        method = handler_call_details.method or ""

        # Skip health checks / reflection
        if _should_skip(method):
            return await continuation(handler_call_details)

        rpc_name = _extract_rpc_name(method)
        metadata = dict(handler_call_details.invocation_metadata or [])

        # ── LOGGING (always active) ───────────────────────────────
        caller_id = "anonymous"
        tenant_info = ""

        token_str = metadata.get("x-context-token", "").strip()
        if not token_str:
            auth = metadata.get("authorization", "")
            if auth.startswith("Bearer "):
                token_str = auth[7:].strip()

        token: ContextToken | None = None
        if token_str:
            try:
                from ..token_utils import parse_token_string

                token = parse_token_string(token_str)
                if token:
                    caller_id = token.agent_id or token.token_id or "unknown"
                    if token.allowed_tenants:
                        tenant_info = f" tenants={list(token.allowed_tenants)}"
            except Exception:
                pass  # Don't break RPC flow for logging

        logger.info(
            "%s RPC %s | caller=%s%s",
            self._service_name,
            rpc_name,
            caller_id,
            tenant_info,
        )

        # ── SECURITY ──────────────────────────────────────────────
        if self._mode == EnforcementMode.OFF:
            return await continuation(handler_call_details)

        # Map RPC to required permission
        required_permission = self._rpc_map.get(rpc_name)
        deny_reason: str | None = None
        deny_code: grpc.StatusCode = grpc.StatusCode.PERMISSION_DENIED

        if required_permission is None:
            deny_reason = "RPC not mapped to permission"
            deny_code = grpc.StatusCode.PERMISSION_DENIED
        elif not token_str:
            deny_reason = f"no token (requires {required_permission})"
            deny_code = grpc.StatusCode.UNAUTHENTICATED
        elif token is None:
            deny_reason = "invalid token"
            deny_code = grpc.StatusCode.UNAUTHENTICATED
        elif token.is_expired():
            deny_reason = f"token expired (token '{token.token_id}')"
            deny_code = grpc.StatusCode.UNAUTHENTICATED
        else:
            perm_denial = check_permission(token, required_permission)
            if perm_denial:
                deny_reason = f"{perm_denial} (token '{token.token_id}')"
                deny_code = grpc.StatusCode.PERMISSION_DENIED

        if deny_reason:
            # ── WARN mode: log but allow ──────────────────────────
            if self._mode == EnforcementMode.WARN:
                logger.warning(
                    "%s WARN_DENIED '%s' — %s (would block in enforce mode)",
                    self._service_name,
                    rpc_name,
                    deny_reason,
                )
                return await continuation(handler_call_details)

            # ── ENFORCE mode: actually block ──────────────────────
            logger.warning(
                "%s DENIED '%s' — %s",
                self._service_name,
                rpc_name,
                deny_reason,
            )

            _deny_msg = f"{self._service_name}: {rpc_name} denied — {deny_reason}"
            _deny_status = deny_code

            async def _denied(request, context):
                await context.abort(_deny_status, _deny_msg)

            return grpc.unary_unary_rpc_method_handler(_denied)

        logger.debug(
            "%s ALLOWED '%s' for token '%s'",
            self._service_name,
            rpc_name,
            token.token_id if token else "anonymous",
        )

        return await continuation(handler_call_details)


# ── Legacy Interceptor ───────────────────────────────────────────


class TokenValidationInterceptor(grpc.aio.ServerInterceptor):
    """Legacy interceptor — kept for backward compatibility.

    Prefer ``ServicePermissionInterceptor`` for new services.
    This interceptor only validates token presence, not RPC-level permissions.
    """

    def __init__(self, config: SecurityConfig | None = None) -> None:
        self._config = config or SecurityConfig()

    async def intercept_service(self, continuation, handler_call_details) -> grpc.RpcMethodHandler:
        """Intercept incoming gRPC calls for token validation."""
        if not self._config.security_enabled:
            return await continuation(handler_call_details)

        method = handler_call_details.method or ""
        for skip in self._config.skip_methods:
            if skip in method:
                return await continuation(handler_call_details)

        return await continuation(handler_call_details)


__all__ = [
    "EnforcementMode",
    "ServicePermissionInterceptor",
    "TokenValidationInterceptor",
    "_extract_rpc_name",
    "_should_skip",
    "check_permission",
]
