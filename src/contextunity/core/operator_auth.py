"""Local operator token mint — single HMAC path for CLI, Forge, and MCP."""

from __future__ import annotations

from contextunity.core.exceptions import ConfigurationError, SecurityError
from contextunity.core.permissions import Permissions
from contextunity.core.signing import HmacBackend
from contextunity.core.token_utils import serialize_token, verify_token_string
from contextunity.core.tokens import ContextToken, PlatformBound, TokenBuilder

_LOCAL_READ_PERMISSIONS: tuple[str, ...] = (
    Permissions.ADMIN_READ,
    Permissions.BRAIN_READ,
    Permissions.TRACE_READ,
    Permissions.TRACE_ARTIFACT_READ,
    Permissions.MEMORY_READ,
)

_LOCAL_PLATFORM_PERMISSIONS: tuple[str, ...] = (
    Permissions.ADMIN_ALL,
    Permissions.ADMIN_READ,
    Permissions.BRAIN_READ,
    Permissions.BRAIN_WRITE,
    Permissions.BRAIN_EMBED,
    Permissions.DOCS_READ,
    Permissions.DOCS_WRITE,
    Permissions.TRACE_READ,
    Permissions.TRACE_ARTIFACT_READ,
    Permissions.MEMORY_READ,
    Permissions.ROUTER_INTROSPECT,
)

# Explicit TTL contract — local platform admin is short-lived; scoped tenant tokens longer.
LOCAL_PLATFORM_ADMIN_TTL_S = 86_400.0  # 24h
LOCAL_SCOPED_TTL_S = 604_800.0  # 7d


def mint_local_operator_token(
    *,
    platform_secret: str,
    allowed_tenants: tuple[str, ...] | None = None,
    ttl_s: float | None = None,
    agent_id: str = "local:operator",
) -> tuple[str, ContextToken, float]:
    """Mint a local HMAC operator token.

    Default (no ``allowed_tenants``): platform admin — ``admin:all`` for cross-tenant
    Brain admin RPCs on the local stack.

    Scoped (``allowed_tenants`` non-empty): ``admin:read`` only, restricted tenants.
    """
    secret = platform_secret.strip()
    if not secret:
        raise ConfigurationError(
            "CU_PLATFORM_SECRET is required for local operator login",
            code="CONFIGURATION_ERROR",
        )

    if allowed_tenants:
        permissions = _LOCAL_READ_PERMISSIONS
        tenants = allowed_tenants
        effective_ttl = ttl_s if ttl_s is not None else LOCAL_SCOPED_TTL_S
    else:
        permissions = _LOCAL_PLATFORM_PERMISSIONS
        tenants = ()
        effective_ttl = ttl_s if ttl_s is not None else LOCAL_PLATFORM_ADMIN_TTL_S

    backend = HmacBackend("platform", secret)
    token = TokenBuilder().mint_root(
        user_ctx={},
        permissions=permissions,
        project_binding=PlatformBound(),
        allowed_tenants=tenants,
        ttl_s=effective_ttl,
        agent_id=agent_id,
    )
    bearer = serialize_token(token, backend=backend)
    verified = verify_token_string(bearer, backend)
    if verified is None:
        raise SecurityError("Local operator mint produced an unverifiable token", code="INVALID_TOKEN")
    exp = verified.exp_unix if verified.exp_unix is not None else 0.0
    return bearer, verified, exp


__all__ = [
    "LOCAL_PLATFORM_ADMIN_TTL_S",
    "LOCAL_SCOPED_TTL_S",
    "mint_local_operator_token",
]
