"""Access control + token primitives (ContextUnit protocol).

ContextToken provides authorization for ContextUnit operations.
It integrates with ContextUnit.security (SecurityScopes) for capability-based access control.

This is the canonical implementation of ContextToken for the ContextUnit protocol.
All services (contextunity.brain, contextunity.router, contextunity.commerce) should import from here.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any, Iterable, Literal

from .sdk import ContextUnit, SecurityScopes


@dataclass(frozen=True)
class ContextToken:
    """Authorization token for ContextUnit operations.

    ContextToken provides:
    - token_id: Unique identifier for audit trails
    - permissions: List of capability strings (e.g., "catalog:read", "product:write")
    - allowed_tenants: Tenant IDs this token can access. Empty = admin (all tenants).
    - exp_unix: Expiration timestamp (None = no expiration)
    - user_id: Identity of the human user (None = system/anonymous)
    - agent_id: Identity of the executing agent (None = unspecified)
    - user_namespace: Access tier within tenant ("free", "pro", "admin", "system")

    The token's permissions are validated against ContextUnit.security.scopes
    to enforce capability-based access control.
    """

    token_id: str
    permissions: tuple[str, ...] = ()
    allowed_tenants: tuple[str, ...] = ()  # Empty = admin (all tenants)
    exp_unix: float | None = None
    revocation_id: str | None = None  # For instant revocation via RevocationStore

    # Identity scoping — who is making the request
    user_id: str | None = None  # Human user identity (None = system/anonymous)
    agent_id: str | None = None  # Executing agent identity (None = unspecified)
    user_namespace: str = "default"  # Access tier: free, pro, admin, system

    # Traceability — cryptographically tied data lineage
    provenance: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Pre-compute expanded permissions for inheritance-aware access checks.

        Uses ``object.__setattr__`` because this is a frozen dataclass.
        ``_effective_permissions`` is consumed by ``has_permission()``,
        ``can_read()``, ``can_write()``, and ``TokenBuilder.verify()``.
        """
        from .permissions.inheritance import expand_permissions

        object.__setattr__(
            self,
            "_effective_permissions",
            frozenset(expand_permissions(self.permissions)),
        )

    def is_expired(self, *, now: float | None = None) -> bool:
        """Check if token has expired."""
        if self.exp_unix is None:
            return False
        t = time.time() if now is None else now
        return t >= self.exp_unix

    def has_permission(self, permission: str) -> bool:
        """Check if token has a specific permission (including inherited).

        Uses expanded permissions: ``admin:all`` implies ``brain:read``, etc.
        See :data:`~contextunity.core.permissions.inheritance.PERMISSION_INHERITANCE`.
        """
        return permission in self._effective_permissions

    def can_access_tenant(self, tenant_id: str) -> bool:
        """Check if token is authorized to access a given tenant.

        Returns True if:
        - allowed_tenants is empty (admin token — unrestricted), OR
        - tenant_id is in allowed_tenants

        Returns False if:
        - tenant_id is empty/falsy (abuse prevention)
        - tenant_id is not in allowed_tenants
        """
        if not tenant_id:
            return False  # Empty tenant_id is never allowed
        if not self.allowed_tenants:
            return True  # Admin token — all tenants
        return tenant_id in self.allowed_tenants

    def can_read(self, scopes: SecurityScopes) -> bool:
        """Check if token can read from the given security scopes.

        Returns True if:
        - Any effective (expanded) permission matches any read scope, OR
        - Read scopes are empty (no restrictions)
        """
        if not scopes.read:
            return True  # No restrictions
        return bool(self._effective_permissions & set(scopes.read))

    def can_write(self, scopes: SecurityScopes) -> bool:
        """Check if token can write to the given security scopes.

        Returns True if:
        - Any effective (expanded) permission matches any write scope, OR
        - Write scopes are empty (no restrictions)
        """
        if not scopes.write:
            return True  # No restrictions
        return bool(self._effective_permissions & set(scopes.write))


class TokenBuilder:
    """Token minting + attenuation + verification.

    Part of the ContextUnit protocol. Creates and validates ContextToken instances
    that integrate with ContextUnit.security for capability-based access control.

    Security is always enforced — there is no opt-out.
    Signing is handled by contextunity.core.signing backends (auto-detected).
    """

    def mint_root(
        self,
        *,
        user_ctx: dict[str, Any],
        permissions: Iterable[str],
        ttl_s: float,
        allowed_tenants: Iterable[str] | None = None,
        user_id: str | None = None,
        agent_id: str | None = None,
        user_namespace: str = "default",
    ) -> ContextToken:
        """Create a new root token with specified permissions.

        Args:
            user_ctx: User context (reserved for future datalog facts)
            permissions: Capability strings (e.g., ["catalog:read", "product:write"])
            ttl_s: Time-to-live in seconds
            allowed_tenants: Tenant IDs this token can access.
                             None or empty = admin (all tenants).
                             Example: ["tenant-a", "tenant-b"]
            user_id: Identity of the human user making the request.
                     This is the source of truth — agents cannot override it.
            agent_id: Identity of the agent executing the request.
            user_namespace: Access tier within tenant ("free", "pro", "admin", "system").

        Returns:
            New ContextToken instance
        """
        _ = user_ctx  # reserved for future datalog facts
        token_id = secrets.token_urlsafe(16)
        revocation_id = f"rev-{secrets.token_urlsafe(12)}"
        exp_unix = time.time() + float(ttl_s)

        identity = user_id or agent_id or "system"

        return ContextToken(
            token_id=token_id,
            permissions=tuple(permissions),
            allowed_tenants=tuple(allowed_tenants or ()),
            exp_unix=exp_unix,
            revocation_id=revocation_id,
            user_id=user_id,
            agent_id=agent_id,
            user_namespace=user_namespace,
            provenance=(f"*{identity}",),
        )

    def attenuate(
        self,
        token: ContextToken,
        *,
        permissions: Iterable[str] | None = None,
        ttl_s: float | None = None,
        agent_id: str | None = None,
    ) -> ContextToken:
        """Create a new token with reduced permissions (attenuation).

        identity fields (user_id, user_namespace, allowed_tenants) are
        inherited from the parent token and cannot be expanded.
        agent_id CAN be changed — this is the normal delegation pattern
        (dispatcher → rag_agent → tool_agent).

        Args:
            token: Original token to attenuate
            permissions: New permission set (None = keep original)
            ttl_s: New TTL (None = keep original)
            agent_id: Override agent_id for the child (None = keep original)

        Returns:
            New ContextToken with attenuated permissions
        """
        exp_unix = token.exp_unix
        if ttl_s is not None:
            exp_unix = min(exp_unix or (time.time() + ttl_s), time.time() + ttl_s)

        if permissions is not None:
            from .permissions.validation import validate_attenuation_permissions

            perms = validate_attenuation_permissions(token.permissions, tuple(permissions))
        else:
            perms = token.permissions

        # ── Update Provenance ──
        new_provenance = list(token.provenance)

        # Provenance tracks the delegation chain (who → who).
        # Scopes are NOT recorded here — they are in token.permissions.
        if agent_id is not None and agent_id != token.agent_id:
            new_provenance.append(f">{agent_id}")

        return ContextToken(
            token_id=token.token_id,
            permissions=perms,
            allowed_tenants=token.allowed_tenants,
            exp_unix=exp_unix,
            revocation_id=token.revocation_id,
            user_id=token.user_id,
            agent_id=agent_id if agent_id is not None else token.agent_id,
            user_namespace=token.user_namespace,
            provenance=tuple(new_provenance),
        )

    def verify(self, token: ContextToken, *, required_permission: str) -> None:
        """Verify token has required permission (inheritance-aware).

        Uses ``has_permission()`` which checks expanded permissions.

        Raises:
            PermissionError: If token is missing, expired, or lacks permission
        """
        if not isinstance(token, ContextToken):
            raise PermissionError("Missing token")
        if token.is_expired():
            raise PermissionError("Token expired")
        if not token.has_permission(required_permission):
            raise PermissionError(f"Missing permission: {required_permission}")

    def verify_unit_access(
        self,
        token: ContextToken,
        unit: ContextUnit,
        *,
        operation: Literal["read", "write"] = "read",
    ) -> None:
        """Verify token can access ContextUnit based on its security scopes.

        Args:
            token: ContextToken to verify
            unit: ContextUnit to check access for
            operation: "read" or "write"

        Raises:
            PermissionError: If token cannot access the unit
        """
        # Security is always enforced — no opt-out.

        if not isinstance(token, ContextToken):
            raise PermissionError("Missing token")
        if token.is_expired():
            raise PermissionError("Token expired")

        scopes = unit.security
        if operation == "read":
            if not token.can_read(scopes):
                raise PermissionError(f"Token lacks read permission for unit scopes: {scopes.read}")
        elif operation == "write":
            if not token.can_write(scopes):
                raise PermissionError(f"Token lacks write permission for unit scopes: {scopes.write}")
        else:
            raise ValueError(f"Invalid operation: {operation}")


# ── Service Token Factory ────────────────────────────────────────

import threading  # noqa: E402

_service_token_cache: dict[str, ContextToken] = {}
_service_token_lock = threading.Lock()

_DEFAULT_SERVICE_TTL = 3600  # 1 hour


def mint_service_token(
    token_id: str,
    *,
    permissions: Iterable[str],
    ttl_s: float = _DEFAULT_SERVICE_TTL,
    allowed_tenants: Iterable[str] = (),
) -> ContextToken:
    """Mint or return a cached service-to-service ContextToken.

    Centralized factory for infrastructure tokens (Worker→Brain,
    Router→Brain, View→Brain, etc.). Handles caching and automatic
    TTL refresh — callers just declare WHAT they need.

    Thread-safe. Token is regenerated when it expires.

    Args:
        token_id: Stable identifier for audit (e.g. ``"worker-brain-service"``).
        permissions: Required permission strings.
        ttl_s: Token lifetime in seconds (default: 3600 = 1 hour).
        allowed_tenants: Tenant restriction (empty = admin/all-tenant).

    Returns:
        A valid, non-expired ContextToken.

    Usage::

        from contextunity.core.tokens import mint_service_token
        from contextunity.core.permissions import Permissions

        token = mint_service_token(
            "worker-brain-service",
            permissions=(Permissions.BRAIN_READ, Permissions.BRAIN_WRITE),
        )
        client = BrainClient(host=host, mode="grpc", token=token)
    """
    with _service_token_lock:
        cached = _service_token_cache.get(token_id)
        if cached is not None and not cached.is_expired():
            return cached

        token = ContextToken(
            token_id=token_id,
            permissions=tuple(permissions),
            allowed_tenants=tuple(allowed_tenants),
            exp_unix=time.time() + float(ttl_s),
            provenance=(f"service:{token_id}",),
        )
        _service_token_cache[token_id] = token
        return token


# ── Caller-aware Brain service token ────────────────────────────

from .permissions import Permissions  # noqa: E402

# Minimum permissions per caller → Brain.
# Each service gets exactly what it needs (principle of least privilege).
_BRAIN_PERMISSION_MAP: dict[str, tuple[str, ...]] = {
    "router": (
        Permissions.BRAIN_READ,
        Permissions.BRAIN_WRITE,
        Permissions.MEMORY_READ,
        Permissions.MEMORY_WRITE,
        Permissions.TRACE_WRITE,
        Permissions.WORKER_EXECUTE,
    ),
    "worker": (
        Permissions.BRAIN_READ,
        Permissions.BRAIN_WRITE,
        Permissions.MEMORY_READ,
        Permissions.MEMORY_WRITE,
        Permissions.TRACE_WRITE,
        Permissions.WORKER_EXECUTE,
    ),
    "view": (
        Permissions.BRAIN_READ,
        Permissions.MEMORY_READ,
        Permissions.TRACE_READ,
    ),
    "commerce": (
        Permissions.BRAIN_READ,
        Permissions.BRAIN_WRITE,
        Permissions.MEMORY_READ,
        Permissions.TRACE_WRITE,
        Permissions.WORKER_EXECUTE,
        Permissions.ROUTER_EXECUTE,
    ),
    "zero": (Permissions.TRACE_WRITE,),
}


def get_brain_service_token(caller: str) -> ContextToken:
    """Return a cached service→Brain ContextToken with caller-appropriate permissions.

    Replaces per-service ``core/brain_token.py`` files. Each caller gets
    precisely the minimum permissions it needs.

    Args:
        caller: Service name (``"router"``, ``"worker"``, ``"view"``,
                ``"commerce"``, ``"zero"``).

    Example::

        from contextunity.core.tokens import get_brain_service_token

        token = get_brain_service_token("router")
        client = BrainClient(host=endpoint, token=token)
    """
    permissions = _BRAIN_PERMISSION_MAP.get(caller)
    if permissions is None:
        raise ValueError(f"Unknown Brain service caller: {caller!r}. Known callers: {sorted(_BRAIN_PERMISSION_MAP)}")
    return mint_service_token(
        f"{caller}-brain-service",
        permissions=permissions,
    )


__all__ = ["ContextToken", "TokenBuilder", "mint_service_token", "get_brain_service_token"]
