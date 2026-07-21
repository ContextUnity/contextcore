"""Access control + token primitives (ContextUnit protocol).

ContextToken provides authorization for ContextUnit operations.
It integrates with ContextUnit.security (SecurityScopes) for capability-based access control.

This is the canonical implementation of ContextToken for the ContextUnit protocol.
All services (contextunity.brain, contextunity.router, contextunity.commerce) should import from here.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import TypeAlias

from .exceptions import ConfigurationError
from .sdk import ContextUnit, SecurityScopes
from .types import JsonValue


@dataclass(frozen=True, slots=True)
class ProjectBound:
    """Signed authority bound to one exact manifest project id."""

    project_id: str

    def __post_init__(self) -> None:
        project_id = self.project_id.strip()
        if not project_id:
            raise ValueError("ProjectBound requires a non-empty project_id")
        if ":" in project_id:
            raise ValueError("ProjectBound project_id must not contain the kid delimiter ':'")
        object.__setattr__(self, "project_id", project_id)


@dataclass(frozen=True, slots=True)
class PlatformBound:
    """Explicit signed platform authority; never inferred from a null project."""


ProjectBinding: TypeAlias = ProjectBound | PlatformBound


@dataclass(frozen=True)
class ContextToken:
    """Authorization token for ContextUnit operations.

    ContextToken provides:
    - token_id: Unique identifier for audit trails
    - permissions: List of capability strings (e.g., "catalog:read", "product:write")
    - allowed_tenants: Tenant IDs this token can access. Empty grants no tenant
      access unless the token has ``admin:all``.
    - exp_unix: Expiration timestamp (None = no expiration)
    - iat: Issue timestamp (None = not tracked for this token). Used for
      precise epoch-based revoke-all comparisons (see
      contextunity.core.security.backend_resolver.is_token_revoked).
    - user_id: Identity of the human user (None = system/anonymous)
    - agent_id: Identity of the executing agent (None = unspecified)
    - user_namespace: Access tier within tenant ("free", "pro", "admin", "system")

    The token's permissions are validated against ContextUnit.security.scopes
    to enforce capability-based access control.
    """

    token_id: str
    project_binding: ProjectBinding | None = None
    permissions: tuple[str, ...] = ()
    allowed_tenants: tuple[str, ...] = ()
    exp_unix: float | None = None
    iat: float | None = None  # Issue time (Unix seconds); enables precise epoch-based revoke-all
    revocation_id: str | None = None  # For instant revocation via RevocationStore

    # Identity scoping — who is making the request
    user_id: str | None = None  # Human user identity (None = system/anonymous)
    agent_id: str | None = None  # Executing agent identity (None = unspecified)
    user_namespace: str = "default"  # Access tier: free, pro, admin, system

    # Traceability — cryptographically tied data lineage
    provenance: tuple[str, ...] = ()

    # Pre-computed expanded permissions (set in __post_init__)
    _effective_permissions: frozenset[str] = field(default=frozenset(), init=False, repr=False)

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

    @property
    def effective_permissions(self) -> frozenset[str]:
        """Expanded permission set including inherited scopes."""
        return self._effective_permissions

    def is_expired(self, *, now: float | None = None) -> bool:
        """Determine if the token has expired relative to a given timestamp.

        Args:
            now: Optional current Unix timestamp. Defaults to the current system time.

        Returns:
            bool: True if the token's expiration timestamp is set and has passed, False otherwise.
        """
        if self.exp_unix is None:
            return False
        t = time.time() if now is None else now
        return t >= self.exp_unix

    def has_permission(self, permission: str) -> bool:
        """Check if the token carries a specific permission scope.

        Performs a lookup within the pre-computed set of effective permissions,
        honoring the hierarchical inheritance model.

        Args:
            permission: The target permission string to check (e.g., "brain:read").

        Returns:
            bool: True if the permission is present directly or via inheritance,
            False otherwise.
        """
        return permission in self._effective_permissions

    def can_access_tenant(self, tenant_id: str) -> bool:
        """Check if the token is authorized to access the given tenant.

        Args:
            tenant_id: The tenant identifier to evaluate.

        Returns:
            bool: True if the token has access to the tenant, False otherwise.
        """
        if not tenant_id:
            return False  # Empty tenant_id is never allowed
        if self.has_permission("admin:all"):
            return True
        return tenant_id in self.allowed_tenants

    def can_read(self, scopes: SecurityScopes) -> bool:
        """Verify if the token has the necessary permissions to read from the specified scopes.

        Args:
            scopes: The security scopes restricting read access.

        Returns:
            bool: True if the token is authorized (at least one permission intersects
            the target read scopes, or the target has no read constraints), False otherwise.
        """
        if not scopes.read:
            return True  # No restrictions
        return bool(self._effective_permissions & set(scopes.read))

    def can_write(self, scopes: SecurityScopes) -> bool:
        """Verify if the token has the necessary permissions to write to the specified scopes.

        Args:
            scopes: The security scopes restricting write access.

        Returns:
            bool: True if the token is authorized (at least one permission intersects
            the target write scopes, or the target has no write constraints), False otherwise.
        """
        if not scopes.write:
            return True  # No restrictions
        return bool(self._effective_permissions & set(scopes.write))


class TokenBuilder:
    """Token Minting, Attenuation, and Security Verification Registry.

    This class serves as the core token factory and validation engine in the ContextUnity
    cryptographic security model. It generates, attenuates, and verifies `ContextToken` objects
    which are attached to every operation context across services.

    Key Security Capabilities:
        - Root Token Minting: Generating initial high-privilege tokens for human users or system processes.
        - Token Attenuation: Generating lower-privilege tokens derived from parent tokens by narrowing
          permissions, limiting TTL, or tracking delegation lineage.
        - Verification & Auditing: Enforcing role-based access control, inheritance check, expiration
          validity, and ContextUnit resource access gates.

    Security Invariant:
        Security verification is always active across the platform. There is no fallback or opt-out mechanism.
    """

    def mint_root(
        self,
        *,
        user_ctx: dict[str, JsonValue],
        permissions: Iterable[str],
        ttl_s: float,
        project_binding: ProjectBinding | None = None,
        allowed_tenants: Iterable[str] | None = None,
        user_id: str | None = None,
        agent_id: str | None = None,
        user_namespace: str = "default",
    ) -> ContextToken:
        """Create a new root capability token with specified permissions and identity attributes.

        This method is the initial entrypoint for producing high-privilege context tokens. It constructs
        a new token identity with an expansion-restricted permission set, namespace tier, and optional
        tenant boundaries.

        Args:
            user_ctx: A dictionary containing user execution context details (reserved for future datalog facts).
            permissions: Capability strings representing granted permissions (e.g., `["catalog:read", "product:write"]`).
            ttl_s: Time-to-live duration in seconds.
            project_binding: Signed project or platform authority carried by the token.
            allowed_tenants: Tenant identifiers this token is restricted to. Empty grants
                no tenant access unless ``permissions`` includes ``admin:all``.
            user_id: The unique identity of the human user initiating the request. This field is the immutable source
                of truth and cannot be modified or overridden by downstream agents.
            agent_id: The unique identity of the agent executing the request (e.g., "router-agent").
            user_namespace: Access tier configuration determining resource access tier ("free", "pro", "admin", "system").

        Returns:
            ContextToken: A newly minted cryptographic token holding the defined capabilities.
        """
        _ = user_ctx  # reserved for future datalog facts
        token_id = secrets.token_urlsafe(32)  # 256 bits
        revocation_id = f"rev-{secrets.token_urlsafe(16)}"
        now = time.time()
        exp_unix = now + ttl_s

        identity = user_id or agent_id or "system"

        return ContextToken(
            token_id=token_id,
            project_binding=project_binding,
            permissions=tuple(permissions),
            allowed_tenants=tuple(allowed_tenants or ()),
            exp_unix=exp_unix,
            iat=now,
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
        allowed_tenants: Iterable[str] | None = None,
        ttl_s: float | None = None,
        agent_id: str | None = None,
    ) -> ContextToken:
        """Derive a new, attenuated token with reduced capabilities and updated delegation lineage.

        This method generates a lower-privilege token from an existing parent token. It strictly prevents
        permission expansion (child permissions must be a subset of parent permissions) and tenant
        expansion (child ``allowed_tenants`` must be a subset of the parent's, unless
        the parent has ``admin:all``).

        Lineage (Provenance) Tracking:
            When delegating a token to a downstream agent (e.g., dispatcher delegating to a RAG agent, which
            delegates to a tool agent), the transition is appended to the token's `provenance` tuple (e.g.,
            `*user > dispatcher > rag_agent`), ensuring an auditable execution chain.

        Args:
            token: The parent `ContextToken` from which the attenuated token is derived.
            permissions: A narrowed permission set. Must be a strict subset of the parent's permissions.
                If `None`, the child inherits the parent's permission set verbatim.
            allowed_tenants: A narrowed tenant scope. Must be a subset of the parent's
                tenants unless the parent has ``admin:all``.
            ttl_s: Optional time-to-live duration in seconds for the child token. The resulting absolute
                expiration timestamp is capped by the parent's expiration timestamp.
            agent_id: The identifier of the downstream agent to which execution is being delegated.

        Returns:
            ContextToken: The attenuated cryptographic token with updated delegation history and narrowed scopes.

        Raises:
            PermissionError: If the requested permissions are not a subset of the parent token's permissions.
            SecurityError: If the requested tenants are not a subset of the parent token's tenants.
        """
        exp_unix = token.exp_unix
        if ttl_s is not None:
            exp_unix = min(exp_unix or (time.time() + ttl_s), time.time() + ttl_s)

        if permissions is not None:
            from .permissions.validation import validate_attenuation_permissions

            perms = validate_attenuation_permissions(token.permissions, tuple(permissions))
        else:
            perms = token.permissions

        if allowed_tenants is not None:
            from .permissions.validation import validate_attenuation_tenants

            tenants = validate_attenuation_tenants(
                token.allowed_tenants,
                tuple(allowed_tenants),
                parent_is_admin=token.has_permission("admin:all"),
            )
        else:
            tenants = token.allowed_tenants

        # ── Update Provenance ──
        new_provenance = list(token.provenance)

        # Provenance tracks the delegation chain (who → who).
        # Scopes are NOT recorded here — they are in token.permissions.
        if agent_id is not None and agent_id != token.agent_id:
            new_provenance.append(f">{agent_id}")

        return ContextToken(
            token_id=token.token_id,
            project_binding=token.project_binding,
            permissions=perms,
            allowed_tenants=tenants,
            exp_unix=exp_unix,
            iat=token.iat,
            revocation_id=token.revocation_id,
            user_id=token.user_id,
            agent_id=agent_id if agent_id is not None else token.agent_id,
            user_namespace=token.user_namespace,
            provenance=tuple(new_provenance),
        )

    def verify(self, token: object, *, required_permission: str) -> None:
        """Verify that the given token has not expired and possesses the required capability.

        Checks the token validity status. It evaluates permission inheritance rules (e.g., checking if the
        implied/expanded permissions resolve to the required capability target).

        Args:
            token: The `ContextToken` instance to inspect.
            required_permission: The capability string required for the current execution context.

        Raises:
            PermissionError: If the token is missing, expired, or does not carry the required capability.
        """
        if not isinstance(token, ContextToken):
            raise PermissionError("Missing token")
        if token.is_expired():
            raise PermissionError("Token expired")
        if not token.has_permission(required_permission):
            raise PermissionError(f"Missing permission: {required_permission}")

    def verify_unit_access(
        self,
        token: object,
        unit: ContextUnit,
        *,
        operation: str = "read",
    ) -> None:
        """Verify that the token is authorized to access a specific ContextUnit resource.

        Evaluates the security scopes defined on the target `ContextUnit` against the token's expanded read/write
        privileges.

        Args:
            token: The `ContextToken` requesting access.
            unit: The `ContextUnit` resource target.
            operation: The type of access requested, either "read" or "write".

        Raises:
            PermissionError: If the token is missing, expired, or fails to meet the target unit's read/write scopes.
            ConfigurationError: If the specified operation is not "read" or "write".
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
            raise ConfigurationError(f"Invalid operation: {operation}")


# ── Service Token Factory ────────────────────────────────────────

import threading  # noqa: E402

_service_token_cache: dict[
    tuple[str, tuple[str, ...], tuple[str, ...], ProjectBinding | None],
    ContextToken,
] = {}
_service_token_lock = threading.Lock()

_DEFAULT_SERVICE_TTL = 3600  # 1 hour


_SERVICE_TOKEN_CACHE_MAX = 256


def _purge_expired_service_tokens() -> None:
    for key in list(_service_token_cache):
        cached = _service_token_cache.get(key)
        if cached is not None and cached.is_expired():
            del _service_token_cache[key]


def _trim_service_token_cache() -> None:
    _purge_expired_service_tokens()
    while len(_service_token_cache) > _SERVICE_TOKEN_CACHE_MAX:
        oldest_key = min(
            _service_token_cache,
            key=lambda cache_key: _service_token_cache[cache_key].exp_unix or 0.0,
        )
        del _service_token_cache[oldest_key]


def _tenant_scope_tuple(allowed_tenants: Iterable[str]) -> tuple[str, ...]:
    """Normalize tenant scope for service token construction and cache keys."""
    tenants: list[str] = []
    seen: set[str] = set()
    for tenant in allowed_tenants:
        if not tenant or tenant in seen:
            continue
        tenants.append(tenant)
        seen.add(tenant)
    return tuple(tenants)


def mint_service_token(
    token_id: str,
    *,
    permissions: Iterable[str],
    ttl_s: float = _DEFAULT_SERVICE_TTL,
    allowed_tenants: Iterable[str] = (),
    project_binding: ProjectBinding | None = None,
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
        allowed_tenants: Tenant restriction. Empty grants no tenant access unless
            ``permissions`` includes ``admin:all``.

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
    tenants = _tenant_scope_tuple(allowed_tenants)
    permission_tuple = tuple(permissions)
    cache_key = (token_id, permission_tuple, tenants, project_binding)

    with _service_token_lock:
        _purge_expired_service_tokens()
        cached = _service_token_cache.get(cache_key)
        if cached is not None and not cached.is_expired():
            return cached

        token = ContextToken(
            token_id=token_id,
            project_binding=project_binding,
            permissions=permission_tuple,
            allowed_tenants=tenants,
            exp_unix=time.time() + ttl_s,
            provenance=(f"service:{token_id}",),
        )
        _service_token_cache[cache_key] = token
        _trim_service_token_cache()
        return token


# ── Caller-aware Brain service token ────────────────────────────

from .permissions import brain_caller_permissions  # noqa: E402


def get_brain_service_token(
    caller: str,
    *,
    allowed_tenants: Iterable[str] = (),
    project_binding: ProjectBinding | None = None,
) -> ContextToken:
    """Return a cached service→Brain ContextToken with caller-appropriate permissions.

    Replaces per-service ``core/brain_token.py`` files. Each caller gets
    precisely the minimum permissions it needs.

    Args:
        caller: Service name (``"router"``, ``"worker"``, ``"view"``,
                ``"commerce"``).
        allowed_tenants: Explicit tenant scope for service-originated Brain
            calls. Empty grants no tenant access unless the permission set has
            ``admin:all``.

    Raises:
        ConfigurationError: If the `caller` service name is not recognized or not mapped to permissions.

    Example::

        from contextunity.core.tokens import get_brain_service_token

        token = get_brain_service_token("router")
        client = BrainClient(host=endpoint, token=token)
    """
    permissions = brain_caller_permissions(caller)
    if project_binding is None:
        from .authz.context import get_auth_context

        auth_context = get_auth_context()
        if auth_context is not None:
            project_binding = auth_context.project_binding
        else:
            from .sdk.identity import get_project_id

            project_id = get_project_id()
            if project_id:
                project_binding = ProjectBound(project_id)
    return mint_service_token(
        f"{caller}-brain-service",
        permissions=permissions,
        allowed_tenants=allowed_tenants,
        project_binding=project_binding,
    )


__all__ = [
    "ContextToken",
    "PlatformBound",
    "ProjectBinding",
    "ProjectBound",
    "TokenBuilder",
    "mint_service_token",
    "get_brain_service_token",
]
