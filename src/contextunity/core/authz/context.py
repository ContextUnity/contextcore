"""Verified auth context — canonical runtime identity after interceptor verification.

``VerifiedAuthContext`` is created by the service interceptor after cryptographic
token verification. All downstream handlers and authorization decisions consume
this object instead of re-parsing raw metadata.

Usage::

    # In interceptor (after token verification):
    auth_ctx = VerifiedAuthContext.from_token(
        token=verified_token,
        token_string=raw_token_str,
        project_id=project_id,
    )
    set_auth_context(auth_ctx)

    # In handler:
    auth_ctx = get_auth_context()
    decision = authorize(auth_ctx, permission="brain:read", tenant_id="nszu")
"""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from typing import Literal

from ..tokens import ContextToken

# ── ContextVar for async-safe propagation ────────────────────────

_auth_context_var: ContextVar[VerifiedAuthContext | None] = ContextVar("verified_auth_context", default=None)


def set_auth_context(ctx: VerifiedAuthContext) -> None:
    """Set the verified auth context for the current async task."""
    _auth_context_var.set(ctx)


def get_auth_context() -> VerifiedAuthContext | None:
    """Get the verified auth context for the current async task."""
    return _auth_context_var.get()


def require_auth_context() -> VerifiedAuthContext:
    """Get the verified auth context or raise.

    Use in handlers that MUST have a verified caller.

    Raises:
        PermissionError: If no verified auth context is available.
    """
    ctx = _auth_context_var.get()
    if ctx is None:
        raise PermissionError("No verified auth context — handler called without interceptor verification")
    return ctx


def reset_auth_context() -> None:
    """Reset the auth context (for testing)."""
    _auth_context_var.set(None)


# ── VerifiedAuthContext ──────────────────────────────────────────


@dataclass(frozen=True)
class VerifiedAuthContext:
    """Verified caller identity after interceptor token verification.

    Created once at the gRPC boundary by ``ServicePermissionInterceptor``.
    Downstream code reads this from a ``ContextVar`` — no re-parsing metadata.

    Attributes:
        token: The cryptographically verified ``ContextToken``.
        token_string: Raw serialized token string (for forwarding to downstream services).
        project_id: Project extracted from the token's kid (e.g. ``"nszu"``).
        caller_kind: Classification of the caller.
        effective_permissions: Post-expansion permission set (inheritance resolved).
        effective_tenants: Tenant IDs from the token (empty = admin/all).
        active_tenant: Resolved target tenant for this request (None = not yet resolved).
    """

    token: ContextToken
    token_string: str
    project_id: str | None = None
    caller_kind: Literal["project", "service", "user", "admin"] = "project"
    effective_permissions: tuple[str, ...] = ()
    effective_tenants: tuple[str, ...] = ()
    active_tenant: str | None = None

    @classmethod
    def from_token(
        cls,
        token: ContextToken,
        token_string: str,
        *,
        project_id: str | None = None,
        caller_kind: Literal["project", "service", "user", "admin"] | None = None,
        active_tenant: str | None = None,
    ) -> VerifiedAuthContext:
        """Create from a verified ContextToken.

        Automatically expands permissions and classifies caller kind.

        Args:
            token: Verified ContextToken.
            token_string: Raw token string for forwarding.
            project_id: Project ID from kid (optional).
            caller_kind: Override caller classification (auto-detected if None).
            active_tenant: Explicit target tenant (optional).
        """
        effective_permissions = tuple(sorted(token._effective_permissions))
        effective_tenants = token.allowed_tenants

        # Auto-detect caller kind
        if caller_kind is None:
            if not effective_tenants:
                kind: Literal["project", "service", "user", "admin"] = "admin"
            elif token.agent_id and token.agent_id.startswith("project:"):
                kind = "project"
            elif token.user_id and token.user_id == "system":
                kind = "service"
            else:
                kind = "user"
        else:
            kind = caller_kind

        return cls(
            token=token,
            token_string=token_string,
            project_id=project_id,
            caller_kind=kind,
            effective_permissions=effective_permissions,
            effective_tenants=effective_tenants,
            active_tenant=active_tenant,
        )

    def can_access_tenant(self, tenant_id: str) -> bool:
        """Check if this context authorizes access to a tenant."""
        return self.token.can_access_tenant(tenant_id)

    def has_permission(self, permission: str) -> bool:
        """Check if this context has a permission (expansion-aware)."""
        return self.token.has_permission(permission)


__all__ = [
    "VerifiedAuthContext",
    "get_auth_context",
    "require_auth_context",
    "reset_auth_context",
    "set_auth_context",
]
