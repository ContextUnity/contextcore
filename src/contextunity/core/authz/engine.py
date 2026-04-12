"""Unified authorization engine for ContextUnity.

Single entry point for ALL authorization decisions across all services.
Replaces scattered ``has_tool_access``, ``has_registration_access``,
``check_permission``, and service-local ``AccessManager`` checks.

Usage::

    from contextunity.core.authz import authorize

    decision = authorize(
        auth_ctx,
        permission="brain:read",
        tenant_id="nszu",
    )
    if not decision.allowed:
        context.abort(grpc.StatusCode.PERMISSION_DENIED, decision.reason)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..logging import get_contextunit_logger
from ..permissions.access import (
    has_graph_access,
    has_registration_access,
    has_tool_access,
    has_tool_scope_access,
)
from ..permissions.policy import ToolPolicy, ToolRisk

if TYPE_CHECKING:
    from ..tokens import ContextToken
    from .context import VerifiedAuthContext

logger = get_contextunit_logger(__name__)


# ── Decision result ──────────────────────────────────────────────


@dataclass(frozen=True)
class AuthzDecision:
    """Result of an authorization check.

    Attributes:
        allowed: Whether the action is authorized.
        reason: Human-readable explanation (populated on denial).
        risk: Risk level for tool operations (safe/confirm/deny).
        effective_permissions: Permissions that were considered.
        effective_tenant: Resolved tenant for this decision.
        audit_tags: Metadata for audit logging.
    """

    allowed: bool = True
    reason: str | None = None
    risk: str = ToolRisk.SAFE
    effective_permissions: tuple[str, ...] = ()
    effective_tenant: str | None = None
    audit_tags: dict[str, str] = field(default_factory=dict)

    @property
    def denied(self) -> bool:
        return not self.allowed

    def require(self) -> None:
        """Raise PermissionError if denied."""
        if not self.allowed:
            raise PermissionError(self.reason or "Authorization denied")


# ── Core authorize function ─────────────────────────────────────


def authorize(
    auth: VerifiedAuthContext | ContextToken,
    *,
    permission: str | None = None,
    tenant_id: str | None = None,
    tool_name: str | None = None,
    tool_scope: str | None = None,
    tool_policy: ToolPolicy | None = None,
    graph_name: str | None = None,
    registration_project_id: str | None = None,
    service: str = "",
    rpc_name: str = "",
) -> AuthzDecision:
    """Unified authorization decision.

    Consolidates all permission/tenant/tool/graph/registration checks
    into one function with a structured result.

    Args:
        auth: Verified auth context or raw ContextToken.
        permission: Explicit permission string to check.
        tenant_id: Target tenant (checked against token.allowed_tenants).
        tool_name: Tool to authorize (uses has_tool_access).
        tool_scope: Tool scope for scoped-check (requires tool_name).
        tool_policy: Optional ToolPolicy for HITL/risk classification.
        graph_name: Graph to authorize (uses has_graph_access).
        registration_project_id: Project for registration check.
        service: Service name for audit tags.
        rpc_name: RPC method name for audit tags.

    Returns:
        AuthzDecision with allow/deny and reasoning.

    Examples::

        # Simple permission check
        authorize(ctx, permission="brain:read")

        # Tool with scope and policy
        authorize(ctx, tool_name="sql", tool_scope="read",
                  tool_policy=sql_policy, tenant_id="nszu")

        # Registration check
        authorize(ctx, registration_project_id="nszu")

        # Graph access
        authorize(ctx, graph_name="rag_retrieval")
    """
    from ..tokens import ContextToken
    from .context import VerifiedAuthContext

    # Resolve token and permissions
    if isinstance(auth, VerifiedAuthContext):
        token = auth.token
        effective_perms = auth.effective_permissions
        resolved_tenant = auth.active_tenant or tenant_id
    elif isinstance(auth, ContextToken):
        token = auth
        effective_perms = tuple(sorted(token._effective_permissions))
        resolved_tenant = tenant_id
    else:
        return AuthzDecision(
            allowed=False,
            reason="Invalid auth object — expected VerifiedAuthContext or ContextToken",
            effective_tenant=tenant_id,
        )

    audit = {
        "service": service,
        "rpc": rpc_name,
        "user_id": token.user_id or "",
        "agent_id": token.agent_id or "",
    }

    # ── Check 1: Token expiry ────────────────────────────
    if token.is_expired():
        return AuthzDecision(
            allowed=False,
            reason="Token expired",
            effective_permissions=effective_perms,
            effective_tenant=resolved_tenant,
            audit_tags=audit,
        )

    # ── Check 2: Tenant binding ──────────────────────────
    if resolved_tenant and not token.can_access_tenant(resolved_tenant):
        return AuthzDecision(
            allowed=False,
            reason=f"Token not authorized for tenant '{resolved_tenant}'",
            effective_permissions=effective_perms,
            effective_tenant=resolved_tenant,
            audit_tags=audit,
        )

    # ── Check 3: Explicit permission ─────────────────────
    # Skip if tool_name is provided — tool check (Check 4) handles
    # tool:* wildcards and admin:all via has_tool_access().
    if permission and not tool_name and not token.has_permission(permission):
        return AuthzDecision(
            allowed=False,
            reason=f"Missing permission: {permission}",
            effective_permissions=effective_perms,
            effective_tenant=resolved_tenant,
            audit_tags=audit,
        )

    # ── Check 4: Tool authorization ──────────────────────
    if tool_name:
        if tool_scope:
            # Scoped check with optional policy
            if not has_tool_scope_access(effective_perms, tool_name, tool_scope):
                return AuthzDecision(
                    allowed=False,
                    reason=f"Missing permission for tool '{tool_name}' at scope '{tool_scope}'",
                    risk=ToolRisk.DENY,
                    effective_permissions=effective_perms,
                    effective_tenant=resolved_tenant,
                    audit_tags=audit,
                )
            # Policy / HITL check
            if tool_policy:
                risk = tool_policy.risk_for_scope(tool_scope)
                if risk == ToolRisk.DENY:
                    return AuthzDecision(
                        allowed=False,
                        reason=f"Tool '{tool_name}' at scope '{tool_scope}' is policy-denied",
                        risk=risk,
                        effective_permissions=effective_perms,
                        effective_tenant=resolved_tenant,
                        audit_tags=audit,
                    )
                return AuthzDecision(
                    allowed=True,
                    risk=risk,
                    effective_permissions=effective_perms,
                    effective_tenant=resolved_tenant,
                    audit_tags=audit,
                )
        else:
            # Simple tool name check
            if not has_tool_access(effective_perms, tool_name):
                return AuthzDecision(
                    allowed=False,
                    reason=f"Missing permission for tool '{tool_name}'",
                    effective_permissions=effective_perms,
                    effective_tenant=resolved_tenant,
                    audit_tags=audit,
                )

    # ── Check 5: Graph authorization ─────────────────────
    if graph_name and not has_graph_access(effective_perms, graph_name):
        return AuthzDecision(
            allowed=False,
            reason=f"Missing permission for graph '{graph_name}'",
            effective_permissions=effective_perms,
            effective_tenant=resolved_tenant,
            audit_tags=audit,
        )

    # ── Check 6: Registration authorization ──────────────
    if registration_project_id and not has_registration_access(effective_perms, registration_project_id):
        return AuthzDecision(
            allowed=False,
            reason=f"Missing registration permission for project '{registration_project_id}'",
            effective_permissions=effective_perms,
            effective_tenant=resolved_tenant,
            audit_tags=audit,
        )

    # ── All checks passed ────────────────────────────────
    return AuthzDecision(
        allowed=True,
        effective_permissions=effective_perms,
        effective_tenant=resolved_tenant,
        audit_tags=audit,
    )


__all__ = [
    "AuthzDecision",
    "authorize",
]
