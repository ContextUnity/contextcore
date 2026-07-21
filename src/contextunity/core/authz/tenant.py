"""Canonical fail-closed tenant resolution for authenticated runtime paths."""

from __future__ import annotations

from collections.abc import Iterable

from contextunity.core.exceptions import SecurityError
from contextunity.core.tenant_policy import validate_tenant_id
from contextunity.core.tokens import ContextToken


def resolve_single_tenant_scope(
    allowed_tenants: Iterable[str],
    *,
    boundary: str,
) -> str:
    """Resolve exactly one tenant from a scope or fail closed.

    Args:
        allowed_tenants: Authorized tenant identifiers.
        boundary: Runtime boundary included in safe diagnostic messages.

    Returns:
        The sole validated tenant identifier.

    Raises:
        SecurityError: When the scope is empty or ambiguous.
    """
    tenants = tuple(allowed_tenants)
    if not tenants:
        raise SecurityError(message=f"{boundary} cannot resolve tenant: token has no allowed_tenants")
    if len(tenants) != 1:
        raise SecurityError(
            message=(
                f"{boundary} cannot resolve tenant: token has multiple allowed_tenants; "
                "provide an explicit authorized tenant_id"
            )
        )
    (tenant_id,) = tenants
    return validate_tenant_id(tenant_id, allow_reserved=True)


def resolve_token_tenant(
    token: ContextToken | None,
    *,
    requested_tenant_id: str | None = None,
    boundary: str,
) -> str:
    """Resolve an authorized target tenant from a verified token.

    Payload/request tenant identifiers are selectors, never identity authority.
    An omitted selector is accepted only for a single-tenant token.

    Args:
        token: Verified caller token.
        requested_tenant_id: Explicit target tenant selector, if supplied.
        boundary: Runtime boundary included in safe diagnostic messages.

    Returns:
        An authorized tenant identifier.

    Raises:
        SecurityError: For missing tokens, unauthorized selectors, or ambiguous scopes.
    """
    if token is None:
        raise SecurityError(
            message=f"{boundary} requires a verified ContextToken",
            code="UNAUTHENTICATED",
        )

    if requested_tenant_id:
        tenant_id = validate_tenant_id(requested_tenant_id, allow_reserved=True)
        if not token.can_access_tenant(tenant_id):
            raise SecurityError(message=f"{boundary} tenant {tenant_id!r} is outside token scope")
        return tenant_id

    return resolve_single_tenant_scope(token.allowed_tenants, boundary=boundary)


__all__ = ["resolve_single_tenant_scope", "resolve_token_tenant"]
