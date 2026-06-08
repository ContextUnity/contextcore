"""Shared validation logic for capability-based permissions."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from contextunity.core.permissions.inheritance import expand_permissions


def validate_attenuation_permissions(
    parent_permissions: Iterable[str],
    requested_permissions: Sequence[str] | None,
) -> tuple[str, ...]:
    """Validates that requested_permissions do not exceed parent_permissions.

    If requested_permissions is None, returns the parent permissions unchanged.
    If requested permissions contain unauthorized elements, raises SecurityError.

    Args:
        parent_permissions: The permissions held by the parent token.
        requested_permissions: The permissions being requested for the child token.

    Returns:
        The validated tuple of permissions for the child token.

    Raises:
        SecurityError: If requested permissions exceed the parent's scope.
    """
    if requested_permissions is None:
        return tuple(parent_permissions)

    parent_expanded = frozenset(expand_permissions(list(parent_permissions)))
    child_expanded = frozenset(expand_permissions(list(requested_permissions)))
    excess = set(child_expanded - parent_expanded)

    if excess:
        unauthorized: set[str] = set()
        for perm in excess:
            parts = perm.split(":")
            if len(parts) >= 2:
                prefix = parts[0]
                if f"{prefix}:*" in parent_expanded:
                    continue

                allowed = False
                for depth in range(2, len(parts)):
                    ancestor = ":".join(parts[:depth])
                    if ancestor in parent_expanded:
                        allowed = True
                        break
                if allowed:
                    continue
            unauthorized.add(perm)

        if unauthorized:
            from contextunity.core.exceptions import SecurityError

            raise SecurityError(
                f"Delegation violation: requested permissions exceed parent scope: {sorted(unauthorized)}. Parent had: {sorted(parent_expanded)}"
            )

    return tuple(requested_permissions)


def validate_attenuation_tenants(
    parent_tenants: Iterable[str],
    requested_tenants: Sequence[str] | None,
    *,
    parent_is_admin: bool = False,
) -> tuple[str, ...]:
    """Validate tenant narrowing for delegated/attenuated tokens.

    An explicitly administrative parent may adopt ``requested_tenants`` verbatim.
    Otherwise ``requested_tenants`` must be a subset of the parent set.

    Args:
        parent_tenants: Tenants on the parent token.
        requested_tenants: Narrower tenant set for the child token.
        parent_is_admin: Whether the parent has the explicit ``admin:all`` capability.

    Returns:
        Effective tenant tuple for the child token.

    Raises:
        SecurityError: If requested tenants exceed the parent scope.
    """
    if requested_tenants is None:
        return tuple(parent_tenants)

    requested = tuple(requested_tenants)
    parent = tuple(parent_tenants)
    if parent_is_admin:
        return requested

    parent_set = set(parent)
    excess = [tenant for tenant in requested if tenant not in parent_set]
    if excess:
        from contextunity.core.exceptions import SecurityError

        raise SecurityError(
            (
                "Delegation violation: requested tenants exceed parent scope: "
                f"{sorted(excess)}. Parent allows: {sorted(parent_set)}"
            )
        )
    return requested
