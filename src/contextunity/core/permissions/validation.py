"""Shared validation logic for capability-based permissions."""

from __future__ import annotations

from typing import Iterable, Sequence

from contextunity.core.permissions.inheritance import expand_permissions


def validate_attenuation_permissions(
    parent_permissions: Iterable[str],
    requested_permissions: Sequence[str] | None,
) -> tuple[str, ...]:
    """Validates that requested_permissions do not exceed parent_permissions.

    If requested_permissions is None, returns the parent permissions unchanged.
    If requested permissions contain unauthorized elements, raises PermissionError.

    Args:
        parent_permissions: The permissions held by the parent token.
        requested_permissions: The permissions being requested for the child token.

    Returns:
        The validated tuple of permissions for the child token.

    Raises:
        PermissionError: If requested permissions exceed the parent's scope.
    """
    if requested_permissions is None:
        return tuple(parent_permissions)

    parent_expanded = frozenset(expand_permissions(parent_permissions))
    child_expanded = frozenset(expand_permissions(requested_permissions))
    excess = set(child_expanded - parent_expanded)

    if excess:
        unauthorized = set()
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
            raise PermissionError(
                f"Delegation violation: requested permissions exceed parent scope: {sorted(unauthorized)}. Parent had: {sorted(parent_expanded)}"
            )

    return tuple(requested_permissions)
