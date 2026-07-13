"""Canonical permission profiles for autonomous platform services."""

from __future__ import annotations

from typing import Final

from contextunity.core.exceptions import ConfigurationError

from .constants import Permissions

SERVICE_SESSION_PERMISSION_PROFILES: Final[dict[str, tuple[str, ...]]] = {
    "brain": (
        Permissions.BRAIN_READ,
        Permissions.BRAIN_WRITE,
        Permissions.TRACE_READ,
        Permissions.TRACE_WRITE,
        Permissions.MEMORY_READ,
        Permissions.MEMORY_WRITE,
    ),
    "router": (
        Permissions.ROUTER_EXECUTE,
        Permissions.TOOL_ALL,
        Permissions.GRAPH_ALL,
        Permissions.SHIELD_SECRETS_READ,
        Permissions.PRIVACY_ALL,
    ),
    "worker": (
        Permissions.SHIELD_SESSION_TOKEN_ISSUE,
        Permissions.WORKER_EXECUTE,
        Permissions.WORKER_SCHEDULE,
        Permissions.BRAIN_READ,
        Permissions.BRAIN_WRITE,
        Permissions.BRAIN_EMBED,
        Permissions.DOCS_READ,
        Permissions.MEMORY_READ,
        Permissions.MEMORY_WRITE,
        Permissions.TRACE_WRITE,
    ),
    "shield": (
        Permissions.SHIELD_SECRETS_READ,
        Permissions.SHIELD_SECRETS_WRITE,
        Permissions.SHIELD_SESSION_TOKEN_ISSUE,
    ),
}


BRAIN_CALLER_PERMISSION_PROFILES: Final[dict[str, tuple[str, ...]]] = {
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
        Permissions.BRAIN_EMBED,
        Permissions.DOCS_READ,
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
}


def _permission_profile(
    profiles: dict[str, tuple[str, ...]],
    subject: str,
    *,
    profile_kind: str,
) -> tuple[str, ...]:
    permissions = profiles.get(subject)
    if permissions is None:
        raise ConfigurationError(
            f"Unsupported {profile_kind}: {subject!r}. Known values: {sorted(profiles)}",
        )
    return permissions


def service_session_permissions(service_name: str) -> tuple[str, ...]:
    """Return policy-bounded permissions for one autonomous service session."""
    return _permission_profile(
        SERVICE_SESSION_PERMISSION_PROFILES,
        service_name,
        profile_kind="autonomous Shield service",
    )


def brain_caller_permissions(caller: str) -> tuple[str, ...]:
    """Return minimum permissions for one service-to-Brain token."""
    return _permission_profile(
        BRAIN_CALLER_PERMISSION_PROFILES,
        caller,
        profile_kind="Brain service caller",
    )


__all__ = [
    "BRAIN_CALLER_PERMISSION_PROFILES",
    "SERVICE_SESSION_PERMISSION_PROFILES",
    "brain_caller_permissions",
    "service_session_permissions",
]
