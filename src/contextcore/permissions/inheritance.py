"""Permission inheritance, expansion, and access-tier profiles.

Provides:
- ``PERMISSION_INHERITANCE`` — parent → children relationships.
- ``expand_permissions()`` — resolve inherited permissions.
- ``NAMESPACE_PROFILES`` — user tier → default permission sets.
- ``PROJECT_PROFILES`` — common project configurations.
"""

from __future__ import annotations

from .constants import Permissions, UserNamespace

# ── Permission Inheritance ──────────────────────────────
# Parent permission implies all children.

PERMISSION_INHERITANCE: dict[str, tuple[str, ...]] = {
    Permissions.ADMIN_ALL: (
        Permissions.ADMIN_READ,
        Permissions.ADMIN_WRITE,
        Permissions.ADMIN_TRACE,
        Permissions.BRAIN_READ,
        Permissions.BRAIN_WRITE,
        Permissions.MEMORY_READ,
        Permissions.MEMORY_WRITE,
        Permissions.TRACE_READ,
        Permissions.TRACE_WRITE,
    ),
    Permissions.GRAPH_DISPATCHER: (
        Permissions.GRAPH_RAG,
        Permissions.GRAPH_COMMERCE,
        Permissions.GRAPH_NEWS,
        Permissions.GRAPH_MEDICAL,
    ),
    Permissions.MEMORY_WRITE: (Permissions.MEMORY_READ,),
    Permissions.BRAIN_WRITE: (Permissions.BRAIN_READ,),
    Permissions.ADMIN_TRACE: (Permissions.TRACE_READ,),
    Permissions.ZERO_ALL: (
        Permissions.ZERO_ANONYMIZE,
        Permissions.ZERO_DEANONYMIZE,
        Permissions.ZERO_CHECK_PII,
        Permissions.ZERO_AUDIT,
    ),
    Permissions.ZERO_ANONYMIZE: (
        Permissions.ZERO_DEANONYMIZE,
        Permissions.ZERO_CHECK_PII,
    ),
}


def expand_permissions(permissions: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """Expand permissions by resolving inheritance.

    If a token has ``admin:all``, this will expand it to include
    ``admin:read``, ``admin:write``, ``brain:read``, etc.

    Args:
        permissions: Raw permission strings from token or profile.

    Returns:
        Deduplicated, sorted tuple with all implied permissions.

    Example::

        >>> expand_permissions(("admin:all",))
        ('admin:all', 'admin:read', 'admin:trace', 'admin:write',
         'brain:read', 'brain:write', 'memory:read', 'memory:write',
         'trace:read', 'trace:write')
    """
    expanded: set[str] = set(permissions)
    queue = list(permissions)

    while queue:
        perm = queue.pop()
        children = PERMISSION_INHERITANCE.get(perm, ())
        for child in children:
            if child not in expanded:
                expanded.add(child)
                queue.append(child)

    return tuple(sorted(expanded))


# ── Namespace → Permission Profiles ─────────────────────

NAMESPACE_PROFILES: dict[str, tuple[str, ...]] = {
    UserNamespace.FREE: (
        Permissions.GRAPH_RAG,
        Permissions.BRAIN_READ,
    ),
    UserNamespace.DEFAULT: (
        Permissions.GRAPH_RAG,
        Permissions.BRAIN_READ,
        Permissions.MEMORY_READ,
        Permissions.TRACE_WRITE,
    ),
    UserNamespace.PRO: (
        Permissions.GRAPH_RAG,
        Permissions.BRAIN_READ,
        Permissions.MEMORY_READ,
        Permissions.MEMORY_WRITE,
        Permissions.TRACE_WRITE,
        Permissions.TOOL_WEB_SEARCH,
        Permissions.TOOL_MEMORY,
        Permissions.ZERO_ANONYMIZE,
    ),
    UserNamespace.ADMIN: (Permissions.ADMIN_ALL,),
    UserNamespace.SYSTEM: (
        Permissions.BRAIN_READ,
        Permissions.BRAIN_WRITE,
        Permissions.MEMORY_WRITE,
        Permissions.TRACE_WRITE,
        Permissions.WORKER_SCHEDULE,
        Permissions.ZERO_ANONYMIZE,
        Permissions.ZERO_AUDIT,
    ),
}


# ── Project Profiles ────────────────────────────────────

PROJECT_PROFILES: dict[str, tuple[str, ...]] = {
    "rag_readonly": (
        Permissions.GRAPH_RAG,
        Permissions.BRAIN_READ,
        Permissions.MEMORY_READ,
    ),
    "rag_full": (
        Permissions.GRAPH_RAG,
        Permissions.BRAIN_READ,
        Permissions.MEMORY_READ,
        Permissions.MEMORY_WRITE,
        Permissions.TRACE_WRITE,
    ),
    "commerce": (
        Permissions.GRAPH_COMMERCE,
        Permissions.BRAIN_READ,
        Permissions.BRAIN_WRITE,
    ),
    "medical": (
        Permissions.GRAPH_MEDICAL,
        Permissions.BRAIN_READ,
        Permissions.MEMORY_READ,
        Permissions.MEMORY_WRITE,
        Permissions.TRACE_WRITE,
        Permissions.ZERO_ANONYMIZE,
        Permissions.ZERO_AUDIT,
    ),
    "admin": (Permissions.ADMIN_ALL,),
}


__all__ = [
    "NAMESPACE_PROFILES",
    "PERMISSION_INHERITANCE",
    "PROJECT_PROFILES",
    "expand_permissions",
]
