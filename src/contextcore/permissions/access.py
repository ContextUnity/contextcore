"""Access-check helpers for tools, graphs, and registration.

Provides runtime functions to check if a permission set grants
access to a specific resource. Used by service handlers and
the security guard node.
"""

from __future__ import annotations

import logging

from .constants import Permissions
from .policy import ToolPolicy, ToolRisk, ToolScope

logger = logging.getLogger(__name__)


def has_tool_access(permissions: tuple[str, ...] | list[str], tool_name: str) -> bool:
    """Check if a permission set grants access to a specific tool.

    Checks in order:
    1. ``tool:*`` (wildcard — all tools)
    2. ``tool:{tool_name}`` (exact match)
    3. ``admin:all`` (superadmin)

    Args:
        permissions: Permission strings from a ContextToken.
        tool_name: Exact tool name (e.g. ``"brain_search"``, ``"shield_scan"``).

    Returns:
        True if access is granted.

    Example::

        token = builder.mint_root(permissions=[
            Permissions.tool("brain_search"),
            Permissions.tool("shield_scan"),
        ])
        has_tool_access(token.permissions, "brain_search")  # True
        has_tool_access(token.permissions, "sql_execute")   # False

        # Wildcard grants access to everything
        admin_token = builder.mint_root(permissions=[Permissions.TOOL_ALL])
        has_tool_access(admin_token.permissions, "anything")  # True
    """
    perm_set = set(permissions)
    if Permissions.TOOL_ALL in perm_set:
        logger.warning(
            "tool:* wildcard used for tool '%s' — consider specific 'tool:%s' permission",
            tool_name,
            tool_name,
        )
        return True
    return Permissions.ADMIN_ALL in perm_set or f"tool:{tool_name}" in perm_set


def has_registration_access(
    permissions: tuple[str, ...] | list[str],
    project_id: str,
) -> bool:
    """Check if a permission set grants tool registration for project_id.

    Checks in order:
    1. ``tools:register`` (generic — register for ANY project)
    2. ``tools:register:{project_id}`` (project-specific)
    3. ``admin:all`` (superadmin)

    Args:
        permissions: Permission strings from a ContextToken.
        project_id: Project to check registration rights for.

    Returns:
        True if registration is allowed.

    Example::

        # Generic registration permission
        has_registration_access(("tools:register",), "nszu")  # True
        has_registration_access(("tools:register",), "acme")  # True

        # Project-specific
        has_registration_access(("tools:register:nszu",), "nszu")  # True
        has_registration_access(("tools:register:nszu",), "acme")  # False
    """
    perm_set = set(permissions)
    return (
        Permissions.TOOLS_REGISTER in perm_set
        or Permissions.ADMIN_ALL in perm_set
        or f"tools:register:{project_id}" in perm_set
    )


def has_graph_access(permissions: tuple[str, ...] | list[str], graph_name: str) -> bool:
    """Check if a permission set grants access to a specific graph.

    Checks in order:
    1. ``graph:*`` (wildcard — all graphs)
    2. ``graph:{graph_name}`` (exact match)
    3. ``graph:dispatcher`` (implies all graphs via inheritance)
    4. ``admin:all`` (superadmin)

    Args:
        permissions: Permission strings from a ContextToken.
        graph_name: Graph key as registered in graph_registry
                    (e.g. ``"rag_retrieval"``, ``"commerce_search"``).

    Returns:
        True if access is granted.

    Example::

        token = builder.mint_root(permissions=[
            Permissions.graph("rag_retrieval"),
        ])
        has_graph_access(token.permissions, "rag_retrieval")    # True
        has_graph_access(token.permissions, "commerce_search")  # False
    """
    perm_set = set(permissions)
    return (
        Permissions.GRAPH_ALL in perm_set
        or Permissions.ADMIN_ALL in perm_set
        or Permissions.GRAPH_DISPATCHER in perm_set
        or f"graph:{graph_name}" in perm_set
    )


def extract_tool_names(permissions: tuple[str, ...] | list[str]) -> frozenset[str]:
    """Extract concrete tool names from a permission set.

    Useful for building the ``allowed_tools`` whitelist in
    ``security_guard_node()``.

    Returns ``None``-equivalent (empty frozenset with ``*``) if wildcard
    is present — caller should interpret as "all tools allowed".

    Args:
        permissions: Permission strings from a ContextToken.

    Returns:
        Frozenset of tool names (e.g. ``frozenset({"brain_search", "shield_scan"})``).
        Contains ``"*"`` if wildcard is granted.

    Example::

        perms = ("tool:brain_search", "tool:shield_scan", "brain:read")
        extract_tool_names(perms)  # frozenset({"brain_search", "shield_scan"})

        perms = ("tool:*", "brain:read")
        extract_tool_names(perms)  # frozenset({"*"})
    """
    if Permissions.TOOL_ALL in permissions or Permissions.ADMIN_ALL in permissions:
        return frozenset({"*"})

    return frozenset(
        perm.split(":", 1)[1] for perm in permissions if perm.startswith("tool:") and perm != Permissions.TOOL_ALL
    )


# ── Scoped Tool Permission Checking ────────────────────


def has_tool_scope_access(
    permissions: tuple[str, ...] | list[str],
    tool_name: str,
    scope: str,
) -> bool:
    """Check if a permission set grants access to a tool at a specific scope.

    Checks (in order of priority):
    1. ``admin:all`` — superadmin, everything allowed
    2. ``tool:*`` — wildcard for all tools, all scopes
    3. ``tool:{name}`` — full access to this tool (all scopes)
    4. ``tool:{name}:{scope}`` — exact scope match
    5. Scope hierarchy: ``tool:{name}:admin`` implies write and read;
       ``tool:{name}:write`` implies read.

    Args:
        permissions: Permission strings from a ContextToken.
        tool_name: Tool name (e.g. ``"sql"``, ``"execute_cmd"``).
        scope: Required scope (use :class:`ToolScope` constants).

    Returns:
        True if the token authorizes the operation.

    Example::

        perms = (Permissions.tool("sql", "read"),)
        has_tool_scope_access(perms, "sql", ToolScope.READ)   # True
        has_tool_scope_access(perms, "sql", ToolScope.WRITE)  # False

        perms = (Permissions.tool("sql", "write"),)
        has_tool_scope_access(perms, "sql", ToolScope.READ)   # True (write ⊃ read)
        has_tool_scope_access(perms, "sql", ToolScope.ADMIN)  # False

        perms = (Permissions.tool("sql"),)  # full access
        has_tool_scope_access(perms, "sql", ToolScope.ADMIN)  # True
    """
    perm_set = set(permissions)

    # Superadmin & wildcards
    if Permissions.ADMIN_ALL in perm_set or Permissions.TOOL_ALL in perm_set:
        return True

    # Full tool access (unscoped)
    if f"tool:{tool_name}" in perm_set:
        return True

    # Exact scope match
    if f"tool:{tool_name}:{scope}" in perm_set:
        return True

    # Hierarchy: higher scope implies lower scopes
    hierarchy = ToolScope.HIERARCHY
    try:
        required_idx = hierarchy.index(scope)
    except ValueError:
        return False  # Unknown scope

    # Check if any granted scope is >= required scope
    for granted_scope in hierarchy[required_idx + 1 :]:
        if f"tool:{tool_name}:{granted_scope}" in perm_set:
            return True

    return False


def check_tool_scope(
    permissions: tuple[str, ...] | list[str],
    tool_name: str,
    scope: str,
    policy: ToolPolicy | None = None,
) -> str:
    """Combined authorization + policy check for a tool operation.

    This is the main enforcement function. It answers both:
    - **CAN** the agent do this? (permission check)
    - **SHOULD** the agent do this? (risk classification / HITL)

    Returns a :class:`ToolRisk` value:
    - ``ToolRisk.SAFE`` → auto-execute
    - ``ToolRisk.CONFIRM`` → hold and request human approval
    - ``ToolRisk.DENY`` → block entirely

    Decision logic:
    1. If token lacks permission for this tool+scope → ``DENY``
    2. If policy says ``DENY`` for this scope → ``DENY``
    3. If policy says ``CONFIRM`` → ``CONFIRM``
    4. Otherwise → ``SAFE``

    Args:
        permissions: Permission strings from a ContextToken.
        tool_name: Tool name (e.g. ``"sql"``).
        scope: Operation scope (e.g. ``ToolScope.READ``).
        policy: Optional ToolPolicy. If None, uses default (read=safe, write=confirm, admin=deny).

    Returns:
        ToolRisk string (``"safe"``, ``"confirm"``, or ``"deny"``).

    Example::

        # Token allows read, policy is default
        check_tool_scope(perms, "sql", ToolScope.READ)   # "safe"
        check_tool_scope(perms, "sql", ToolScope.WRITE)  # "deny" (no permission)

        # Token allows write, policy requires confirmation
        perms = (Permissions.tool("sql", "write"),)
        check_tool_scope(perms, "sql", ToolScope.READ)   # "safe"
        check_tool_scope(perms, "sql", ToolScope.WRITE)  # "confirm"
        check_tool_scope(perms, "sql", ToolScope.ADMIN)  # "deny" (no permission)
    """
    # Step 1: Authorization check (CAN)
    if not has_tool_scope_access(permissions, tool_name, scope):
        return ToolRisk.DENY

    # Step 2: Policy check (SHOULD)
    effective_policy = policy or ToolPolicy(tool_name=tool_name)
    return effective_policy.risk_for_scope(scope)


__all__ = [
    "check_tool_scope",
    "extract_tool_names",
    "has_graph_access",
    "has_registration_access",
    "has_tool_access",
    "has_tool_scope_access",
]
