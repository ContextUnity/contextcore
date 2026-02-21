"""Permission constants and namespace tiers for ContextUnity.

Provides:
- ``Permissions`` — all permission string constants (``domain:action`` format).
- ``UserNamespace`` — access tiers (free, pro, admin, system).
"""

from __future__ import annotations


class Permissions:
    """Canonical permission constants for ContextUnity.

    Format: ``{domain}:{action}``

    Two modes of use:

    1. **Static constants** — predefined common permissions::

        token.has_permission(Permissions.BRAIN_READ)

    2. **Dynamic builders** — for concrete tool/graph names::

        Permissions.tool("my_sql_executor")   → "tool:my_sql_executor"
        Permissions.graph("rag_retrieval")    → "graph:rag_retrieval"
        Permissions.service("brain", "read")  → "brain:read"
    """

    # ── Service Access ──────────────────────────────────
    DISPATCHER_EXECUTE = "dispatcher:execute"
    ROUTER_INVOKE = "router:invoke"
    BRAIN_READ = "brain:read"
    BRAIN_WRITE = "brain:write"
    SHIELD_CHECK = "shield:check"
    ZERO_ALL = "zero:*"  # Wildcard — access to all Zero operations
    ZERO_ANONYMIZE = "zero:anonymize"
    ZERO_DEANONYMIZE = "zero:deanonymize"
    ZERO_CHECK_PII = "zero:check_pii"
    ZERO_AUDIT = "zero:audit"
    WORKER_SCHEDULE = "worker:schedule"
    WORKER_EXECUTE = "worker:execute"
    WORKER_READ = "worker:read"

    # ── Graph Access ────────────────────────────────────
    GRAPH_RAG = "graph:rag"
    GRAPH_COMMERCE = "graph:commerce"
    GRAPH_NEWS = "graph:news"
    GRAPH_MEDICAL = "graph:medical"
    GRAPH_DISPATCHER = "graph:dispatcher"
    GRAPH_ALL = "graph:*"  # Wildcard — access to all graphs

    # ── Memory & Trace ──────────────────────────────────
    MEMORY_READ = "memory:read"
    MEMORY_WRITE = "memory:write"
    TRACE_WRITE = "trace:write"
    TRACE_READ = "trace:read"

    # ── Tool Access ─────────────────────────────────────
    # Common categories (shortcuts for well-known tools)
    TOOL_BRAIN_SEARCH = "tool:brain_search"
    TOOL_WEB_SEARCH = "tool:web_search"
    TOOL_MEMORY = "tool:memory"
    TOOL_SQL = "tool:sql"
    TOOL_FILE = "tool:file"
    TOOL_API = "tool:api"
    TOOL_ALL = "tool:*"  # Wildcard — access to all tools

    # ── Registration ────────────────────────────────────
    TOOLS_REGISTER = "tools:register"  # Generic — register for ANY project
    # Use Permissions.register(project_id) for project-specific:
    #   "tools:register:nszu" — register only for 'nszu' project

    # ── Admin ───────────────────────────────────────────
    ADMIN_READ = "admin:read"
    ADMIN_WRITE = "admin:write"
    ADMIN_TRACE = "admin:trace"
    ADMIN_ALL = "admin:all"

    # ── Builders ────────────────────────────────────────

    @staticmethod
    def tool(name: str, scope: str | None = None) -> str:
        """Build a permission string for a specific tool, optionally scoped.

        Args:
            name: Exact tool name as registered in discover_all_tools().
                  Examples: "brain_search", "shield_scan", "execute_sql"
            scope: Optional operation scope within the tool.
                   Use :class:`ToolScope` constants: ``"read"``, ``"write"``, ``"admin"``.
                   If None, grants full access to all scopes of that tool.

        Returns:
            Permission string:
            - ``"tool:sql"``        — full access (all scopes)
            - ``"tool:sql:read"``   — read-only scope
            - ``"tool:sql:write"``  — write scope (includes read)
            - ``"tool:sql:admin"``  — admin scope (destructive ops)

        Example::

            # Full access to a tool
            Permissions.tool("sql")            # "tool:sql"

            # Scoped access
            Permissions.tool("sql", "read")    # "tool:sql:read"  — SELECT only
            Permissions.tool("sql", "write")   # "tool:sql:write" — + INSERT/UPDATE
            Permissions.tool("sql", "admin")   # "tool:sql:admin" — + DELETE/DROP

            # In token minting
            builder.mint_root(permissions=[
                Permissions.tool("sql", "read"),      # SELECT only
                Permissions.tool("brain_search"),      # full access
                Permissions.tool("execute_cmd", "read"),# ls, cat only
            ])
        """
        if scope:
            return f"tool:{name}:{scope}"
        return f"tool:{name}"

    @staticmethod
    def graph(name: str) -> str:
        """Build a permission string for a specific graph by name.

        Args:
            name: Graph key as registered in graph_registry.
                  Examples: "rag_retrieval", "commerce_search", "dispatcher_agent"

        Returns:
            Permission string like ``"graph:rag_retrieval"``

        Example::

            builder.mint_root(permissions=[
                Permissions.graph("rag_retrieval"),
                Permissions.graph("commerce_search"),
            ])
        """
        return f"graph:{name}"

    @staticmethod
    def register(project_id: str) -> str:
        """Build a project-specific registration permission.

        Args:
            project_id: Project identifier (e.g. "nszu")

        Returns:
            Permission string like ``"tools:register:nszu"``

        Example::

            # Project-specific registration
            Permissions.register("nszu")  # "tools:register:nszu"

            # In token minting
            builder.mint_root(permissions=[
                Permissions.register("nszu"),  # Only nszu
            ])
        """
        return f"tools:register:{project_id}"

    @staticmethod
    def service(domain: str, action: str) -> str:
        """Build a permission string from domain and action.

        Args:
            domain: Service or resource namespace (e.g. "brain", "memory")
            action: Specific operation (e.g. "read", "write")

        Returns:
            Permission string like ``"brain:read"``
        """
        return f"{domain}:{action}"


class UserNamespace:
    """Access tier within a tenant.

    Not a permission — a scope boundary that maps to a default set
    of permissions via :data:`NAMESPACE_PROFILES`.
    """

    DEFAULT = "default"
    FREE = "free"
    PRO = "pro"
    ADMIN = "admin"
    SYSTEM = "system"

    ALL = frozenset({"default", "free", "pro", "admin", "system"})


__all__ = [
    "Permissions",
    "UserNamespace",
]
