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
    ROUTER_EXECUTE: str = "router:execute"
    ROUTER_EXECUTE_NODE: str = "router:execute_node"
    ROUTER_INTROSPECT: str = "router:introspect"
    BRAIN_READ: str = "brain:read"
    BRAIN_WRITE: str = "brain:write"
    BRAIN_EMBED: str = "brain:embed"
    DOCS_READ: str = "docs:read"
    DOCS_WRITE: str = "docs:write"
    SHIELD_CHECK: str = "shield:check"
    SHIELD_SESSION_TOKEN_ISSUE: str = "shield:session_token:issue"
    SHIELD_PROJECT_KEY_READ: str = "shield:project_key:read"
    SHIELD_PROJECT_KEY_ROTATE: str = "shield:project_key:rotate"
    SHIELD_POLICY_WRITE: str = "shield:policy:write"
    SHIELD_SECRETS_READ: str = "shield:secrets:read"
    SHIELD_SECRETS_WRITE: str = "shield:secrets:write"
    SHIELD_TRACE_ARTIFACT_PROTECT: str = "shield:trace_artifacts:protect"
    # Privacy is in-Router. ``secure_node`` attenuates request tokens down to
    # these scopes when manifest nodes enable PII masking.
    PRIVACY_ALL: str = "privacy:*"
    PRIVACY_ANONYMIZE: str = "privacy:anonymize"
    PRIVACY_DEANONYMIZE: str = "privacy:deanonymize"
    PRIVACY_CHECK_PII: str = "privacy:check_pii"
    PRIVACY_AUDIT: str = "privacy:audit"
    WORKER_SCHEDULE: str = "worker:schedule"
    WORKER_EXECUTE: str = "worker:execute"
    WORKER_READ: str = "worker:read"
    WORKER_TRACE_ARTIFACT_ARCHIVE: str = "worker:trace_artifacts:archive"

    # ── Graph Access ────────────────────────────────────
    GRAPH_RAG: str = "graph:rag"
    GRAPH_COMMERCE: str = "graph:commerce"
    GRAPH_NEWS: str = "graph:news"
    GRAPH_MEDICAL: str = "graph:medical"
    GRAPH_DISPATCHER: str = "graph:dispatcher"
    GRAPH_ALL: str = "graph:*"  # Wildcard — access to all graphs

    # ── Memory & Trace ──────────────────────────────────
    MEMORY_READ: str = "memory:read"
    MEMORY_WRITE: str = "memory:write"
    CONVERSATION_READ: str = "conversation:read"
    TRACE_WRITE: str = "trace:write"
    TRACE_READ: str = "trace:read"
    TRACE_ARTIFACT_READ: str = "trace:artifacts:read"
    TRACE_ARTIFACT_LIFECYCLE: str = "trace:artifacts:lifecycle"

    # ── Tool Access ─────────────────────────────────────
    # Common categories (shortcuts for well-known tools)
    TOOL_BRAIN_SEARCH: str = "tool:brain_search"
    TOOL_WEB_SEARCH: str = "tool:web_search"
    TOOL_MEMORY: str = "tool:memory"
    TOOL_SQL: str = "tool:sql"
    TOOL_FILE: str = "tool:file"
    TOOL_API: str = "tool:api"
    TOOL_ALL: str = "tool:*"  # Wildcard — access to all tools

    # ── Registration ────────────────────────────────────
    TOOLS_REGISTER: str = "tools:register"  # Generic — register for ANY project
    # Use Permissions.register(project_id) for project-specific:
    #   "tools:register:nszu" — register only for 'nszu' project

    # ── Admin ───────────────────────────────────────────
    ADMIN_READ: str = "admin:read"
    ADMIN_WRITE: str = "admin:write"
    ADMIN_TRACE: str = "admin:trace"
    ADMIN_ALL: str = "admin:all"

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
            str: Permission string:
                - ``"tool:sql"``        — full access (all scopes)
                - ``"tool:sql:read"``   — read-only scope
                - ``"tool:sql:write"``  — write scope (includes read)
                - ``"tool:sql:admin"``  — admin scope (destructive ops)

        Examples:
            >>> Permissions.tool("sql")
            'tool:sql'
            >>> Permissions.tool("sql", "read")
            'tool:sql:read'
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
            str: Permission string like ``"graph:rag_retrieval"``.

        Examples:
            >>> Permissions.graph("rag_retrieval")
            'graph:rag_retrieval'
        """
        return f"graph:{name}"

    @staticmethod
    def register(project_id: str) -> str:
        """Build a project-specific registration permission.

        Args:
            project_id: Project identifier (e.g., "nszu").

        Returns:
            str: Permission string like ``"tools:register:nszu"``.

        Examples:
            >>> Permissions.register("nszu")
            'tools:register:nszu'
        """
        return f"tools:register:{project_id}"

    @staticmethod
    def introspect(project_id: str) -> str:
        """Build a project-specific manifest introspection permission.

        Args:
            project_id: Registered project identifier (e.g., ``"nszu"``).

        Returns:
            str: Permission string like ``"router:introspect:nszu"``.
        """
        return f"router:introspect:{project_id}"

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

    DEFAULT: str = "default"
    FREE: str = "free"
    PRO: str = "pro"
    ADMIN: str = "admin"
    SYSTEM: str = "system"

    ALL: frozenset[str] = frozenset({"default", "free", "pro", "admin", "system"})


__all__ = [
    "Permissions",
    "UserNamespace",
]
