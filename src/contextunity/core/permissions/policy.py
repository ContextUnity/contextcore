"""Tool scope and policy system for fine-grained tool access control.
Provides:
- ``ToolScope`` — operation granularity (read / write / admin).
- ``ToolRisk`` — risk classification (safe / confirm / deny).
- ``ToolPolicy`` — per-tool risk mapping.
- ``DEFAULT_TOOL_POLICIES`` — sensible defaults for common tools.
"""

from __future__ import annotations

from typing import ClassVar, Final, override


class ToolScope:
    """Operation scope within a tool.

    Permission format: ``tool:{name}:{scope}``
    Example: ``tool:sql:read``, ``tool:execute_cmd:write``

    Scope hierarchy: ``admin`` > ``write`` > ``read``
    Higher scope implies all lower scopes.
    """

    READ: ClassVar[str] = "read"
    WRITE: ClassVar[str] = "write"
    ADMIN: ClassVar[str] = "admin"

    HIERARCHY: ClassVar[tuple[str, ...]] = ("read", "write", "admin")


class ToolRisk:
    """Risk classification for a tool operation.

    Determines what happens when an operation at a given scope is attempted.
    """

    SAFE: ClassVar[str] = "safe"
    CONFIRM: ClassVar[str] = "confirm"
    DENY: ClassVar[str] = "deny"


class ToolPolicy:
    """Defines risk classification per scope for a tool.

    Controls SHOULD (safety gate), not CAN (authorization).
    A token may grant ``tool:sql:write`` permission, but the policy
    can still require HITL confirmation for write operations.

    Args:
        tool_name: Name of the tool this policy applies to.
        scope_risk: Mapping of scope → risk level.
        denied_patterns: Regex patterns that always block (regardless of scope).

    Example::

        sql_policy = ToolPolicy(
            tool_name="sql",
            scope_risk={
                ToolScope.READ:  ToolRisk.SAFE,     # SELECT → auto-execute
                ToolScope.WRITE: ToolRisk.CONFIRM,  # INSERT/UPDATE → HITL
                ToolScope.ADMIN: ToolRisk.DENY,      # DELETE/DROP → blocked
            },
        )

        cmd_policy = ToolPolicy(
            tool_name="execute_cmd",
            scope_risk={
                ToolScope.READ:  ToolRisk.SAFE,     # ls, cat, grep
                ToolScope.WRITE: ToolRisk.CONFIRM,  # sed, mv, cp
                ToolScope.ADMIN: ToolRisk.DENY,      # rm, chmod, chown
            },
            denied_patterns=(r"rm\\\\s+-rf", r":\\\\(\\\\)\\\\{"),  # Always block
        )
    """

    __slots__: Final[tuple[str, ...]] = ("tool_name", "scope_risk", "denied_patterns")

    tool_name: str
    scope_risk: dict[str, str]
    denied_patterns: tuple[str, ...]

    def __init__(
        self,
        *,
        tool_name: str,
        scope_risk: dict[str, str] | None = None,
        denied_patterns: tuple[str, ...] = (),
    ) -> None:
        """Initialize a new instance of ToolPolicy.

        Args:
            tool_name: Name of the tool this policy applies to.
            scope_risk: Mapping of scope to risk level. Defaults to
                read=safe, write=confirm, admin=deny.
            denied_patterns: Optional tuple of regular expression patterns
                that will trigger automatic denial.
        """
        self.tool_name = tool_name
        self.scope_risk = scope_risk or {
            ToolScope.READ: ToolRisk.SAFE,
            ToolScope.WRITE: ToolRisk.CONFIRM,
            ToolScope.ADMIN: ToolRisk.DENY,
        }
        self.denied_patterns = denied_patterns

    def risk_for_scope(self, scope: str) -> str:
        """Get risk level for a given scope.

        Args:
            scope: The execution scope (e.g., "read", "write", "admin").

        Returns:
            str: The risk level (e.g., "safe", "confirm", "deny").
        """
        return self.scope_risk.get(scope, ToolRisk.DENY)

    @override
    def __repr__(self) -> str:
        """Return a string representation of the ToolPolicy instance.

        Returns:
            str: A string representing the ToolPolicy.
        """
        return f"ToolPolicy(tool_name={self.tool_name!r}, scope_risk={self.scope_risk!r})"


# ── Default Tool Policies ──────────────────────────────
# Kept in contextunity.core as sensible defaults. Services can override.

DEFAULT_TOOL_POLICIES: dict[str, ToolPolicy] = {
    "sql": ToolPolicy(
        tool_name="sql",
        scope_risk={
            ToolScope.READ: ToolRisk.SAFE,  # SELECT → auto-execute
            ToolScope.WRITE: ToolRisk.CONFIRM,  # INSERT/UPDATE → HITL
            ToolScope.ADMIN: ToolRisk.DENY,  # DELETE/DROP → blocked
        },
    ),
    "execute_cmd": ToolPolicy(
        tool_name="execute_cmd",
        scope_risk={
            ToolScope.READ: ToolRisk.SAFE,  # ls, cat, grep → auto
            ToolScope.WRITE: ToolRisk.CONFIRM,  # sed, mv → HITL
            ToolScope.ADMIN: ToolRisk.DENY,  # rm, chmod → blocked
        },
        denied_patterns=(r"rm\s+-rf", r":\(\)\{"),
    ),
    "file": ToolPolicy(
        tool_name="file",
        scope_risk={
            ToolScope.READ: ToolRisk.SAFE,  # read file → auto
            ToolScope.WRITE: ToolRisk.CONFIRM,  # write file → HITL
            ToolScope.ADMIN: ToolRisk.DENY,  # delete file → blocked
        },
    ),
}

__all__ = [
    "DEFAULT_TOOL_POLICIES",
    "ToolPolicy",
    "ToolRisk",
    "ToolScope",
]
