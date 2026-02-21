"""Canonical permission registry and access tier profiles for ContextUnity.

Defines:
- Permissions: All permission string constants (domain:action format)
- UserNamespace: Access tier within a tenant (free/pro/admin/system)
- PERMISSION_INHERITANCE: Parent → children relationships
- NAMESPACE_PROFILES: User tier → default permission sets
- PROJECT_PROFILES: Common project configurations
- expand_permissions(): Resolve inherited permissions
"""

from .access import (
    check_tool_scope,
    extract_tool_names,
    has_graph_access,
    has_registration_access,
    has_tool_access,
    has_tool_scope_access,
)
from .constants import Permissions, UserNamespace
from .inheritance import (
    NAMESPACE_PROFILES,
    PERMISSION_INHERITANCE,
    PROJECT_PROFILES,
    expand_permissions,
)
from .policy import (
    DEFAULT_TOOL_POLICIES,
    ToolPolicy,
    ToolRisk,
    ToolScope,
)

__all__ = [
    "DEFAULT_TOOL_POLICIES",
    "NAMESPACE_PROFILES",
    "PERMISSION_INHERITANCE",
    "PROJECT_PROFILES",
    "Permissions",
    "ToolPolicy",
    "ToolRisk",
    "ToolScope",
    "UserNamespace",
    "check_tool_scope",
    "expand_permissions",
    "extract_tool_names",
    "has_graph_access",
    "has_registration_access",
    "has_tool_access",
    "has_tool_scope_access",
]
