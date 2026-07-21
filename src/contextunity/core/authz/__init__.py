"""Unified authorization for ContextUnity.

Public API::

    from contextunity.core.authz import (
        # Engine
        authorize,
        AuthzDecision,
        # Context
        VerifiedAuthContext,
        get_auth_context,
        set_auth_context,
        require_auth_context,
        reset_auth_context,
    )
"""

from .access_manager import AccessManager
from .context import (
    VerifiedAuthContext,
    get_auth_context,
    require_auth_context,
    reset_auth_context,
    set_auth_context,
)
from .engine import AuthzDecision, authorize
from .tenant import resolve_single_tenant_scope, resolve_token_tenant

__all__ = [
    "AccessManager",
    "AuthzDecision",
    "VerifiedAuthContext",
    "authorize",
    "get_auth_context",
    "require_auth_context",
    "reset_auth_context",
    "resolve_single_tenant_scope",
    "resolve_token_tenant",
    "set_auth_context",
]
