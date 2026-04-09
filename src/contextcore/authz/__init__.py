"""Unified authorization for ContextUnity.

Public API::

    from contextcore.authz import (
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

__all__ = [
    "AccessManager",
    "AuthzDecision",
    "VerifiedAuthContext",
    "authorize",
    "get_auth_context",
    "require_auth_context",
    "reset_auth_context",
    "set_auth_context",
]
