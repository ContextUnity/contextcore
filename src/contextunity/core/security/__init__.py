"""Unified security integration for ContextUnity services.

This package provides a single integration point that services use for:
1. **Token validation** (always available via contextunity.core)
2. **Shield firewall** (auto-activates when contextunity.shield is installed)
3. **gRPC interceptors** (unified, parameterised permission enforcement)

Usage (in any service)::

    from contextunity.core.security import ServicePermissionInterceptor

"""

from __future__ import annotations

from .interceptors import (
    ServicePermissionInterceptor,
    _extract_rpc_name,
    _should_skip,
    check_permission,
)
from .utils import validate_safe_url

__all__ = [
    # Permission check
    "check_permission",
    # Interceptors
    "ServicePermissionInterceptor",
    "_extract_rpc_name",
    "_should_skip",
    # Utils
    "validate_safe_url",
]
