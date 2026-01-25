"""Access control + token primitives (ContextUnit protocol).

ContextToken provides authorization for ContextUnit operations.
It integrates with ContextUnit.security (SecurityScopes) for capability-based access control.

This is the canonical implementation of ContextToken for the ContextUnit protocol.
All services (contextbrain, contextrouter, contextcommerce) should import from here.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Literal

from .sdk import ContextUnit, SecurityScopes


@dataclass(frozen=True)
class ContextToken:
    """Authorization token for ContextUnit operations.
    
    ContextToken provides:
    - token_id: Unique identifier for audit trails
    - permissions: List of capability strings (e.g., "catalog:read", "product:write")
    - exp_unix: Expiration timestamp (None = no expiration)
    
    The token's permissions are validated against ContextUnit.security.scopes
    to enforce capability-based access control.
    """

    token_id: str
    permissions: tuple[str, ...] = ()
    exp_unix: float | None = None

    def is_expired(self, *, now: float | None = None) -> bool:
        """Check if token has expired."""
        if self.exp_unix is None:
            return False
        t = time.time() if now is None else now
        return t >= self.exp_unix

    def has_permission(self, permission: str) -> bool:
        """Check if token has a specific permission."""
        return permission in self.permissions

    def can_read(self, scopes: SecurityScopes) -> bool:
        """Check if token can read from the given security scopes.
        
        Returns True if:
        - Any token permission matches any read scope, OR
        - Read scopes are empty (no restrictions)
        """
        if not scopes.read:
            return True  # No restrictions
        return any(perm in scopes.read for perm in self.permissions)

    def can_write(self, scopes: SecurityScopes) -> bool:
        """Check if token can write to the given security scopes.
        
        Returns True if:
        - Any token permission matches any write scope, OR
        - Write scopes are empty (no restrictions)
        """
        if not scopes.write:
            return True  # No restrictions
        return any(perm in scopes.write for perm in self.permissions)


class TokenBuilder:
    """Token minting + attenuation + verification.

    Part of the ContextUnit protocol. Creates and validates ContextToken instances
    that integrate with ContextUnit.security for capability-based access control.
    
    Note: This is a minimal implementation. Services may extend this with
    service-specific configuration (e.g., Config, private keys).
    """

    def __init__(self, *, enabled: bool = True, private_key_path: str | None = None) -> None:
        self._enabled = enabled
        self._private_key_path = private_key_path

    @property
    def enabled(self) -> bool:
        return self._enabled

    def mint_root(
        self, *, user_ctx: dict[str, Any], permissions: Iterable[str], ttl_s: float
    ) -> ContextToken:
        """Create a new root token with specified permissions.
        
        Args:
            user_ctx: User context (reserved for future datalog facts)
            permissions: Capability strings (e.g., ["catalog:read", "product:write"])
            ttl_s: Time-to-live in seconds
            
        Returns:
            New ContextToken instance
        """
        _ = user_ctx  # reserved for future datalog facts
        token_id = secrets.token_urlsafe(16)
        exp_unix = time.time() + float(ttl_s)
        return ContextToken(token_id=token_id, permissions=tuple(permissions), exp_unix=exp_unix)

    def attenuate(
        self,
        token: ContextToken,
        *,
        permissions: Iterable[str] | None = None,
        ttl_s: float | None = None,
    ) -> ContextToken:
        """Create a new token with reduced permissions (attenuation).
        
        Args:
            token: Original token to attenuate
            permissions: New permission set (None = keep original)
            ttl_s: New TTL (None = keep original)
            
        Returns:
            New ContextToken with attenuated permissions
        """
        exp_unix = token.exp_unix
        if ttl_s is not None:
            exp_unix = min(exp_unix or (time.time() + ttl_s), time.time() + ttl_s)
        perms = token.permissions if permissions is None else tuple(permissions)
        return ContextToken(token_id=token.token_id, permissions=perms, exp_unix=exp_unix)

    def verify(self, token: ContextToken, *, required_permission: str) -> None:
        """Verify token has required permission.
        
        Raises:
            PermissionError: If token is missing, expired, or lacks permission
        """
        if not self._enabled:
            return
        if not isinstance(token, ContextToken):
            raise PermissionError("Missing token")
        if token.is_expired():
            raise PermissionError("Token expired")
        if required_permission not in token.permissions:
            raise PermissionError(f"Missing permission: {required_permission}")

    def verify_unit_access(self, token: ContextToken, unit: ContextUnit, *, operation: Literal["read", "write"] = "read") -> None:
        """Verify token can access ContextUnit based on its security scopes.
        
        Args:
            token: ContextToken to verify
            unit: ContextUnit to check access for
            operation: "read" or "write"
            
        Raises:
            PermissionError: If token cannot access the unit
        """
        if not self._enabled:
            return
        
        if not isinstance(token, ContextToken):
            raise PermissionError("Missing token")
        if token.is_expired():
            raise PermissionError("Token expired")
        
        scopes = unit.security
        if operation == "read":
            if not token.can_read(scopes):
                raise PermissionError(
                    f"Token lacks read permission for unit scopes: {scopes.read}"
                )
        elif operation == "write":
            if not token.can_write(scopes):
                raise PermissionError(
                    f"Token lacks write permission for unit scopes: {scopes.write}"
                )
        else:
            raise ValueError(f"Invalid operation: {operation}")


__all__ = ["ContextToken", "TokenBuilder"]
