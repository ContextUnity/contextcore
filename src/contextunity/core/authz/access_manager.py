"""Canonical AccessManager — unified authorization gate for providers/sinks.

Replaces the duplicated AccessManager implementations that existed in both
``contextunity.brain.core.tokens`` and ``contextunity.router.core.tokens``.

The canonical version lives here in ``contextunity.core.authz`` and does NOT depend
on any service-specific Config. Service modules pass their read/write
permission defaults at construction time.

Usage::

    from contextunity.core.authz.access_manager import AccessManager

    # Service-specific construction (in brain/router __init__.py or helpers.py)
    access = AccessManager(
        read_permission="brain:read",
        write_permission="brain:write",
    )
    access.verify_read(token)
    access.verify_unit_write(unit, token)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..exceptions import SecurityError
from ..sdk.payload import get_optional_str
from ..tokens import ContextToken, TokenBuilder

if TYPE_CHECKING:
    from ..sdk import ContextUnit


@dataclass(frozen=True)
class AccessManager:
    """Canonical authorization gate for providers/sinks.

    All authorization decisions delegate to ``TokenBuilder`` (which uses
    inheritance-aware ``has_permission()`` since Step 2).

    Args:
        read_permission: Default permission for read operations.
        write_permission: Default permission for write operations.
        token_builder: TokenBuilder instance (created automatically if None).
    """

    read_permission: str = "brain:read"
    write_permission: str = "brain:write"
    token_builder: TokenBuilder | None = None

    def __post_init__(self) -> None:
        if self.token_builder is None:
            object.__setattr__(self, "token_builder", TokenBuilder())

    def verify_read(self, token: ContextToken, *, permission: str | None = None) -> None:
        """Verify read permission.

        Args:
            token: Token to verify.
            permission: Explicit permission override. Falls back to ``self.read_permission``.

        Raises:
            SecurityError: If token is None, expired, or lacks permission.
        """
        required = permission.strip() if isinstance(permission, str) and permission.strip() else self.read_permission
        token_builder = self.token_builder
        if token_builder is None:
            raise SecurityError("read denied: token builder is not configured")
        token_builder.verify(token, required_permission=required)

    def verify_write(self, token: ContextToken, *, permission: str | None = None) -> None:
        """Verify write permission.

        Args:
            token: Token to verify.
            permission: Explicit permission override. Falls back to ``self.write_permission``.

        Raises:
            SecurityError: If token is None, expired, or lacks permission.
        """
        required = permission.strip() if isinstance(permission, str) and permission.strip() else self.write_permission
        token_builder = self.token_builder
        if token_builder is None:
            raise SecurityError("write denied: token builder is not configured")
        token_builder.verify(token, required_permission=required)

    def verify_unit_read(self, unit: ContextUnit, token: ContextToken) -> None:
        """Verify that a token is authorized to read the given ContextUnit.

        Checks general read permissions first, then verifies the token against
        the ContextUnit's read security scopes if they are set.

        Args:
            unit: The ContextUnit to verify read access for.
            token: The ContextToken authorizing the read operation.

        Raises:
            SecurityError: If token is None, expired, or lacks read permission for the unit.
        """
        self.verify_read(token)

        if unit.security.read or unit.security.write:
            token_builder = self.token_builder
            if token_builder is None:
                raise SecurityError("read denied: token builder is not configured")
            token_builder.verify_unit_access(token, unit, operation="read")

    def verify_unit_write(self, unit: ContextUnit, token: ContextToken) -> None:
        """Verify that a token is authorized to write to the given ContextUnit.

        Checks general write permissions first, binds the token's ID to the
        ContextUnit payload for auditing, and verifies the token against the
        ContextUnit's write security scopes if they are set.

        Args:
            unit: The ContextUnit to verify write access for.
            token: The ContextToken authorizing the write operation.

        Raises:
            SecurityError: If the token is None, expired, lacks write permission, or if there is
                a mismatch/missing token_id on the ContextUnit's payload.
        """
        self.verify_write(token)

        # Security is always enforced.
        env_token_id = get_optional_str(unit.payload, "token_id")
        tok_token_id = token.token_id

        # If the token has an id, ensure the unit carries it for audit trails.
        if tok_token_id and env_token_id is None:
            unit.payload["token_id"] = tok_token_id
            env_token_id = tok_token_id

        if not env_token_id:
            raise SecurityError("write denied: ContextUnit.payload.token_id is required when security is enabled")
        if tok_token_id and env_token_id != tok_token_id:
            raise SecurityError("write denied: ContextUnit.payload.token_id does not match the provided token")

        # Validate against security scopes
        if unit.security.read or unit.security.write:
            token_builder = self.token_builder
            if token_builder is None:
                raise SecurityError("write denied: token builder is not configured")
            token_builder.verify_unit_access(token, unit, operation="write")


__all__ = ["AccessManager"]
