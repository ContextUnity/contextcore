"""Canonical AccessManager — unified authorization gate for providers/sinks.

Replaces the duplicated AccessManager implementations that existed in both
``contextbrain.core.tokens`` and ``contextrouter.core.tokens``.

The canonical version lives here in ``contextcore.authz`` and does NOT depend
on any service-specific Config. Service modules pass their read/write
permission defaults at construction time.

Usage::

    from contextcore.authz.access_manager import AccessManager

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

from ..tokens import ContextToken, TokenBuilder

# TYPE_CHECKING import for ContextUnit
try:
    from ..sdk import ContextUnit
except ImportError:
    ContextUnit = None  # type: ignore[misc,assignment]


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
    token_builder: TokenBuilder = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.token_builder is None:
            object.__setattr__(self, "token_builder", TokenBuilder())

    def verify_read(self, token: ContextToken, *, permission: str | None = None) -> None:
        """Verify read permission.

        Args:
            token: Token to verify.
            permission: Explicit permission override. Falls back to ``self.read_permission``.

        Raises:
            PermissionError: If token is None, expired, or lacks permission.
        """
        required = (
            str(permission).strip() if isinstance(permission, str) and str(permission).strip() else self.read_permission
        )
        self.token_builder.verify(token, required_permission=required)

    def verify_write(self, token: ContextToken, *, permission: str | None = None) -> None:
        """Verify write permission.

        Args:
            token: Token to verify.
            permission: Explicit permission override. Falls back to ``self.write_permission``.

        Raises:
            PermissionError: If token is None, expired, or lacks permission.
        """
        required = (
            str(permission).strip()
            if isinstance(permission, str) and str(permission).strip()
            else self.write_permission
        )
        self.token_builder.verify(token, required_permission=required)

    def verify_unit_read(self, unit: "ContextUnit", token: ContextToken) -> None:
        """Verify token can read from ContextUnit based on security scopes."""
        self.verify_read(token)

        if unit.security.read or unit.security.write:
            self.token_builder.verify_unit_access(token, unit, operation="read")

    def verify_unit_write(self, unit: "ContextUnit", token: ContextToken) -> None:
        """Verify write permission with audit-trail token_id binding.

        Also validates token against unit.security scopes for capability-based
        access control.
        """
        self.verify_write(token)

        # Security is always enforced.
        payload = unit.payload or {}
        env_token_id = payload.get("token_id")
        tok_token_id = token.token_id

        # If the token has an id, ensure the unit carries it for audit trails.
        if tok_token_id and env_token_id is None:
            if unit.payload is None:
                unit.payload = {}
            unit.payload["token_id"] = tok_token_id
            env_token_id = tok_token_id

        if not env_token_id:
            raise PermissionError("write denied: ContextUnit.payload.token_id is required when security is enabled")
        if tok_token_id and env_token_id != tok_token_id:
            raise PermissionError("write denied: ContextUnit.payload.token_id does not match the provided token")

        # Validate against security scopes
        if unit.security.read or unit.security.write:
            self.token_builder.verify_unit_access(token, unit, operation="write")


__all__ = ["AccessManager"]
