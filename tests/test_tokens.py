"""Tests for ContextToken and TokenBuilder."""

from __future__ import annotations

import time

import pytest
from contextcore import ContextToken, ContextUnit, SecurityScopes, TokenBuilder


class TestContextToken:
    """Tests for ContextToken."""

    def test_create_token(self) -> None:
        """Test creating a ContextToken."""
        token = ContextToken(
            token_id="test_token",
            permissions=("read:data", "write:data"),
            exp_unix=None,
        )
        assert token.token_id == "test_token"
        assert "read:data" in token.permissions
        assert "write:data" in token.permissions
        assert token.exp_unix is None

    def test_token_not_expired(self) -> None:
        """Test token expiration check for non-expired token."""
        token = ContextToken(
            token_id="test",
            permissions=(),
            exp_unix=time.time() + 3600,  # 1 hour from now
        )
        assert not token.is_expired()

    def test_token_expired(self) -> None:
        """Test token expiration check for expired token."""
        token = ContextToken(
            token_id="test",
            permissions=(),
            exp_unix=time.time() - 3600,  # 1 hour ago
        )
        assert token.is_expired()

    def test_token_no_expiration(self) -> None:
        """Test token with no expiration."""
        token = ContextToken(
            token_id="test",
            permissions=(),
            exp_unix=None,
        )
        assert not token.is_expired()

    def test_has_permission(self) -> None:
        """Test checking token permissions."""
        token = ContextToken(
            token_id="test",
            permissions=("read:data", "write:data"),
        )
        assert token.has_permission("read:data")
        assert token.has_permission("write:data")
        assert not token.has_permission("delete:data")

    def test_can_read_empty_scopes(self) -> None:
        """Test can_read with empty scopes (allows all)."""
        token = ContextToken(
            token_id="test",
            permissions=("read:data",),
        )
        scopes = SecurityScopes(read=[], write=[])
        assert token.can_read(scopes)  # Empty scopes = no restrictions

    def test_can_read_with_matching_permission(self) -> None:
        """Test can_read with matching permission."""
        token = ContextToken(
            token_id="test",
            permissions=("read:data", "write:data"),
        )
        scopes = SecurityScopes(read=["read:data"], write=[])
        assert token.can_read(scopes)

    def test_can_read_without_matching_permission(self) -> None:
        """Test can_read without matching permission."""
        token = ContextToken(
            token_id="test",
            permissions=("read:other",),
        )
        scopes = SecurityScopes(read=["read:data"], write=[])
        assert not token.can_read(scopes)

    def test_can_write_empty_scopes(self) -> None:
        """Test can_write with empty scopes (allows all)."""
        token = ContextToken(
            token_id="test",
            permissions=("write:data",),
        )
        scopes = SecurityScopes(read=[], write=[])
        assert token.can_write(scopes)  # Empty scopes = no restrictions

    def test_can_write_with_matching_permission(self) -> None:
        """Test can_write with matching permission."""
        token = ContextToken(
            token_id="test",
            permissions=("write:data",),
        )
        scopes = SecurityScopes(read=[], write=["write:data"])
        assert token.can_write(scopes)

    def test_can_write_without_matching_permission(self) -> None:
        """Test can_write without matching permission."""
        token = ContextToken(
            token_id="test",
            permissions=("write:other",),
        )
        scopes = SecurityScopes(read=[], write=["write:data"])
        assert not token.can_write(scopes)

    def test_can_access_tenant_admin(self) -> None:
        """Admin token (empty allowed_tenants) can access any tenant."""
        token = ContextToken(
            token_id="admin",
            permissions=("dispatcher:execute",),
            allowed_tenants=(),  # admin
        )
        assert token.can_access_tenant("traverse") is True
        assert token.can_access_tenant("nszu") is True
        assert token.can_access_tenant("any_tenant") is True

    def test_can_access_tenant_scoped(self) -> None:
        """Scoped token can only access listed tenants."""
        token = ContextToken(
            token_id="traverse_token",
            permissions=("dispatcher:execute",),
            allowed_tenants=("traverse",),
        )
        assert token.can_access_tenant("traverse") is True
        assert token.can_access_tenant("nszu") is False
        assert token.can_access_tenant("pinkpony") is False

    def test_can_access_tenant_multi(self) -> None:
        """Token scoped to multiple tenants."""
        token = ContextToken(
            token_id="multi_token",
            permissions=("dispatcher:execute",),
            allowed_tenants=("traverse", "pinkpony"),
        )
        assert token.can_access_tenant("traverse") is True
        assert token.can_access_tenant("pinkpony") is True
        assert token.can_access_tenant("nszu") is False

    def test_can_access_tenant_empty_id_rejected(self) -> None:
        """Empty tenant_id is always rejected, even for admin tokens."""
        admin_token = ContextToken(
            token_id="admin",
            permissions=("dispatcher:execute",),
            allowed_tenants=(),
        )
        assert admin_token.can_access_tenant("") is False
        assert admin_token.can_access_tenant(None) is False


class TestTokenBuilder:
    """Tests for TokenBuilder."""

    def test_create_builder(self) -> None:
        """Test creating a TokenBuilder."""
        builder = TokenBuilder()
        assert builder.enabled is True

    def test_create_builder_disabled(self) -> None:
        """Test creating a disabled TokenBuilder."""
        builder = TokenBuilder(enabled=False)
        assert builder.enabled is False

    def test_mint_root_token(self) -> None:
        """Test minting a root token."""
        builder = TokenBuilder()
        token = builder.mint_root(
            user_ctx={"user_id": "123"},
            permissions=["read:data", "write:data"],
            ttl_s=3600,
        )
        assert isinstance(token, ContextToken)
        assert len(token.token_id) > 0
        assert "read:data" in token.permissions
        assert "write:data" in token.permissions
        assert token.exp_unix is not None
        assert token.exp_unix > time.time()

    def test_mint_root_token_with_tenants(self) -> None:
        """Test minting a root token with tenant restrictions."""
        builder = TokenBuilder()
        token = builder.mint_root(
            user_ctx={},
            permissions=["dispatcher:execute"],
            ttl_s=3600,
            allowed_tenants=["traverse", "pinkpony"],
        )
        assert token.allowed_tenants == ("traverse", "pinkpony")
        assert token.can_access_tenant("traverse") is True
        assert token.can_access_tenant("nszu") is False

    def test_attenuate_token_permissions(self) -> None:
        """Test attenuating token permissions."""
        builder = TokenBuilder()
        original = builder.mint_root(
            user_ctx={},
            permissions=["read:data", "write:data", "delete:data"],
            ttl_s=3600,
        )
        attenuated = builder.attenuate(
            original,
            permissions=["read:data"],  # Reduced permissions
        )
        assert attenuated.token_id == original.token_id
        assert "read:data" in attenuated.permissions
        assert "write:data" not in attenuated.permissions
        assert "delete:data" not in attenuated.permissions

    def test_attenuate_token_ttl(self) -> None:
        """Test attenuating token TTL."""
        builder = TokenBuilder()
        original = builder.mint_root(
            user_ctx={},
            permissions=["read:data"],
            ttl_s=3600,
        )
        attenuated = builder.attenuate(
            original,
            ttl_s=1800,  # Reduced TTL
        )
        assert attenuated.token_id == original.token_id
        assert attenuated.exp_unix is not None
        assert attenuated.exp_unix < original.exp_unix

    def test_verify_token_success(self) -> None:
        """Test verifying a valid token."""
        builder = TokenBuilder()
        token = builder.mint_root(
            user_ctx={},
            permissions=["read:data"],
            ttl_s=3600,
        )
        # Should not raise
        builder.verify(token, required_permission="read:data")

    def test_verify_token_missing_permission(self) -> None:
        """Test verifying token with missing permission."""
        builder = TokenBuilder()
        token = builder.mint_root(
            user_ctx={},
            permissions=["read:data"],
            ttl_s=3600,
        )
        with pytest.raises(PermissionError, match="Missing permission"):
            builder.verify(token, required_permission="write:data")

    def test_verify_token_expired(self) -> None:
        """Test verifying an expired token."""
        builder = TokenBuilder()
        token = ContextToken(
            token_id="test",
            permissions=("read:data",),
            exp_unix=time.time() - 1,  # Expired
        )
        with pytest.raises(PermissionError, match="Token expired"):
            builder.verify(token, required_permission="read:data")

    def test_verify_token_disabled_builder(self) -> None:
        """Test verification with disabled builder."""
        builder = TokenBuilder(enabled=False)
        # Should not raise even with invalid token
        builder.verify(
            ContextToken(token_id="test", permissions=(), exp_unix=time.time() - 1),
            required_permission="read:data",
        )

    def test_verify_unit_access_read(self) -> None:
        """Test verifying unit access for read operation."""
        builder = TokenBuilder()
        token = builder.mint_root(
            user_ctx={},
            permissions=["read:data"],
            ttl_s=3600,
        )
        unit = ContextUnit(
            security=SecurityScopes(read=["read:data"], write=["write:data"]),
        )
        # Should not raise
        builder.verify_unit_access(token, unit, operation="read")

    def test_verify_unit_access_write(self) -> None:
        """Test verifying unit access for write operation."""
        builder = TokenBuilder()
        token = builder.mint_root(
            user_ctx={},
            permissions=["write:data"],
            ttl_s=3600,
        )
        unit = ContextUnit(
            security=SecurityScopes(read=["read:data"], write=["write:data"]),
        )
        # Should not raise
        builder.verify_unit_access(token, unit, operation="write")

    def test_verify_unit_access_no_permission(self) -> None:
        """Test verifying unit access without permission."""
        builder = TokenBuilder()
        token = builder.mint_root(
            user_ctx={},
            permissions=["read:other"],
            ttl_s=3600,
        )
        unit = ContextUnit(
            security=SecurityScopes(read=["read:data"], write=["write:data"]),
        )
        with pytest.raises(PermissionError):
            builder.verify_unit_access(token, unit, operation="read")

    def test_verify_unit_access_empty_scopes(self) -> None:
        """Test verifying unit access with empty scopes (allows all)."""
        builder = TokenBuilder()
        token = builder.mint_root(
            user_ctx={},
            permissions=["read:data"],
            ttl_s=3600,
        )
        unit = ContextUnit(
            security=SecurityScopes(read=[], write=[]),  # Empty = no restrictions
        )
        # Should not raise
        builder.verify_unit_access(token, unit, operation="read")
        builder.verify_unit_access(token, unit, operation="write")


class TestTokenSigning:
    """Tests for token signing with UnsignedBackend and Ed25519."""

    def test_unsigned_roundtrip(self) -> None:
        """Unsigned token roundtrip preserves all fields in dev mode."""
        from contextcore.signing import UnsignedBackend
        from contextcore.token_utils import parse_token_string, serialize_token

        backend = UnsignedBackend()
        token = ContextToken(
            token_id="dev123",
            permissions=("dispatcher:execute", "brain:read"),
            allowed_tenants=("traverse", "pinkpony"),
            exp_unix=9999999999.0,
        )
        serialized = serialize_token(token, backend=backend)
        assert "." in serialized  # kid.payload.signature format

        parsed = parse_token_string(serialized, backend=backend)
        assert parsed is not None
        assert parsed.token_id == "dev123"
        assert parsed.permissions == ("dispatcher:execute", "brain:read")
        assert parsed.allowed_tenants == ("traverse", "pinkpony")
        assert parsed.exp_unix == 9999999999.0

    def test_unsigned_wire_format(self) -> None:
        """Unsigned tokens use kid.payload.signature format (3 parts)."""
        from contextcore.signing import UnsignedBackend
        from contextcore.token_utils import serialize_token

        backend = UnsignedBackend()
        token = ContextToken(
            token_id="test",
            permissions=("read:data",),
        )
        serialized = serialize_token(token, backend=backend)
        parts = serialized.split(".")
        assert len(parts) == 3  # kid.payload.signature
        assert parts[0] == "unsigned"  # kid = "unsigned"
        assert parts[2] == ""  # empty signature

    def test_unsigned_admin_token(self) -> None:
        """Admin token (empty allowed_tenants) serializes correctly."""
        from contextcore.signing import UnsignedBackend
        from contextcore.token_utils import parse_token_string, serialize_token

        backend = UnsignedBackend()
        token = ContextToken(
            token_id="admin",
            permissions=("dispatcher:execute",),
            allowed_tenants=(),  # Admin
        )
        serialized = serialize_token(token, backend=backend)
        parsed = parse_token_string(serialized, backend=backend)
        assert parsed is not None
        assert parsed.allowed_tenants == ()
        assert parsed.can_access_tenant("anything") is True


class TestTokenEdgeCases:
    """Edge-case tests for tokens (moved from test_error_handling.py)."""

    def test_token_expired_at_exact_boundary(self) -> None:
        """Token expiring at exactly time.time() should be expired."""
        import time

        token = ContextToken(
            token_id="boundary",
            permissions=(),
            exp_unix=time.time(),
        )
        assert token.is_expired()

    def test_mint_root_with_empty_permissions(self) -> None:
        """Minting with empty permissions should succeed."""
        builder = TokenBuilder()
        token = builder.mint_root(user_ctx={}, permissions=[], ttl_s=3600)
        assert len(token.permissions) == 0

    def test_mint_root_with_negative_ttl(self) -> None:
        """Negative TTL should produce an immediately-expired token."""
        builder = TokenBuilder()
        token = builder.mint_root(user_ctx={}, permissions=["read:data"], ttl_s=-100)
        assert token.exp_unix is not None
        assert token.is_expired()

    def test_verify_with_empty_permission_string(self) -> None:
        """Verifying with empty required_permission should raise."""
        builder = TokenBuilder()
        token = builder.mint_root(user_ctx={}, permissions=["read:data"], ttl_s=3600)
        with pytest.raises(PermissionError):
            builder.verify(token, required_permission="")

    def test_verify_unit_access_invalid_operation(self) -> None:
        """Invalid operation should raise ValueError."""
        builder = TokenBuilder()
        token = builder.mint_root(user_ctx={}, permissions=["read:data"], ttl_s=3600)
        from contextcore import ContextUnit, SecurityScopes

        unit = ContextUnit(security=SecurityScopes(read=["read:data"]))
        with pytest.raises(ValueError, match="Invalid operation"):
            builder.verify_unit_access(token, unit, operation="invalid")

    def test_can_read_with_no_permissions(self) -> None:
        """Token with no permissions cannot satisfy non-empty read scopes."""
        from contextcore import SecurityScopes

        token = ContextToken(token_id="empty", permissions=())
        scopes = SecurityScopes(read=["read:data"])
        assert not token.can_read(scopes)

    def test_can_write_with_no_permissions(self) -> None:
        """Token with no permissions cannot satisfy non-empty write scopes."""
        from contextcore import SecurityScopes

        token = ContextToken(token_id="empty", permissions=())
        scopes = SecurityScopes(write=["write:data"])
        assert not token.can_write(scopes)
