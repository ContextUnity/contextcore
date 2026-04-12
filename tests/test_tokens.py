"""Tests for ContextToken and TokenBuilder."""

from __future__ import annotations

import time

import pytest
from contextunity.core import ContextToken, ContextUnit, SecurityScopes, TokenBuilder


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
            permissions=("router:execute",),
            allowed_tenants=(),  # admin
        )
        assert token.can_access_tenant("tenant_b") is True
        assert token.can_access_tenant("tenant_a") is True
        assert token.can_access_tenant("any_tenant") is True

    def test_can_access_tenant_scoped(self) -> None:
        """Scoped token can only access listed tenants."""
        token = ContextToken(
            token_id="traverse_token",
            permissions=("router:execute",),
            allowed_tenants=("tenant_b",),
        )
        assert token.can_access_tenant("tenant_b") is True
        assert token.can_access_tenant("tenant_a") is False
        assert token.can_access_tenant("tenant_c") is False

    def test_can_access_tenant_multi(self) -> None:
        """Token scoped to multiple tenants."""
        token = ContextToken(
            token_id="multi_token",
            permissions=("router:execute",),
            allowed_tenants=("tenant_b", "tenant_c"),
        )
        assert token.can_access_tenant("tenant_b") is True
        assert token.can_access_tenant("tenant_c") is True
        assert token.can_access_tenant("tenant_a") is False

    def test_can_access_tenant_empty_id_rejected(self) -> None:
        """Empty tenant_id is always rejected, even for admin tokens."""
        admin_token = ContextToken(
            token_id="admin",
            permissions=("router:execute",),
            allowed_tenants=(),
        )
        assert admin_token.can_access_tenant("") is False
        assert admin_token.can_access_tenant(None) is False


class TestTokenBuilder:
    """Tests for TokenBuilder."""

    def test_create_builder(self) -> None:
        """Test creating a TokenBuilder."""
        builder = TokenBuilder()
        assert isinstance(builder, TokenBuilder)

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
            permissions=["router:execute"],
            ttl_s=3600,
            allowed_tenants=["tenant_b", "tenant_c"],
        )
        assert token.allowed_tenants == ("tenant_b", "tenant_c")
        assert token.can_access_tenant("tenant_b") is True
        assert token.can_access_tenant("tenant_a") is False

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

    def test_verify_always_enforced(self) -> None:
        """Test that verify always enforces — security has no opt-out."""
        builder = TokenBuilder()
        with pytest.raises(PermissionError, match="Token expired"):
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
        from contextunity.core import ContextUnit, SecurityScopes

        unit = ContextUnit(security=SecurityScopes(read=["read:data"]))
        with pytest.raises(ValueError, match="Invalid operation"):
            builder.verify_unit_access(token, unit, operation="invalid")

    def test_can_read_with_no_permissions(self) -> None:
        """Token with no permissions cannot satisfy non-empty read scopes."""
        from contextunity.core import SecurityScopes

        token = ContextToken(token_id="empty", permissions=())
        scopes = SecurityScopes(read=["read:data"])
        assert not token.can_read(scopes)

    def test_can_write_with_no_permissions(self) -> None:
        """Token with no permissions cannot satisfy non-empty write scopes."""
        from contextunity.core import SecurityScopes

        token = ContextToken(token_id="empty", permissions=())
        scopes = SecurityScopes(write=["write:data"])
        assert not token.can_write(scopes)

    def test_mint_root_populates_provenance(self) -> None:
        """Test minting a root token correctly sets initial agent provenance."""
        builder = TokenBuilder()
        token = builder.mint_root(user_ctx={}, permissions=["router:execute"], ttl_s=3600, agent_id="test_agent")
        assert token.provenance == ("*test_agent",)

        token_default = builder.mint_root(
            user_ctx={},
            permissions=[],
            ttl_s=3600,
        )
        assert token_default.provenance == ("*system",)

    def test_attenuate_appends_provenance(self) -> None:
        """Test attenuation correctly appends the delegation chain to provenance."""
        builder = TokenBuilder()
        root_token = builder.mint_root(
            user_ctx={}, permissions=["router:execute", "brain:write"], ttl_s=3600, agent_id="router_agent"
        )
        assert root_token.provenance == ("*router_agent",)

        # Attenuating without changing agent_id does NOT append to provenance
        same_agent = builder.attenuate(root_token, permissions=["brain:write"])
        assert same_agent.provenance == ("*router_agent",)

        # Changing agent_id DOES append to provenance
        delegated_token = builder.attenuate(root_token, permissions=["brain:write"], agent_id="tool_agent")
        assert delegated_token.provenance == ("*router_agent", ">tool_agent")
        assert delegated_token.agent_id == "tool_agent"
