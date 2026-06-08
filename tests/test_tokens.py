"""Tests for ContextToken and TokenBuilder."""

from __future__ import annotations

import time

import pytest
from contextunity.core import ContextToken, ContextUnit, SecurityScopes, TokenBuilder
from contextunity.core.exceptions import ConfigurationError


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

    @pytest.mark.parametrize(
        ("perms", "scope_read", "scope_write", "op", "expected"),
        [
            (("read:data",), [], [], "read", True),
            (("read:data", "write:data"), ["read:data"], [], "read", True),
            (("read:other",), ["read:data"], [], "read", False),
            (("write:data",), [], [], "write", True),
            (("write:data",), [], ["write:data"], "write", True),
            (("write:other",), [], ["write:data"], "write", False),
            ((), ["read:data"], [], "read", False),
            ((), [], ["write:data"], "write", False),
        ],
        ids=[
            "read-empty-scope",
            "read-match",
            "read-nomatch",
            "write-empty-scope",
            "write-match",
            "write-nomatch",
            "read-no-perms",
            "write-no-perms",
        ],
    )
    def test_scope_access(self, perms, scope_read, scope_write, op, expected) -> None:
        """Token scope checks: can_read/can_write with various permission combinations."""
        token = ContextToken(token_id="test", permissions=perms)
        scopes = SecurityScopes(read=scope_read, write=scope_write)
        result = token.can_read(scopes) if op == "read" else token.can_write(scopes)
        assert result is expected

    @pytest.mark.parametrize(
        ("allowed_tenants", "tenant_id", "expected"),
        [
            ((), "tenant_b", False),
            ((), "any_tenant", False),
            (("tenant_b",), "tenant_b", True),
            (("tenant_b",), "tenant_a", False),
            (("tenant_b", "tenant_c"), "tenant_c", True),
            (("tenant_b", "tenant_c"), "tenant_a", False),
            ((), "", False),
            ((), None, False),
        ],
        ids=[
            "empty-scope",
            "empty-scope2",
            "scoped-match",
            "scoped-nomatch",
            "multi-match",
            "multi-nomatch",
            "empty-id",
            "none-id",
        ],
    )
    def test_can_access_tenant(self, allowed_tenants, tenant_id, expected) -> None:
        """Tenant isolation requires explicit tenant scope or admin:all."""
        token = ContextToken(
            token_id="t",
            permissions=("router:execute",),
            allowed_tenants=allowed_tenants,
        )
        assert token.can_access_tenant(tenant_id) is expected

    def test_admin_all_can_access_any_tenant(self) -> None:
        token = ContextToken(token_id="admin", permissions=("admin:all",))

        assert token.can_access_tenant("tenant_a") is True


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
        assert token.revocation_id is not None
        assert token.revocation_id.startswith("rev-")

    def test_revocation_id_uniqueness(self) -> None:
        """Each minted token gets a unique revocation ID."""
        builder = TokenBuilder()
        t1 = builder.mint_root(user_ctx={}, permissions=[], ttl_s=60)
        t2 = builder.mint_root(user_ctx={}, permissions=[], ttl_s=60)
        assert t1.revocation_id != t2.revocation_id

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
        with pytest.raises(ConfigurationError, match="Invalid operation"):
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


class TestMintRootDefaults:
    """Structural assertions for mint_root defaults."""

    def test_defaults(self) -> None:
        """Verify all default values from mint_root in one shot."""
        builder = TokenBuilder()
        token = builder.mint_root(user_ctx={}, permissions=["brain:read"], ttl_s=300)
        assert token.user_namespace == "default"
        assert token.revocation_id is not None
        assert token.revocation_id.startswith("rev-")
        assert token.user_id is None
        assert token.agent_id is None
        assert token.allowed_tenants == ()
        assert len(token.token_id) == 43  # secrets.token_urlsafe(32)
        assert token.provenance == ("*system",)

    def test_provenance_uses_user_id_over_agent_id(self) -> None:
        """Provenance uses user_id when both user_id and agent_id provided."""
        builder = TokenBuilder()
        token = builder.mint_root(
            user_ctx={},
            permissions=["brain:read"],
            ttl_s=300,
            user_id="alice",
            agent_id="dispatcher",
        )
        assert token.provenance == ("*alice",)


class TestServiceTokenTenants:
    """Service token cache must preserve explicit tenant scopes."""

    def test_service_token_allows_explicit_tenant_scope(self) -> None:
        from contextunity.core.tokens import get_brain_service_token

        token = get_brain_service_token("router", allowed_tenants=("tenant-a",))

        assert token.allowed_tenants == ("tenant-a",)
        assert token.can_access_tenant("tenant-a") is True
        assert token.can_access_tenant("tenant-b") is False

    def test_service_token_cache_isolated_by_tenant_scope(self) -> None:
        from contextunity.core.tokens import get_brain_service_token

        empty_scope = get_brain_service_token("router")
        tenant_scope = get_brain_service_token("router", allowed_tenants=("tenant-a",))

        assert empty_scope.allowed_tenants == ()
        assert tenant_scope.allowed_tenants == ("tenant-a",)


class TestVerifyEdgeCases:
    """Edge cases for verify() and verify_unit_access()."""

    @pytest.mark.parametrize(
        ("bad_value",),
        [("not_a_token",), (None,), (42,)],
        ids=["string", "none", "int"],
    )
    def test_verify_rejects_non_token(self, bad_value) -> None:
        """verify() raises PermissionError for non-ContextToken."""
        builder = TokenBuilder()
        with pytest.raises(PermissionError, match="Missing token"):
            builder.verify(bad_value, required_permission="read:data")

    def test_verify_error_contains_permission_name(self) -> None:
        """verify() error message contains the missing permission name."""
        builder = TokenBuilder()
        token = builder.mint_root(user_ctx={}, permissions=["brain:read"], ttl_s=3600)
        with pytest.raises(PermissionError, match="memory:write"):
            builder.verify(token, required_permission="memory:write")

    def test_verify_unit_access_rejects_non_token(self) -> None:
        """verify_unit_access() rejects non-ContextToken."""
        builder = TokenBuilder()
        unit = ContextUnit(security=SecurityScopes(read=["read:data"]))
        with pytest.raises(PermissionError, match="Missing token"):
            builder.verify_unit_access("not_a_token", unit, operation="read")

    def test_verify_unit_access_expired_token(self) -> None:
        """verify_unit_access() rejects expired token."""
        builder = TokenBuilder()
        token = ContextToken(
            token_id="expired",
            permissions=("read:data",),
            exp_unix=time.time() - 1,
        )
        unit = ContextUnit(security=SecurityScopes(read=["read:data"]))
        with pytest.raises(PermissionError, match="Token expired"):
            builder.verify_unit_access(token, unit, operation="read")

    def test_verify_unit_access_write_denied(self) -> None:
        """verify_unit_access() write denied includes scope info."""
        builder = TokenBuilder()
        token = builder.mint_root(user_ctx={}, permissions=["brain:read"], ttl_s=3600)
        unit = ContextUnit(security=SecurityScopes(write=["write:data"]))
        with pytest.raises(PermissionError, match="write permission"):
            builder.verify_unit_access(token, unit, operation="write")


class TestAttenuateEdgeCases:
    """Edge cases for attenuate() — TTL clamping and permission validation."""

    def test_attenuate_ttl_clamped_to_parent(self) -> None:
        """Child TTL cannot exceed parent TTL."""
        builder = TokenBuilder()
        parent = builder.mint_root(user_ctx={}, permissions=["brain:read"], ttl_s=60)
        # Request longer TTL than parent
        child = builder.attenuate(parent, ttl_s=3600)
        assert child.exp_unix <= parent.exp_unix

    def test_attenuate_inherits_revocation_id(self) -> None:
        """Attenuation preserves parent's revocation_id."""
        builder = TokenBuilder()
        parent = builder.mint_root(user_ctx={}, permissions=["brain:read"], ttl_s=300)
        child = builder.attenuate(parent, permissions=["brain:read"])
        assert child.revocation_id == parent.revocation_id

    def test_attenuate_preserves_token_id(self) -> None:
        """Child shares parent's token_id."""
        builder = TokenBuilder()
        parent = builder.mint_root(user_ctx={}, permissions=["brain:read"], ttl_s=300)
        child = builder.attenuate(parent, permissions=["brain:read"])
        assert child.token_id == parent.token_id


pytestmark = pytest.mark.unit
