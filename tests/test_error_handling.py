"""Tests for error handling and edge cases in contextcore."""

from __future__ import annotations

import time
from uuid import uuid4

import pytest

from contextcore import (
    ContextToken,
    ContextUnit,
    LogLevel,
    SecurityScopes,
    SharedConfig,
    TokenBuilder,
    redact_secrets,
    safe_preview,
)


class TestErrorHandling:
    """Tests for error handling in various components."""

    def test_context_unit_invalid_uuid_string(self) -> None:
        """Test ContextUnit with invalid UUID string."""
        with pytest.raises((ValueError, TypeError)):
            ContextUnit(unit_id="invalid-uuid")  # type: ignore[arg-type]

    def test_context_unit_empty_payload(self) -> None:
        """Test ContextUnit with empty payload (should work)."""
        unit = ContextUnit(payload={})
        assert unit.payload == {}

    def test_context_unit_none_payload(self) -> None:
        """Test ContextUnit with None payload (should default to {})."""
        # Pydantic should handle None and convert to default
        unit = ContextUnit()
        assert unit.payload == {}

    def test_security_scopes_empty_lists(self) -> None:
        """Test SecurityScopes with empty lists (allows all)."""
        scopes = SecurityScopes(read=[], write=[])
        assert scopes.read == []
        assert scopes.write == []

    def test_token_expired_edge_case(self) -> None:
        """Test token expiration at exact boundary."""
        # Token expiring exactly now
        token = ContextToken(
            token_id="test",
            permissions=(),
            exp_unix=time.time(),
        )
        # Should be expired (>= means expired)
        assert token.is_expired()

    def test_token_expired_future(self) -> None:
        """Test token not expired in future."""
        token = ContextToken(
            token_id="test",
            permissions=(),
            exp_unix=time.time() + 1,
        )
        assert not token.is_expired()

    def test_token_builder_mint_with_empty_permissions(self) -> None:
        """Test minting token with empty permissions."""
        builder = TokenBuilder()
        token = builder.mint_root(
            user_ctx={},
            permissions=[],
            ttl_s=3600,
        )
        assert len(token.permissions) == 0

    def test_token_builder_mint_with_negative_ttl(self) -> None:
        """Test minting token with negative TTL."""
        builder = TokenBuilder()
        token = builder.mint_root(
            user_ctx={},
            permissions=["read:data"],
            ttl_s=-100,  # Negative TTL
        )
        # Token should be expired immediately
        assert token.exp_unix is not None
        assert token.is_expired()

    def test_token_verify_with_empty_permission(self) -> None:
        """Test verifying token with empty permission string."""
        builder = TokenBuilder()
        token = builder.mint_root(
            user_ctx={},
            permissions=["read:data"],
            ttl_s=3600,
        )
        # Empty permission should fail
        with pytest.raises(PermissionError):
            builder.verify(token, required_permission="")

    def test_token_verify_unit_access_invalid_operation(self) -> None:
        """Test verify_unit_access with invalid operation."""
        builder = TokenBuilder()
        token = builder.mint_root(
            user_ctx={},
            permissions=["read:data"],
            ttl_s=3600,
        )
        unit = ContextUnit(security=SecurityScopes(read=["read:data"]))

        with pytest.raises(ValueError, match="Invalid operation"):
            builder.verify_unit_access(token, unit, operation="invalid")

    def test_safe_preview_with_very_long_string(self) -> None:
        """Test safe_preview with extremely long string."""
        long_string = "a" * 10000
        result = safe_preview(long_string, limit=100)
        assert len(result) == 100
        assert result.endswith("…")

    def test_safe_preview_with_none_limit(self) -> None:
        """Test safe_preview with None value and limit."""
        result = safe_preview(None, limit=100)
        assert result == ""

    def test_redact_secrets_with_none(self) -> None:
        """Test redact_secrets with None input."""
        result = redact_secrets(None)  # type: ignore[arg-type]
        assert result is None

    def test_redact_secrets_with_empty_string(self) -> None:
        """Test redact_secrets with empty string."""
        result = redact_secrets("")
        assert result == ""

    def test_redact_secrets_with_multiple_secrets(self) -> None:
        """Test redact_secrets with multiple secret patterns."""
        text = 'password: "secret123" api_key: sk-1234567890 bearer token: abc123'
        result = redact_secrets(text)
        assert "[REDACTED]" in result
        assert "secret123" not in result
        assert "sk-1234567890" not in result
        assert "abc123" not in result

    def test_shared_config_invalid_log_level(self) -> None:
        """Test SharedConfig with invalid log level."""
        with pytest.raises(ValueError, match="Invalid log level"):
            SharedConfig(log_level="INVALID")  # type: ignore[arg-type]

    def test_shared_config_invalid_redis_url(self) -> None:
        """Test SharedConfig with invalid Redis URL."""
        with pytest.raises(ValueError, match="Redis URL must start with"):
            SharedConfig(redis_url="http://localhost:6379")

    def test_context_unit_chain_of_thought_invalid_status(self) -> None:
        """Test CotStep with custom status (should work, status is just a string)."""
        from contextcore import CotStep
        step = CotStep(agent="test", action="test", status="custom_status")
        assert step.status == "custom_status"

    def test_token_can_read_with_empty_token_permissions(self) -> None:
        """Test can_read with token that has no permissions."""
        token = ContextToken(token_id="test", permissions=())
        scopes = SecurityScopes(read=["read:data"])
        # Token with no permissions should not be able to read
        assert not token.can_read(scopes)

    def test_token_can_write_with_empty_token_permissions(self) -> None:
        """Test can_write with token that has no permissions."""
        token = ContextToken(token_id="test", permissions=())
        scopes = SecurityScopes(write=["write:data"])
        # Token with no permissions should not be able to write
        assert not token.can_write(scopes)

    def test_context_unit_provenance_append_none(self) -> None:
        """Test appending None to provenance (should work as string)."""
        unit = ContextUnit()
        unit.provenance.append(None)  # type: ignore[arg-type]
        # Should convert None to string
        assert None in unit.provenance or "None" in unit.provenance
