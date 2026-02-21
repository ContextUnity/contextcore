"""Tests for contextcore.security module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from contextcore.permissions import Permissions
from contextcore.security import (
    EnforcementMode,
    GuardResult,
    SecurityConfig,
    SecurityGuard,
    ServicePermissionInterceptor,
    check_permission,
    get_security_guard,
    get_security_interceptors,
    reset_security_guard,
    shield_status,
)
from contextcore.token_utils import serialize_token
from contextcore.tokens import ContextToken


class TestSecurityConfig:
    """SecurityConfig tests."""

    def test_defaults(self):
        config = SecurityConfig()
        assert config.security_enabled is False
        assert config.shield_enabled is True
        assert config.fail_open is False
        assert config.log_allowed is False
        assert "grpc.health.v1.Health" in config.skip_methods


class TestGuardResult:
    """GuardResult tests."""

    def test_allowed_by_default(self):
        result = GuardResult()
        assert result.allowed is True
        assert result.blocked is False
        assert result.reason == ""

    def test_blocked(self):
        result = GuardResult(allowed=False, reason="injection detected")
        assert result.blocked is True
        assert result.reason == "injection detected"


class TestSecurityGuard:
    """SecurityGuard tests."""

    def test_security_disabled_skips_validation(self):
        """When security_enabled=False, validate_token returns None."""
        guard = SecurityGuard(SecurityConfig(security_enabled=False))
        mock_context = MagicMock()
        token = guard.validate_token(mock_context)
        assert token is None
        mock_context.abort.assert_not_called()

    def test_validate_token_missing_required(self):
        """When token missing and require=True, abort is called."""
        guard = SecurityGuard(SecurityConfig(security_enabled=True))
        mock_context = MagicMock()
        # extract_token_from_grpc_metadata returns None
        with patch(
            "contextcore.security.guard.extract_token_from_grpc_metadata",
            return_value=None,
        ):
            guard.validate_token(mock_context, require=True)
        mock_context.abort.assert_called_once()

    def test_validate_token_missing_optional(self):
        """When token missing and require=False, returns None without abort."""
        guard = SecurityGuard(SecurityConfig(security_enabled=True))
        mock_context = MagicMock()
        with patch(
            "contextcore.security.guard.extract_token_from_grpc_metadata",
            return_value=None,
        ):
            result = guard.validate_token(mock_context, require=False)
        assert result is None
        mock_context.abort.assert_not_called()

    def test_validate_expired_token(self):
        """Expired token triggers abort."""
        guard = SecurityGuard(SecurityConfig(security_enabled=True))
        mock_context = MagicMock()
        expired_token = MagicMock(spec=ContextToken)
        expired_token.is_expired.return_value = True
        with patch(
            "contextcore.security.guard.extract_token_from_grpc_metadata",
            return_value=expired_token,
        ):
            guard.validate_token(mock_context)
        mock_context.abort.assert_called_once()

    def test_validate_valid_token(self):
        """Valid token is returned without abort."""
        guard = SecurityGuard(SecurityConfig(security_enabled=True))
        mock_context = MagicMock()
        valid_token = MagicMock(spec=ContextToken)
        valid_token.is_expired.return_value = False
        with patch(
            "contextcore.security.guard.extract_token_from_grpc_metadata",
            return_value=valid_token,
        ):
            result = guard.validate_token(mock_context)
        assert result is valid_token
        mock_context.abort.assert_not_called()

    def test_shield_not_active_without_package(self):
        """Shield is not active when contextshield is not installed."""
        with patch("contextcore.security.guard._SHIELD_AVAILABLE", False):
            guard = SecurityGuard(SecurityConfig(shield_enabled=True))
            assert guard.shield_active is False

    @pytest.mark.asyncio
    async def test_check_input_no_shield(self):
        """check_input returns allowed when no Shield."""
        with patch("contextcore.security.guard._SHIELD_AVAILABLE", False):
            guard = SecurityGuard(SecurityConfig(shield_enabled=True))
            result = await guard.check_input("test input")
            assert result.allowed is True
            assert result.shield_active is False


class TestSingleton:
    """Singleton factory tests."""

    def setup_method(self):
        reset_security_guard()

    def teardown_method(self):
        reset_security_guard()

    def test_singleton_created(self):
        guard = get_security_guard()
        guard2 = get_security_guard()
        assert guard is guard2

    def test_reset(self):
        g1 = get_security_guard()
        reset_security_guard()
        g2 = get_security_guard()
        assert g1 is not g2


class TestInterceptors:
    """Interceptor factory tests."""

    def test_no_interceptors_when_disabled(self):
        interceptors = get_security_interceptors(SecurityConfig(security_enabled=False))
        assert interceptors == []

    def test_interceptors_when_enabled(self):
        interceptors = get_security_interceptors(SecurityConfig(security_enabled=True))
        assert len(interceptors) == 1


class TestShieldStatus:
    """shield_status() tests."""

    def setup_method(self):
        reset_security_guard()

    def teardown_method(self):
        reset_security_guard()

    def test_status_dict(self):
        status = shield_status()
        assert "shield_installed" in status
        assert "shield_active" in status
        assert "security_enabled" in status
        assert "fail_open" in status


# ── check_permission ────────────────────────────────────────────


class TestCheckPermission:
    """Tests for check_permission helper."""

    def test_direct_permission_allowed(self):
        token = ContextToken(
            token_id="t1",
            permissions=(Permissions.BRAIN_READ,),
        )
        assert check_permission(token, Permissions.BRAIN_READ) is None

    def test_missing_permission_denied(self):
        token = ContextToken(
            token_id="t2",
            permissions=(Permissions.BRAIN_READ,),
        )
        result = check_permission(token, Permissions.BRAIN_WRITE)
        assert result is not None
        assert "missing permission" in result

    def test_inheritance_expansion_allowed(self):
        """zero:anonymize should imply zero:deanonymize via inheritance."""
        token = ContextToken(
            token_id="t3",
            permissions=(Permissions.ZERO_ANONYMIZE,),
        )
        assert check_permission(token, Permissions.ZERO_ANONYMIZE) is None
        assert check_permission(token, Permissions.ZERO_DEANONYMIZE) is None

    def test_tenant_allowed(self):
        token = ContextToken(
            token_id="t4",
            permissions=(Permissions.BRAIN_READ,),
            allowed_tenants=("tenant-a",),
        )
        assert check_permission(token, Permissions.BRAIN_READ, tenant_id="tenant-a") is None

    def test_tenant_denied(self):
        token = ContextToken(
            token_id="t5",
            permissions=(Permissions.BRAIN_READ,),
            allowed_tenants=("tenant-a",),
        )
        result = check_permission(token, Permissions.BRAIN_READ, tenant_id="tenant-b")
        assert result is not None
        assert "tenant access denied" in result


# ── ServicePermissionInterceptor ────────────────────────────────

# Test RPC map
_TEST_RPC_MAP = {
    "Search": Permissions.BRAIN_READ,
    "IngestDocument": Permissions.BRAIN_WRITE,
}


def _make_handler_call_details(method: str, metadata: list | None = None):
    """Create a mock HandlerCallDetails."""
    mock = MagicMock()
    mock.method = method
    mock.invocation_metadata = metadata or []
    return mock


def _make_token_metadata(token: ContextToken) -> list[tuple[str, str]]:
    """Serialize a token and return it as gRPC metadata."""
    token_str = serialize_token(token)
    return [("authorization", f"Bearer {token_str}")]


class TestServicePermissionInterceptor:
    """Tests for the unified ServicePermissionInterceptor."""

    @pytest.mark.asyncio
    async def test_disabled_passes_through(self):
        """Security off → all RPCs pass through."""
        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
            enforcement=EnforcementMode.OFF,
        )

        async def _continuation(details):
            return "handler"

        details = _make_handler_call_details("/test.Service/Search")
        result = await interceptor.intercept_service(_continuation, details)
        assert result == "handler"

    @pytest.mark.asyncio
    async def test_health_check_skipped(self):
        """Health check RPCs bypass security even when enforced."""
        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
            enforcement=EnforcementMode.ENFORCE,
        )

        async def _continuation(details):
            return "handler"

        details = _make_handler_call_details("/grpc.health.v1.Health/Check")
        result = await interceptor.intercept_service(_continuation, details)
        assert result == "handler"

    @pytest.mark.asyncio
    async def test_reflection_skipped(self):
        """Reflection RPCs bypass security."""
        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
            enforcement=EnforcementMode.ENFORCE,
        )

        async def _continuation(details):
            return "handler"

        details = _make_handler_call_details("/grpc.reflection.v1.ServerReflection/ServerReflectionInfo")
        result = await interceptor.intercept_service(_continuation, details)
        assert result == "handler"

    @pytest.mark.asyncio
    async def test_unmapped_rpc_denied(self):
        """Unknown/unmapped RPC → PERMISSION_DENIED (fail-closed)."""
        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
            enforcement=EnforcementMode.ENFORCE,
        )

        token = ContextToken(token_id="t1", permissions=(Permissions.BRAIN_READ,))
        metadata = _make_token_metadata(token)

        async def _continuation(details):
            return "handler"

        details = _make_handler_call_details("/test.Service/UnknownRPC", metadata)
        result = await interceptor.intercept_service(_continuation, details)
        # Returns a handler that will abort with PERMISSION_DENIED
        assert result is not None
        assert result != "handler"

    @pytest.mark.asyncio
    async def test_no_token_unauthenticated(self):
        """No token in metadata → UNAUTHENTICATED."""
        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
            enforcement=EnforcementMode.ENFORCE,
        )

        async def _continuation(details):
            return "handler"

        details = _make_handler_call_details("/test.Service/Search", [])
        result = await interceptor.intercept_service(_continuation, details)
        # Returns handler that will abort
        assert result is not None
        assert result != "handler"

    @pytest.mark.asyncio
    async def test_valid_token_allowed(self):
        """Valid token with correct permission → passes through."""
        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
            enforcement=EnforcementMode.ENFORCE,
        )

        token = ContextToken(token_id="valid", permissions=(Permissions.BRAIN_READ,))
        metadata = _make_token_metadata(token)

        async def _continuation(details):
            return "handler"

        details = _make_handler_call_details("/test.Service/Search", metadata)
        result = await interceptor.intercept_service(_continuation, details)
        assert result == "handler"

    @pytest.mark.asyncio
    async def test_wrong_permission_denied(self):
        """Token with wrong permission → PERMISSION_DENIED."""
        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
            enforcement=EnforcementMode.ENFORCE,
        )

        # Token has only trace:write, but Search requires brain:read
        token = ContextToken(token_id="wrong", permissions=(Permissions.TRACE_WRITE,))
        metadata = _make_token_metadata(token)

        async def _continuation(details):
            return "handler"

        details = _make_handler_call_details("/test.Service/Search", metadata)
        result = await interceptor.intercept_service(_continuation, details)
        assert result is not None
        assert result != "handler"

    @pytest.mark.asyncio
    async def test_inherited_permission_allowed(self):
        """Token with zero:anonymize → allowed for zero:deanonymize via inheritance."""
        # Use a Zero RPC map for this test
        zero_rpc_map = {"Deanonymize": Permissions.ZERO_DEANONYMIZE}
        interceptor = ServicePermissionInterceptor(
            zero_rpc_map,
            service_name="Test",
            enforcement=EnforcementMode.ENFORCE,
        )

        # Token has zero:anonymize which implies zero:deanonymize
        token = ContextToken(token_id="inherited", permissions=(Permissions.ZERO_ANONYMIZE,))
        metadata = _make_token_metadata(token)

        async def _continuation(details):
            return "handler"

        details = _make_handler_call_details("/test.Service/Deanonymize", metadata)
        result = await interceptor.intercept_service(_continuation, details)
        assert result == "handler"

    def test_constructor_defaults(self):
        """Default constructor values — mode is WARN (fail-safe, not silent OFF)."""
        interceptor = ServicePermissionInterceptor({})
        assert interceptor._mode == EnforcementMode.WARN
        assert interceptor._service_name == "Service"
        assert interceptor._rpc_map == {}

    @pytest.mark.asyncio
    async def test_warn_mode_logs_but_allows(self):
        """Warn mode → denied RPC still passes through."""
        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
            enforcement=EnforcementMode.WARN,
        )

        async def _continuation(details):
            return "handler"

        # No token → would be denied in enforce, but warn lets it through
        details = _make_handler_call_details("/test.Service/Search", [])
        result = await interceptor.intercept_service(_continuation, details)
        assert result == "handler"
