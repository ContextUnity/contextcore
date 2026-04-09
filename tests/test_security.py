"""Tests for contextcore.security module."""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

os.environ["CU_PROJECT_SECRET"] = "test_secret"
from contextcore.permissions import Permissions
from contextcore.security import (
    ServicePermissionInterceptor,
    check_permission,
)
from contextcore.token_utils import (
    build_verifier_backend_from_token_string,
    extract_and_verify_token_from_http_request,
    serialize_token,
    verify_token_string,
)
from contextcore.tokens import ContextToken

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


class TestHttpTokenVerification:
    """Tests for verified HTTP token extraction helpers."""

    def test_build_verifier_backend_from_token_string_uses_project_secret(self, monkeypatch):
        from contextcore.signing import HmacBackend

        backend = HmacBackend("test_proj", "test_secret")
        token = ContextToken(
            token_id="http-token",
            permissions=(Permissions.BRAIN_READ,),
            allowed_tenants=("tenant-a",),
        )
        token_str = serialize_token(token, backend=backend)

        monkeypatch.setattr(
            "contextcore.discovery.get_project_key",
            lambda project_id, **kwargs: {"project_secret": "test_secret"},
        )

        verifier = build_verifier_backend_from_token_string(token_str)
        assert verifier is not None
        verified = verify_token_string(token_str, verifier)
        assert verified is not None
        assert verified.token_id == token.token_id

    def test_extract_and_verify_token_from_http_request(self, monkeypatch):
        from contextcore.signing import HmacBackend

        backend = HmacBackend("test_proj", "test_secret")
        token = ContextToken(
            token_id="http-token",
            permissions=(Permissions.BRAIN_READ,),
            allowed_tenants=("tenant-a",),
        )
        token_str = serialize_token(token, backend=backend)
        request = SimpleNamespace(
            META={"HTTP_AUTHORIZATION": f"Bearer {token_str}"},
            headers={},
        )

        monkeypatch.setattr(
            "contextcore.token_utils.http.build_verifier_backend_from_token_string",
            lambda *args, **kwargs: backend,
        )

        verified = extract_and_verify_token_from_http_request(request)
        assert verified is not None
        assert verified.token_id == token.token_id


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
    from contextcore.signing import HmacBackend

    backend = HmacBackend("test_proj", "test_secret")
    token_str = serialize_token(token, backend=backend)
    return [("authorization", f"Bearer {token_str}")]


class TestServicePermissionInterceptor:
    """Tests for the unified ServicePermissionInterceptor."""

    @pytest.fixture(autouse=True)
    def mock_get_project_key(self, monkeypatch):
        def _mock_get_project_key(project_id, **kwargs):
            return {"project_secret": "test_secret"}

        monkeypatch.setattr("contextcore.discovery.get_project_key", _mock_get_project_key)

    @pytest.mark.asyncio
    async def test_health_check_skipped(self):
        """Health check RPCs bypass security even when enforced."""
        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
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
        """Default constructor values."""
        interceptor = ServicePermissionInterceptor({})
        assert interceptor._service_name == "Service"
        assert interceptor._rpc_map == {}

    @pytest.mark.asyncio
    async def test_expired_token_denied(self):
        """Token with exp_unix in the past → UNAUTHENTICATED."""
        import time

        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
        )

        # Create a token that expired 10 seconds ago
        token = ContextToken(
            token_id="expired",
            permissions=(Permissions.BRAIN_READ,),
            exp_unix=time.time() - 10,
        )
        metadata = _make_token_metadata(token)

        async def _continuation(details):
            return "handler"

        details = _make_handler_call_details("/test.Service/Search", metadata)
        result = await interceptor.intercept_service(_continuation, details)
        # Should be denied — expired token
        assert result is not None
        assert result != "handler"

    @pytest.mark.asyncio
    async def test_valid_ttl_token_allowed(self):
        """Token with exp_unix in the future → allowed."""
        import time

        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
        )

        # Create a token that expires in 1 hour
        token = ContextToken(
            token_id="valid-ttl",
            permissions=(Permissions.BRAIN_READ,),
            exp_unix=time.time() + 3600,
        )
        metadata = _make_token_metadata(token)

        async def _continuation(details):
            return "handler"

        details = _make_handler_call_details("/test.Service/Search", metadata)
        result = await interceptor.intercept_service(_continuation, details)
        assert result == "handler"
