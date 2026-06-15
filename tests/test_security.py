"""Tests for contextunity.core.security module."""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import MagicMock

import grpc
import pytest

os.environ["CU_PROJECT_SECRET"] = "test_secret"
from contextunity.core.permissions import Permissions
from contextunity.core.security import (
    ServicePermissionInterceptor,
    check_permission,
)
from contextunity.core.token_utils import (
    build_verifier_backend_from_token_string,
    extract_and_verify_token_from_http_request,
    serialize_token,
    verify_token_string,
)
from contextunity.core.tokens import ContextToken

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
        """privacy:anonymize should imply privacy:deanonymize via inheritance."""
        token = ContextToken(
            token_id="t3",
            permissions=(Permissions.PRIVACY_ANONYMIZE,),
        )
        assert check_permission(token, Permissions.PRIVACY_ANONYMIZE) is None
        assert check_permission(token, Permissions.PRIVACY_DEANONYMIZE) is None

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
        from contextunity.core.signing import HmacBackend

        backend = HmacBackend("test_proj", "test_secret")
        token = ContextToken(
            token_id="http-token",
            permissions=(Permissions.BRAIN_READ,),
            allowed_tenants=("tenant-a",),
        )
        token_str = serialize_token(token, backend=backend)

        monkeypatch.setattr(
            "contextunity.core.discovery.get_project_key",
            lambda project_id, **kwargs: {"project_secret": "test_secret"},
        )

        verifier = build_verifier_backend_from_token_string(token_str)
        assert verifier is not None
        verified = verify_token_string(token_str, verifier)
        assert verified is not None
        assert verified.token_id == token.token_id

    def test_extract_and_verify_token_from_http_request(self, monkeypatch):
        from contextunity.core.signing import HmacBackend

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
            "contextunity.core.token_utils.http.build_verifier_backend_from_token_string",
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


def _make_handler_call_details(method: str, metadata: object = None):
    """Create a mock HandlerCallDetails.

    ``metadata`` may be any gRPC container shape (list, tuple, ``grpc.aio.Metadata``)
    so tests can faithfully reproduce real invocation metadata.
    """
    mock = MagicMock()
    mock.method = method
    mock.invocation_metadata = [] if metadata is None else metadata
    return mock


def _make_token_metadata(token: ContextToken) -> list[tuple[str, str]]:
    """Serialize a token and return it as gRPC metadata."""
    from contextunity.core.signing import HmacBackend

    backend = HmacBackend("test_proj", "test_secret")
    token_str = serialize_token(token, backend=backend)
    return [("authorization", f"Bearer {token_str}")]


def _as_metadata_container(pairs: list[tuple[str, str]], kind: str) -> object:
    """Re-pack ``(key, value)`` pairs into the requested gRPC container shape.

    Real gRPC servers hand the interceptor ``handler_call_details.invocation_metadata``
    as a *tuple* of ``_Metadatum`` namedtuples or a ``grpc.aio.Metadata`` object —
    NOT a ``list``. Tests must exercise these shapes so a normalization regression
    (e.g. only handling ``list``) is caught instead of silently denying every RPC.
    """
    if kind == "list":
        return list(pairs)
    if kind == "tuple":
        return tuple(pairs)
    if kind == "aio_metadata":
        from grpc.aio import Metadata

        return Metadata(*pairs)
    raise ValueError(f"unknown metadata kind: {kind}")


# Container shapes a real gRPC stack may deliver to the interceptor.
_METADATA_KINDS = ("list", "tuple", "aio_metadata")


class TestServicePermissionInterceptor:
    """Tests for the unified ServicePermissionInterceptor."""

    @pytest.fixture(autouse=True)
    def mock_get_project_key(self, monkeypatch):
        def _mock_get_project_key(project_id, **kwargs):
            return {"project_secret": "test_secret"}

        monkeypatch.setattr("contextunity.core.discovery.get_project_key", _mock_get_project_key)

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
    @pytest.mark.parametrize(
        ("method", "token_factory", "expected_reason", "expected_code"),
        [
            (
                "/test.Service/UnknownRPC",
                lambda: ContextToken(token_id="t1", permissions=(Permissions.BRAIN_READ,)),
                "RPC not mapped to permission",
                grpc.StatusCode.PERMISSION_DENIED,
            ),
            (
                "/test.Service/Search",
                lambda: None,  # No token
                "no token",
                grpc.StatusCode.UNAUTHENTICATED,
            ),
            (
                "/test.Service/Search",
                lambda: ContextToken(token_id="wrong", permissions=(Permissions.TRACE_WRITE,)),
                "missing permission: brain:read",
                grpc.StatusCode.PERMISSION_DENIED,
            ),
        ],
        ids=["unmapped-rpc", "no-token", "wrong-permission"],
    )
    async def test_denial_returns_grpc_handler(self, method, token_factory, expected_reason, expected_code):
        """Denied requests return a gRPC method handler with exact reason/code."""
        from unittest.mock import AsyncMock

        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
        )

        token = token_factory()
        metadata = _make_token_metadata(token) if token else []

        async def _continuation(details):
            return "handler"

        # Mock _build_denial_handler to inspect exactly what was denied
        interceptor._build_denial_handler = AsyncMock(return_value="mock_denial_handler")

        details = _make_handler_call_details(method, metadata)
        result = await interceptor.intercept_service(_continuation, details)

        assert result == "mock_denial_handler", "Expected intercept_service to return the denial handler"

        # Verify the exact reason and code
        interceptor._build_denial_handler.assert_called_once()
        call_args = interceptor._build_denial_handler.call_args.args
        assert call_args[0] == method.split("/")[-1], "Should pass RPC name"
        assert expected_reason in call_args[1], f"Expected reason to contain '{expected_reason}', got '{call_args[1]}'"
        assert call_args[2] == expected_code, f"Expected gRPC status code {expected_code}, got {call_args[2]}"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("metadata_kind", _METADATA_KINDS)
    async def test_valid_token_allowed(self, metadata_kind):
        """Valid token with correct permission → passes through.

        Parametrized over every gRPC metadata container shape (list, tuple,
        ``grpc.aio.Metadata``). Regression guard: a normalization that only
        accepted ``list`` would drop the ``authorization`` header for real
        tuple/Metadata invocations and deny every authenticated RPC.
        """
        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
        )

        token = ContextToken(token_id="valid", permissions=(Permissions.BRAIN_READ,))
        metadata = _as_metadata_container(_make_token_metadata(token), metadata_kind)

        async def _continuation(details):
            return "handler"

        details = _make_handler_call_details("/test.Service/Search", metadata)
        result = await interceptor.intercept_service(_continuation, details)
        assert result == "handler", f"valid token denied for metadata kind={metadata_kind}"

    @pytest.mark.asyncio
    async def test_inherited_permission_allowed(self):
        """Token with privacy:anonymize → allowed for privacy:deanonymize via inheritance."""
        privacy_rpc_map = {"Deanonymize": Permissions.PRIVACY_DEANONYMIZE}
        interceptor = ServicePermissionInterceptor(
            privacy_rpc_map,
            service_name="Test",
        )

        token = ContextToken(token_id="inherited", permissions=(Permissions.PRIVACY_ANONYMIZE,))
        metadata = _make_token_metadata(token)

        async def _continuation(details):
            return "handler"

        details = _make_handler_call_details("/test.Service/Deanonymize", metadata)
        result = await interceptor.intercept_service(_continuation, details)
        assert result == "handler"

    @pytest.mark.asyncio
    async def test_expired_token_denied(self):
        """Token with exp_unix in the past → denied with grpc handler."""
        import time
        from unittest.mock import AsyncMock

        import grpc

        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
        )

        token = ContextToken(
            token_id="expired",
            permissions=(Permissions.BRAIN_READ,),
            exp_unix=time.time() - 10,
        )
        metadata = _make_token_metadata(token)

        async def _continuation(details):
            return "handler"

        interceptor._build_denial_handler = AsyncMock(return_value="mock_denial_handler")

        details = _make_handler_call_details("/test.Service/Search", metadata)
        result = await interceptor.intercept_service(_continuation, details)

        assert result == "mock_denial_handler"
        interceptor._build_denial_handler.assert_called_once()
        args = interceptor._build_denial_handler.call_args.args
        assert "token expired" in args[1]
        assert args[2] == grpc.StatusCode.UNAUTHENTICATED

    @pytest.mark.asyncio
    async def test_valid_ttl_token_allowed(self):
        """Token with exp_unix in the future → allowed."""
        import time

        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
        )

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

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("token_id", "revocation_id", "is_revoked", "expected_result"),
        [
            ("token-1", "rev-123", True, "mock_denial_handler"),
            ("token-2", "rev-456", False, "handler"),
        ],
    )
    async def test_token_revocation_checks(self, monkeypatch, token_id, revocation_id, is_revoked, expected_result):
        """Revoked tokens must be rejected exactly based on revocation_id."""
        from unittest.mock import AsyncMock

        import grpc

        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
        )
        interceptor._build_denial_handler = AsyncMock(return_value="mock_denial_handler")

        class _AsyncFakeRedis:
            async def exists(self, key: str):
                # Only rev-123 is in the "database"
                if "rev-123" in key:
                    return 1
                return 0

            async def aclose(self):
                return None

        monkeypatch.setattr(
            "redis.asyncio.from_url",
            lambda *args, **kwargs: _AsyncFakeRedis(),
        )
        from contextunity.core.config import get_core_config

        config = get_core_config()
        monkeypatch.setattr(config.redis, "url", "redis://localhost:6379/0")

        token = ContextToken(
            token_id=token_id,
            permissions=(Permissions.BRAIN_READ,),
            revocation_id=revocation_id,
        )
        metadata = _make_token_metadata(token)

        async def _continuation(details):
            return "handler"

        details = _make_handler_call_details("/test.Service/Search", metadata)
        result = await interceptor.intercept_service(_continuation, details)

        assert result == expected_result
        if is_revoked:
            interceptor._build_denial_handler.assert_called_once()
            args = interceptor._build_denial_handler.call_args.args
            assert "token revoked" in args[1]
            assert args[2] == grpc.StatusCode.UNAUTHENTICATED
        else:
            interceptor._build_denial_handler.assert_not_called()

    @pytest.mark.asyncio
    async def test_revocation_fails_closed_without_redis_url(self, monkeypatch):
        """Tokens with revocation_id must be denied if redis_url is unset.

        Revocation is a security primitive; an unconfigured store is an
        operator error, not a licence to bypass the check.
        """
        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
        )

        from contextunity.core.config import get_core_config

        config = get_core_config()
        monkeypatch.setattr(config.redis, "url", "")
        monkeypatch.setattr(config, "local_mode", False)

        token = ContextToken(
            token_id="revocable",
            permissions=(Permissions.BRAIN_READ,),
            revocation_id="rev-missing-redis",
        )
        assert await interceptor._is_token_revoked(token) is True

    @pytest.mark.asyncio
    async def test_revocation_skipped_in_local_mode_without_redis(self, monkeypatch):
        """Local platform runs without Redis — do not treat HMAC tokens as revoked."""
        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
        )

        from contextunity.core.config import get_core_config

        config = get_core_config()
        monkeypatch.setattr(config.redis, "url", "")
        monkeypatch.setattr(config, "local_mode", True)

        token = ContextToken(
            token_id="local-dev",
            permissions=(Permissions.BRAIN_READ,),
            revocation_id="rev-local-skip",
        )
        assert await interceptor._is_token_revoked(token) is False

    @pytest.mark.asyncio
    async def test_revocation_fails_closed_on_redis_error(self, monkeypatch):
        """Redis errors (connection refused, transport) must fail closed."""
        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
        )

        class _BrokenRedis:
            async def exists(self, key: str):
                raise ConnectionError("redis unreachable")

            async def aclose(self):
                return None

        monkeypatch.setattr(
            "redis.asyncio.from_url",
            lambda *args, **kwargs: _BrokenRedis(),
        )
        from contextunity.core.config import get_core_config

        config = get_core_config()
        monkeypatch.setattr(config.redis, "url", "redis://localhost:6379/0")

        token = ContextToken(
            token_id="revocable",
            permissions=(Permissions.BRAIN_READ,),
            revocation_id="rev-redis-down",
        )
        assert await interceptor._is_token_revoked(token) is True

    @pytest.mark.asyncio
    async def test_revocation_fails_closed_on_timeout(self, monkeypatch):
        """Revocation store timeouts must fail closed (prefer deny over allow)."""
        import asyncio as _asyncio

        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
        )

        class _HangingRedis:
            async def exists(self, key: str):
                await _asyncio.sleep(10)
                return 0

            async def aclose(self):
                return None

        monkeypatch.setattr(
            "redis.asyncio.from_url",
            lambda *args, **kwargs: _HangingRedis(),
        )
        from contextunity.core.config import get_core_config

        config = get_core_config()
        monkeypatch.setattr(config.redis, "url", "redis://localhost:6379/0")

        token = ContextToken(
            token_id="revocable",
            permissions=(Permissions.BRAIN_READ,),
            revocation_id="rev-timeout",
        )

        async def _fast_wait_for(coro, timeout):
            if hasattr(coro, "close"):
                coro.close()
            raise _asyncio.TimeoutError()

        monkeypatch.setattr("asyncio.wait_for", _fast_wait_for)

        assert await interceptor._is_token_revoked(token) is True

    @pytest.mark.asyncio
    async def test_revocation_skips_tokens_without_revocation_id(self, monkeypatch):
        """Tokens without revocation_id are non-revocable and must pass."""
        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
        )

        from contextunity.core.config import get_core_config

        config = get_core_config()
        monkeypatch.setattr(config.redis, "url", "")

        token = ContextToken(
            token_id="non-revocable",
            permissions=(Permissions.BRAIN_READ,),
            revocation_id=None,
        )
        assert await interceptor._is_token_revoked(token) is False


class TestMetadataNormalization:
    """Direct tests for ``invocation_metadata_as_dict``.

    gRPC delivers ``invocation_metadata`` as a tuple of ``_Metadatum`` namedtuples
    or a ``grpc.aio.Metadata`` object — never a ``list``. The normalizer must turn
    any of these into a ``{header: value}`` mapping so the ``authorization`` token
    survives. These tests pin every supported container shape.
    """

    def test_grpc_container_shapes_preserve_authorization(self):
        from contextunity.core.grpc_metadata import invocation_metadata_as_dict

        pairs = [("authorization", "Bearer abc"), ("x-tenant", "nszu")]
        for kind in _METADATA_KINDS:
            container = _as_metadata_container(pairs, kind)
            result = invocation_metadata_as_dict(container)
            assert result.get("authorization") == "Bearer abc", f"lost auth header for kind={kind}"
            assert result.get("x-tenant") == "nszu", f"lost x-tenant for kind={kind}"

    def test_dict_metadata_supported(self):
        from contextunity.core.grpc_metadata import invocation_metadata_as_dict

        result = invocation_metadata_as_dict({"authorization": "Bearer abc"})
        assert result == {"authorization": "Bearer abc"}

    def test_bytes_values_preserved(self):
        from contextunity.core.grpc_metadata import invocation_metadata_as_dict

        result = invocation_metadata_as_dict((("bin-header", b"\x00\x01"),))
        assert result.get("bin-header") == b"\x00\x01"

    @pytest.mark.parametrize("bad", [None, "authorization: Bearer abc", b"raw", 42])
    def test_non_pair_iterables_yield_empty(self, bad):
        from contextunity.core.grpc_metadata import invocation_metadata_as_dict

        # str/bytes/None/scalars are not (key, value) pair iterables → empty mapping,
        # never a crash and never a partial/garbage parse.
        assert invocation_metadata_as_dict(bad) == {}


# ── HMAC Fallback Semantics (ProjectStore Unification Phase 6) ──


class TestHmacFallbackSemantics:
    """Verify HMAC secret resolution in _build_verifier_backend.

    After ProjectStore unification, the contract is:
      - No key_data at all → CU_PROJECT_SECRET dev fallback (single env escape hatch)
      - key_data exists with project_secret → use it (ProjectStore is source of truth)
      - key_data exists WITHOUT project_secret → reject (no silent env fallback)
    """

    @pytest.mark.asyncio
    async def test_no_project_record_falls_back_to_env_secret(self, monkeypatch):
        """Unregistered project → CU_PROJECT_SECRET dev fallback still works."""
        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
        )

        # get_project_key returns None (project not registered)
        monkeypatch.setattr(
            "contextunity.core.discovery.get_project_key",
            lambda project_id, **kwargs: None,
        )

        # CU_PROJECT_SECRET is set
        from contextunity.core.config import get_core_config

        config = get_core_config()
        monkeypatch.setattr(config.security, "project_secret", "dev-secret-123")

        # kid format: project_id:key_version
        token_str = "unregistered-proj:hmac-v1.fakepayload.fakesig"
        backend = await interceptor._build_verifier_backend(token_str)

        assert backend is not None
        from contextunity.core.signing import HmacBackend

        assert isinstance(backend, HmacBackend)

    @pytest.mark.asyncio
    async def test_registered_project_uses_stored_secret(self, monkeypatch):
        """Registered project with project_secret → verifies through ProjectStore."""
        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
        )

        monkeypatch.setattr(
            "contextunity.core.discovery.get_project_key",
            lambda project_id, **kwargs: {"project_secret": "stored-secret-abc"},
        )

        token_str = "my-project:hmac-v1.fakepayload.fakesig"
        backend = await interceptor._build_verifier_backend(token_str)

        assert backend is not None
        from contextunity.core.signing import HmacBackend

        assert isinstance(backend, HmacBackend)

    @pytest.mark.asyncio
    async def test_registered_project_without_secret_does_not_fallback_to_env(self, monkeypatch):
        """Registered project WITHOUT project_secret → reject, no env fallback.

        This is the key behavioral change from Phase 6: when the ProjectStore
        has the project registered but it has no HMAC secret (e.g. Ed25519-only
        project), the interceptor must NOT silently fall back to CU_PROJECT_SECRET.
        """
        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
        )

        # ProjectStore returns key_data but WITHOUT project_secret
        monkeypatch.setattr(
            "contextunity.core.discovery.get_project_key",
            lambda project_id, **kwargs: {"public_key_b64": "some-pub-key"},
        )

        # CU_PROJECT_SECRET IS set — but should NOT be used
        from contextunity.core.config import get_core_config

        config = get_core_config()
        monkeypatch.setattr(config.security, "project_secret", "should-not-be-used")

        # HMAC token for a registered project that has no HMAC secret
        token_str = "registered-proj:hmac-v1.fakepayload.fakesig"
        backend = await interceptor._build_verifier_backend(token_str)

        # Must be None — no silent fallback
        assert backend is None


pytestmark = pytest.mark.unit
