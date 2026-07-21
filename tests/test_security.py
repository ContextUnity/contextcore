"""Tests for contextunity.core.security module."""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import MagicMock

import grpc
import pytest

os.environ["CU_PLATFORM_SECRET"] = "test_secret"
from contextunity.core.permissions import Permissions
from contextunity.core.security import (
    ServicePermissionInterceptor,
    check_permission,
    mask_token_id,
)
from contextunity.core.token_utils import (
    build_verifier_backend_from_token_string,
    extract_and_verify_token_from_http_request,
    serialize_token,
    verify_token_string,
)
from contextunity.core.tokens import ContextToken


@pytest.fixture(autouse=True)
def _platform_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Guarantee ``get_core_config().security.platform_secret == "test_secret"``
    for every test in this file — not just when ``get_core_config()``'s
    process-wide singleton happens to still be uncached.

    The module-level ``os.environ["CU_PLATFORM_SECRET"] = "test_secret"``
    above only works if it runs *before* the first ``get_core_config()``
    call anywhere in the test session — env vars are read once, at
    construction time, and cached indefinitely afterward. If any other test
    file (e.g. one with a fixture that calls ``get_core_config()``, such as
    ``tests/contracts/conftest.py``) constructs the singleton first — which
    depends on collection/execution order and is not guaranteed — every test
    here that signs with ``HmacBackend("test_proj", "test_secret")`` and
    relies on verification resolving the *same* secret via
    ``build_verifier_backend()``'s ``get_core_config().security.platform_secret``
    lookup fails with "HMAC signature verification failed", intermittently,
    depending on pytest-randomly's collection order. Found as a rare
    (~1-in-10 to 1-in-20 full-suite runs) flake.
    """
    from contextunity.core.config import get_core_config

    security = get_core_config().security
    monkeypatch.setattr(security, "platform_secret", "test_secret")
    monkeypatch.setattr(security, "project_secret", "")


def _enable_redis_for_revocation(
    monkeypatch: pytest.MonkeyPatch,
    config: object,
    *,
    url: str = "redis://localhost:6379/0",
) -> None:
    """Opt into Redis revocation path under unit isolation (REDIS_ENABLED=0).

    ``is_token_revoked`` uses ``config.redis.url if config.redis.enabled else ""``.
    Setting only ``url`` is a no-op when unit conftest left ``enabled=False``.
    """
    redis = getattr(config, "redis")
    monkeypatch.setattr(redis, "enabled", True)
    monkeypatch.setattr(redis, "url", url)


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
        """privacy:anonymize implies check_pii but NOT deanonymize (re-identification
        is strictly more privileged than masking)."""
        token = ContextToken(
            token_id="t3",
            permissions=(Permissions.PRIVACY_ANONYMIZE,),
        )
        assert check_permission(token, Permissions.PRIVACY_ANONYMIZE) is None
        assert check_permission(token, Permissions.PRIVACY_CHECK_PII) is None
        assert check_permission(token, Permissions.PRIVACY_DEANONYMIZE) is not None

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


# ── mask_token_id ────────────────────────────────────────────────


class TestMaskTokenId:
    """Tests for mask_token_id helper."""

    def test_none_or_empty(self):
        assert mask_token_id(None) == "<none>"
        assert mask_token_id("") == "<none>"
        assert mask_token_id("   ") == "<none>"

    def test_short_id_returned_as_is(self):
        assert mask_token_id("expired") == "expired"
        assert mask_token_id("token-1") == "token-1"

    def test_long_id_masked_to_ends(self):
        tid = "JFXYN_co0T5xPglUl9UmRyGo6Nv8vtixeNGu51MwbWI"
        masked = mask_token_id(tid)
        assert masked.startswith(tid[:4])
        assert masked.endswith(tid[-4:])
        assert "\u2026" in masked
        assert tid[4:-4] not in masked


class TestHttpTokenVerification:
    """Tests for verified HTTP token extraction helpers."""

    def test_build_verifier_backend_from_token_string_uses_platform_secret(self, monkeypatch):
        from contextunity.core.signing import HmacBackend

        backend = HmacBackend("test_proj", "test_secret")
        token = ContextToken(
            token_id="http-token",
            permissions=(Permissions.BRAIN_READ,),
            allowed_tenants=("tenant-a",),
        )
        token_str = serialize_token(token, backend=backend)

        from contextunity.core.config import get_core_config

        monkeypatch.setattr(get_core_config().security, "platform_secret", "test_secret")

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
    "SearchCells": Permissions.BRAIN_READ,
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

    def test_local_platform_hmac_is_fail_closed_by_default(self):
        interceptor = ServicePermissionInterceptor(_TEST_RPC_MAP, service_name="Test")

        assert interceptor._allow_local_platform_hmac is False

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
                "/test.Service/SearchCells",
                lambda: None,  # No token
                "no token",
                grpc.StatusCode.UNAUTHENTICATED,
            ),
            (
                "/test.Service/SearchCells",
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

        details = _make_handler_call_details("/test.Service/SearchCells", metadata)
        result = await interceptor.intercept_service(_continuation, details)
        assert result == "handler", f"valid token denied for metadata kind={metadata_kind}"

    @pytest.mark.asyncio
    async def test_inherited_permission_allowed(self):
        """Token with privacy:anonymize → allowed for privacy:check_pii via inheritance
        (deanonymize is deliberately NOT inherited from anonymize)."""
        privacy_rpc_map = {"CheckPii": Permissions.PRIVACY_CHECK_PII}
        interceptor = ServicePermissionInterceptor(
            privacy_rpc_map,
            service_name="Test",
        )

        token = ContextToken(token_id="inherited", permissions=(Permissions.PRIVACY_ANONYMIZE,))
        metadata = _make_token_metadata(token)

        async def _continuation(details):
            return "handler"

        details = _make_handler_call_details("/test.Service/CheckPii", metadata)
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

        details = _make_handler_call_details("/test.Service/SearchCells", metadata)
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

        details = _make_handler_call_details("/test.Service/SearchCells", metadata)
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
        _enable_redis_for_revocation(monkeypatch, config)

        token = ContextToken(
            token_id=token_id,
            permissions=(Permissions.BRAIN_READ,),
            revocation_id=revocation_id,
        )
        metadata = _make_token_metadata(token)

        async def _continuation(details):
            return "handler"

        details = _make_handler_call_details("/test.Service/SearchCells", metadata)
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
        _enable_redis_for_revocation(monkeypatch, config)

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
        _enable_redis_for_revocation(monkeypatch, config)

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

    @pytest.mark.asyncio
    async def test_revocation_epoch_check_blocks_stale_session_token(self, monkeypatch):
        """A session token issued before a project's epoch bump must be
        rejected — the Token Revocation Model's O(1) revoke-all."""
        interceptor = ServicePermissionInterceptor(_TEST_RPC_MAP, service_name="Test")

        class _AsyncFakeRedis:
            async def exists(self, key: str):
                return 0

            async def get(self, key: str):
                if key == "contextunity:epoch:proj-x":
                    return "2000000000"  # epoch bumped far in the future
                return None

            async def aclose(self):
                return None

        monkeypatch.setattr("redis.asyncio.from_url", lambda *a, **k: _AsyncFakeRedis())
        from contextunity.core.config import get_core_config

        config = get_core_config()
        _enable_redis_for_revocation(monkeypatch, config)

        token = ContextToken(
            token_id="session:proj-x:1000000000",
            iat=1000000000.0,  # issued long before the epoch above
            permissions=(Permissions.BRAIN_READ,),
        )
        assert await interceptor._is_token_revoked(token) is True

    @pytest.mark.asyncio
    async def test_revocation_epoch_check_allows_token_issued_after_bump(self, monkeypatch):
        """A session token issued AFTER the epoch watermark must pass."""
        interceptor = ServicePermissionInterceptor(_TEST_RPC_MAP, service_name="Test")

        class _AsyncFakeRedis:
            async def exists(self, key: str):
                return 0

            async def get(self, key: str):
                if key == "contextunity:epoch:proj-y":
                    return "1000000000"  # epoch bumped in the past
                return None

            async def aclose(self):
                return None

        monkeypatch.setattr("redis.asyncio.from_url", lambda *a, **k: _AsyncFakeRedis())
        from contextunity.core.config import get_core_config

        config = get_core_config()
        _enable_redis_for_revocation(monkeypatch, config)

        token = ContextToken(
            token_id="session:proj-y:2000000000",
            iat=2000000000.0,  # issued after the epoch bump
            permissions=(Permissions.BRAIN_READ,),
        )
        assert await interceptor._is_token_revoked(token) is False

    @pytest.mark.asyncio
    async def test_revocation_epoch_check_uses_precise_iat_not_truncated_token_id(self, monkeypatch):
        """Regression test: a token issued in the SAME integer second as a
        revoke_all bump, but chronologically AFTER it, must not be rejected.

        token_id only has 1-second resolution (``int(now)``); comparing the
        epoch against that truncated value could reject a token issued right
        after a bump within the same second. ``ContextToken.iat`` (a float,
        precise to the microsecond) must be used instead when present.
        """
        interceptor = ServicePermissionInterceptor(_TEST_RPC_MAP, service_name="Test")

        class _AsyncFakeRedis:
            async def exists(self, key: str):
                return 0

            async def get(self, key: str):
                if key == "contextunity:epoch:proj-race":
                    return repr(1000.900)  # revoke_all bumped at 1000.900
                return None

            async def aclose(self):
                return None

        monkeypatch.setattr("redis.asyncio.from_url", lambda *a, **k: _AsyncFakeRedis())
        from contextunity.core.config import get_core_config

        config = get_core_config()
        _enable_redis_for_revocation(monkeypatch, config)

        # Both the bump (1000.900) and the token issue time (1000.950) truncate
        # to the same token_id timestamp "1000" via int(now) — the bug this
        # test guards against would compare 1000 < 1000.900 and wrongly reject.
        token = ContextToken(
            token_id="session:proj-race:1000",
            iat=1000.950,  # issued 50ms AFTER the epoch bump
            permissions=(Permissions.BRAIN_READ,),
        )
        assert await interceptor._is_token_revoked(token) is False

    @pytest.mark.asyncio
    async def test_revocation_epoch_check_skipped_without_iat(self, monkeypatch):
        """A session-shaped token_id with iat=None does NOT fall back to a
        token_id-derived comparison — the epoch check is skipped entirely
        (not approximated), and no Redis connection is opened for it, because
        the sole minter of session tokens (Shield's issue_session_token)
        always sets iat; a session token without one cannot occur in
        practice, so there is nothing to defensively approximate."""
        interceptor = ServicePermissionInterceptor(_TEST_RPC_MAP, service_name="Test")

        def _explode(*a, **k):
            raise AssertionError("must not connect to redis for a session token without iat")

        monkeypatch.setattr("redis.asyncio.from_url", _explode)

        token = ContextToken(
            token_id="session:proj-legacy:1000000000",
            iat=None,
            permissions=(Permissions.BRAIN_READ,),
        )
        assert await interceptor._is_token_revoked(token) is False

    @pytest.mark.asyncio
    async def test_revocation_epoch_check_passes_when_no_epoch_ever_set(self, monkeypatch):
        """No revoke-all has ever occurred for this project: absence of an
        epoch key means pass, not fail-closed (distinct from the explicit
        revocation_id check, which fails closed on missing infrastructure)."""
        interceptor = ServicePermissionInterceptor(_TEST_RPC_MAP, service_name="Test")

        class _AsyncFakeRedis:
            async def exists(self, key: str):
                return 0

            async def get(self, key: str):
                return None

            async def aclose(self):
                return None

        monkeypatch.setattr("redis.asyncio.from_url", lambda *a, **k: _AsyncFakeRedis())
        from contextunity.core.config import get_core_config

        config = get_core_config()
        _enable_redis_for_revocation(monkeypatch, config)

        token = ContextToken(
            token_id="session:proj-z:1000000000",
            iat=1000000000.0,
            permissions=(Permissions.BRAIN_READ,),
        )
        assert await interceptor._is_token_revoked(token) is False

    @pytest.mark.asyncio
    async def test_revocation_skips_redis_for_non_session_non_revocable_token(self, monkeypatch):
        """Tokens that are neither explicitly revocable nor session-shaped must
        not even open a Redis connection (fast path preserved)."""
        interceptor = ServicePermissionInterceptor(_TEST_RPC_MAP, service_name="Test")

        def _explode(*a, **k):
            raise AssertionError("must not connect to redis for a non-revocable, non-session token")

        monkeypatch.setattr("redis.asyncio.from_url", _explode)

        token = ContextToken(
            token_id="not-a-session-token-id",
            permissions=(Permissions.BRAIN_READ,),
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

        pairs = [("authorization", "Bearer abc"), ("x-tenant", "sample_project")]
        for kind in _METADATA_KINDS:
            container = _as_metadata_container(pairs, kind)
            result = invocation_metadata_as_dict(container)
            assert result.get("authorization") == "Bearer abc", f"lost auth header for kind={kind}"
            assert result.get("x-tenant") == "sample_project", f"lost x-tenant for kind={kind}"

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


# ── HMAC Resolution Semantics (v1alpha7) ──


class TestHmacFallbackSemantics:
    """Verify HMAC secret resolution in _build_verifier_backend.

    No-Shield HMAC verification:
      - HMAC tokens use CU_PLATFORM_SECRET
      - missing CU_PLATFORM_SECRET rejects
      - no discovery project-key store exists in the verifier path
    """

    @pytest.mark.asyncio
    async def test_hmac_uses_env_secret(self, monkeypatch):
        """HMAC tokens resolve from CU_PLATFORM_SECRET."""
        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
        )

        from contextunity.core.config import get_core_config

        config = get_core_config()
        monkeypatch.setattr(config.security, "platform_secret", "dev-secret-123")

        token_str = "unregistered-proj:hmac-v1.fakepayload.fakesig"
        backend = await interceptor._build_verifier_backend(token_str)

        assert backend is not None
        from contextunity.core.signing import HmacBackend

        assert isinstance(backend, HmacBackend)

    @pytest.mark.asyncio
    async def test_hmac_without_env_secret_rejects(self, monkeypatch):
        """Missing CU_PLATFORM_SECRET rejects HMAC tokens."""
        interceptor = ServicePermissionInterceptor(
            _TEST_RPC_MAP,
            service_name="Test",
        )

        from contextunity.core.config import get_core_config

        config = get_core_config()
        monkeypatch.setattr(config.security, "platform_secret", "")

        token_str = "registered-proj:hmac-v1.fakepayload.fakesig"
        backend = await interceptor._build_verifier_backend(token_str)

        assert backend is None


@pytest.mark.asyncio
async def test_session_verifier_cache_avoids_repeated_shield_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    from contextunity.core.security import backend_resolver
    from contextunity.core.signing import HmacBackend

    backend_resolver.reset_session_verifier_cache()
    cached = HmacBackend("sample", "secret")
    backend_resolver.cache_session_verifier(
        shield_url="shield:50054",
        kid="sample:session-v1",
        backend=cached,
    )

    async def fail_fetch(*_args: object, **_kwargs: object) -> tuple[str, str]:
        pytest.fail("cached session verifier must not fetch Shield")

    monkeypatch.setattr(
        "contextunity.core.token_utils.fetch_project_public_key_async",
        fail_fetch,
    )
    try:
        resolved = await backend_resolver.build_verifier_backend(
            "sample:session-v1.payload.signature",
            shield_url="shield:50054",
        )
    finally:
        backend_resolver.reset_session_verifier_cache()

    assert resolved is cached


pytestmark = pytest.mark.unit
