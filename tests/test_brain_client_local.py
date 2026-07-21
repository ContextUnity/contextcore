"""Tests for BrainClient host resolution priority.

Verifies the behavior chain: explicit host= > env CU_BRAIN_GRPC_URL > default localhost:50051.
Does NOT test gRPC channel wiring (that's an implementation detail).
"""

from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import grpc
import pytest
from contextunity.core import ContextToken
from contextunity.core.signing import (
    HmacBackend,
    SessionTokenBackend,
    reset_signing_backend,
    set_signing_backend,
)


@pytest.fixture(autouse=True)
def _reset_core_config() -> Iterator[None]:
    from contextunity.core.authz.context import reset_auth_context
    from contextunity.core.config import reset_core_config

    reset_auth_context()
    reset_core_config()
    reset_signing_backend()
    yield
    reset_auth_context()
    reset_signing_backend()
    reset_core_config()


@pytest.mark.parametrize(
    ("env_url", "explicit_host", "expected_host"),
    [
        (None, None, "localhost:50051"),
        ("brain.example.com:50051", None, "brain.example.com:50051"),
        ("config-host:50051", "explicit-host:50051", "explicit-host:50051"),
    ],
    ids=["default", "env-override", "explicit-wins-over-env"],
)
def test_brain_client_host_resolution(monkeypatch, env_url, explicit_host, expected_host):
    """Host resolution: explicit > env > default."""
    # Isolate from a running Compose mesh: Redis discovery must not override defaults.
    monkeypatch.setenv("REDIS_ENABLED", "false")
    monkeypatch.delenv("CU_BRAIN_GRPC_URL", raising=False)
    monkeypatch.delenv("BRAIN_URL", raising=False)
    if env_url:
        monkeypatch.setenv("CU_BRAIN_GRPC_URL", env_url)

    with patch("contextunity.core.grpc_utils.create_channel", return_value=MagicMock()):
        from contextunity.core.sdk.clients.brain.base import BrainClientBase

        kwargs = {"host": explicit_host} if explicit_host else {}
        client = BrainClientBase(**kwargs)
        assert client.host == expected_host


def test_brain_client_explicit_backend_isolated_from_process_global() -> None:
    """An autonomous client must sign with its own service backend."""
    global_backend = HmacBackend("global-project", "global-secret")
    worker_backend = HmacBackend("worker-project", "worker-secret")
    set_signing_backend(global_backend)
    token = ContextToken(
        token_id="worker-brain",
        permissions=("brain:read",),
        allowed_tenants=("tenant-a",),
    )

    with patch("contextunity.core.grpc_utils.create_channel", return_value=MagicMock()):
        from contextunity.core.sdk.clients.brain.base import BrainClientBase

        client = BrainClientBase(
            host="brain:50051",
            token=token,
            auth_backend=worker_backend,
        )

    bearer = client._get_metadata()[0][1]
    assert bearer.startswith("Bearer worker-project:hmac-001.")
    assert global_backend.verify(bearer.removeprefix("Bearer ")) is None


def test_explicit_token_does_not_forward_mismatched_ambient_auth_context() -> None:
    from contextunity.core.authz.context import VerifiedAuthContext, set_auth_context
    from contextunity.core.token_utils.grpc import create_grpc_metadata_with_token

    ambient_backend = HmacBackend("ambient-project", "ambient-secret")
    explicit_backend = HmacBackend("explicit-project", "explicit-secret")
    ambient_token = ContextToken(
        token_id="ambient",
        permissions=("brain:read",),
        allowed_tenants=("tenant-a",),
    )
    explicit_token = ContextToken(
        token_id="explicit",
        permissions=("brain:read",),
        allowed_tenants=("tenant-a",),
    )
    ambient_bearer = create_grpc_metadata_with_token(
        ambient_token,
        backend=ambient_backend,
    )[0][1].removeprefix("Bearer ")
    set_auth_context(VerifiedAuthContext.from_token(ambient_token, ambient_bearer))

    with patch("contextunity.core.grpc_utils.create_channel", return_value=MagicMock()):
        from contextunity.core.sdk.clients.brain.base import BrainClientBase

        client = BrainClientBase(
            host="brain:50051",
            token=explicit_token,
            auth_backend=explicit_backend,
        )

    bearer = client._get_metadata()[0][1]
    assert bearer.startswith("Bearer explicit-project:hmac-001.")
    assert bearer != f"Bearer {ambient_bearer}"


def test_brain_client_accepts_explicit_service_session_without_nested_token() -> None:
    """Autonomous service sessions provide their own complete bearer metadata."""
    backend = SessionTokenBackend(
        project_id="sample",
        session_token="shield-session",
        kid="sample:session-v1",
        expires_at=4_102_444_800.0,
        shield_url="shield:50054",
    )

    with patch("contextunity.core.grpc_utils.create_channel", return_value=MagicMock()):
        from contextunity.core.sdk.clients.brain.base import BrainClientBase

        client = BrainClientBase(
            host="brain:50051",
            auth_backend=backend,
        )

    assert client._get_metadata() == (("authorization", "Bearer shield-session"),)


def test_brain_client_without_token_or_backend_fails_closed() -> None:
    with patch("contextunity.core.grpc_utils.create_channel", return_value=MagicMock()):
        from contextunity.core.sdk.clients.brain.base import BrainClientBase

        client = BrainClientBase(host="brain:50051")

    with pytest.raises(PermissionError, match="no ContextToken or client-owned AuthBackend"):
        client._get_metadata()


@pytest.mark.asyncio
async def test_get_cell_returns_none_for_not_found_rpc(monkeypatch: pytest.MonkeyPatch) -> None:
    from contextunity.core.sdk.clients.brain.knowledge import KnowledgeMixin
    from contextunity.core.sdk.contextunit import ContextUnit

    class _NotFound(grpc.RpcError):
        def code(self) -> grpc.StatusCode:
            return grpc.StatusCode.NOT_FOUND

    class _Stub:
        async def GetCell(self, _request: object, *, metadata: object) -> object:
            del metadata
            raise _NotFound()

    client = KnowledgeMixin()
    client._stub = _Stub()
    client._cu_pb2 = object()
    client._get_metadata = lambda: ()
    monkeypatch.setattr(ContextUnit, "to_protobuf", lambda _self, _pb2: object())

    assert await client.get_cell(cell_id="missing", tenant_id="_doc") is None


@pytest.mark.asyncio
async def test_search_cells_forwards_bounded_metadata_filter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from contextunity.core.sdk.clients.brain.knowledge import KnowledgeMixin
    from contextunity.core.sdk.contextunit import ContextUnit

    captured: dict[str, object] = {}

    class _Stub:
        async def SearchCells(self, _request: object, *, metadata: object):
            del metadata
            if False:
                yield object()

    def encode(unit: ContextUnit, _pb2: object) -> object:
        captured.update(unit.payload)
        return object()

    client = KnowledgeMixin()
    client._stub = _Stub()
    client._cu_pb2 = object()
    client._get_metadata = lambda: ()
    monkeypatch.setattr(ContextUnit, "to_protobuf", encode)

    assert (
        await client.search_cells(
            query_text="architecture",
            tenant_id="_doc",
            metadata_filter={"service": "contextunity.docs"},
        )
        == []
    )
    assert captured["metadata_filter"] == {"service": "contextunity.docs"}


pytestmark = pytest.mark.unit
