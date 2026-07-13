"""Tests for BrainClient host resolution priority.

Verifies the behavior chain: explicit host= > env CU_BRAIN_GRPC_URL > default localhost:50051.
Does NOT test gRPC channel wiring (that's an implementation detail).
"""

from collections.abc import Iterator
from unittest.mock import MagicMock, patch

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
    from contextunity.core.config import reset_core_config

    reset_core_config()
    reset_signing_backend()
    yield
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


pytestmark = pytest.mark.unit
