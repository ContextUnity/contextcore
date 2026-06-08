"""Tests for BrainClient host resolution priority.

Verifies the behavior chain: explicit host= > env CU_BRAIN_GRPC_URL > default localhost:50051.
Does NOT test gRPC channel wiring (that's an implementation detail).
"""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _reset_core_config():
    from contextunity.core.config import reset_core_config

    reset_core_config()
    yield
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
    if env_url:
        monkeypatch.setenv("CU_BRAIN_GRPC_URL", env_url)

    with patch("contextunity.core.grpc_utils.create_channel", return_value=MagicMock()):
        from contextunity.core.sdk.clients.brain.base import BrainClientBase

        kwargs = {"host": explicit_host} if explicit_host else {}
        client = BrainClientBase(**kwargs)
        assert client.host == expected_host


pytestmark = pytest.mark.unit
