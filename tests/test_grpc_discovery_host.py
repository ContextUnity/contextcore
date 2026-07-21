"""Tests for Redis discovery host resolution in start_grpc_server."""

from __future__ import annotations

import pytest
from contextunity.core.grpc_utils import _guess_local_ipv4, redis_register_host

pytestmark = pytest.mark.unit


class TestRedisRegisterHost:
    def test_concrete_bind_host_is_reused(self) -> None:
        assert redis_register_host("192.168.1.20") == "192.168.1.20"

    def test_bind_all_never_published(self) -> None:
        advertised = redis_register_host("0.0.0.0")
        assert advertised not in {"0.0.0.0", "::", "[::]", "*", ""}

    def test_guess_local_ipv4_returns_ipv4_or_localhost(self) -> None:
        host = _guess_local_ipv4()
        assert host == "127.0.0.1" or "." in host
