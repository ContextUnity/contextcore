"""Tests for discovery endpoint resolver behavior."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from contextunity.core.discovery.resolve import resolve_service_endpoint


class _RedisCfg:
    def __init__(self, *, enabled: bool, url: str) -> None:
        self.enabled = enabled
        self.url = url


class _CoreCfg:
    def __init__(self, *, enabled: bool, url: str) -> None:
        self.redis = _RedisCfg(enabled=enabled, url=url)


def test_skips_discovery_when_redis_disabled() -> None:
    cfg = _CoreCfg(enabled=False, url="")
    with (
        patch("contextunity.core.discovery.resolve.get_core_config", return_value=cfg),
        patch("contextunity.core.discovery.resolve.discover_services") as discover,
    ):
        endpoint = resolve_service_endpoint(
            "shield",
            configured_host="localhost:50054",
            default_host="localhost:50054",
        )
        assert endpoint == "localhost:50054"
        discover.assert_not_called()


def test_uses_discovery_when_redis_enabled() -> None:
    cfg = _CoreCfg(enabled=True, url="redis://localhost:6379/0")

    class _Svc:
        endpoint = "redis-shield:50054"
        instance = "shared"

    with (
        patch("contextunity.core.discovery.resolve.get_core_config", return_value=cfg),
        patch("contextunity.core.discovery.resolve.discover_services", return_value=[_Svc()]) as discover,
    ):
        endpoint = resolve_service_endpoint(
            "shield",
            configured_host="localhost:50054",
            default_host="localhost:50054",
        )
        assert endpoint == "redis-shield:50054"
        discover.assert_called_once()


pytestmark = pytest.mark.unit
