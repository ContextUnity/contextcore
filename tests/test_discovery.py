"""Tests for contextunity.core.discovery module."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from contextunity.core.discovery import (
    ServiceInfo,
    _redis_key,
)


class TestServiceInfo:
    """Test ServiceInfo dataclass."""

    def test_basic_creation(self):
        info = ServiceInfo(
            service="brain",
            instance="shared",
            endpoint="localhost:50051",
        )
        assert info.service == "brain"
        assert info.instance == "shared"
        assert info.endpoint == "localhost:50051"
        assert info.metadata == {}
        assert info.tenants == []

    def test_with_metadata(self):
        info = ServiceInfo(
            service="worker",
            instance="default",
            endpoint="localhost:7233",
            metadata={"queues": ["harvest", "gardener"]},
        )
        assert info.metadata["queues"] == ["harvest", "gardener"]

    def test_serves_tenant_shared(self):
        """Shared service (empty tenants) serves all tenants."""
        info = ServiceInfo(service="brain", instance="shared", endpoint="localhost:50051")
        assert info.serves_tenant("tenant_b") is True
        assert info.serves_tenant("tenant_a") is True
        assert info.serves_tenant("any") is True

    def test_serves_tenant_scoped(self):
        """Scoped service only serves listed tenants."""
        info = ServiceInfo(
            service="brain",
            instance="tenant_a",
            endpoint="localhost:50053",
            tenants=["tenant_a"],
        )
        assert info.serves_tenant("tenant_a") is True
        assert info.serves_tenant("tenant_b") is False

    def test_serves_tenant_multi(self):
        """Service serving multiple tenants."""
        info = ServiceInfo(
            service="brain",
            instance="shared",
            endpoint="localhost:50051",
            tenants=["tenant_b", "tenant_c"],
        )
        assert info.serves_tenant("tenant_b") is True
        assert info.serves_tenant("tenant_c") is True
        assert info.serves_tenant("tenant_a") is False


class TestRedisKey:
    """Test key formatting."""

    def test_default_prefix(self):
        key = _redis_key("brain", "shared")
        assert key == "contextunity:services:brain:shared"


class FakeRedisDict:
    """In-memory Redis fake to kill mutants that bypass mock structural checks."""

    def __init__(self, data=None):
        self._data = data or {}

    def get(self, key: str) -> str | bytes | None:
        return self._data.get(key)

    def set(self, key: str, value: str | bytes, **kwargs) -> bool:
        self._data[key] = value
        return True

    def keys(self, pattern: str) -> list[str]:
        import re

        # Convert redis glob '*pattern*' to regex '.*pattern.*'
        regex = pattern.replace("*", ".*")
        return [k for k in self._data.keys() if re.match(regex, k)]

    def close(self):
        pass


class TestDiscoverServices:
    """Strong structural tests for discover_services using FakeRedisDict."""

    @pytest.fixture
    def fake_redis(self):
        return FakeRedisDict(
            {
                "contextunity:services:brain:shared": json.dumps(
                    {
                        "endpoint": "localhost:50051",
                        "service": "brain",
                        "instance": "shared",
                        "tenants": [],
                    }
                ),
                "contextunity:services:brain:tenant_a": json.dumps(
                    {
                        "endpoint": "localhost:50053",
                        "service": "brain",
                        "instance": "tenant_a",
                        "tenants": ["tenant_a"],
                    }
                ),
                "contextunity:services:router:default": json.dumps(
                    {
                        "endpoint": "localhost:50050",
                        "service": "router",
                        "instance": "default",
                        "tenants": [],
                    }
                ),
                "contextunity:services:brain:broken": "not-json",
            }
        )

    def test_discover_brain_for_tenant_a(self, fake_redis):
        """tenant_a sees shared + its own scoped instances, but nothing else."""
        from contextunity.core.discovery import discover_services

        with patch("redis.from_url", return_value=fake_redis):
            result = discover_services("brain", tenant_id="tenant_a", redis_url="redis://fake")

        assert len(result) == 2
        instances = {s.instance for s in result}
        assert instances == {"shared", "tenant_a"}

    def test_discover_brain_for_tenant_b(self, fake_redis):
        """tenant_b only sees shared, since tenant_a's is scoped."""
        from contextunity.core.discovery import discover_services

        with patch("redis.from_url", return_value=fake_redis):
            result = discover_services("brain", tenant_id="tenant_b", redis_url="redis://fake")

        assert len(result) == 1
        assert result[0].instance == "shared"

    def test_discover_all_service_types(self, fake_redis):
        """Without service_type, all types are discovered."""
        from contextunity.core.discovery import discover_services

        with patch("redis.from_url", return_value=fake_redis):
            result = discover_services(redis_url="redis://fake")

        services = {s.service for s in result}
        assert services == {"brain", "router"}
        # broken JSON instance is skipped silently
        assert len(result) == 3


pytestmark = pytest.mark.unit
