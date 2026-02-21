"""Tests for contextcore.discovery module."""

from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock, patch

import pytest
from contextcore.discovery import (
    ServiceInfo,
    _redis_key,
    discover_endpoints,
    discover_services,
)


@pytest.fixture(autouse=True)
def _ensure_redis_module():
    """Ensure a mock redis module is available for tests that need it."""
    if "redis" not in sys.modules:
        mock_redis = MagicMock()
        sys.modules["redis"] = mock_redis
        yield
        del sys.modules["redis"]
    else:
        yield


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
        assert info.serves_tenant("traverse") is True
        assert info.serves_tenant("nszu") is True
        assert info.serves_tenant("any") is True

    def test_serves_tenant_scoped(self):
        """Scoped service only serves listed tenants."""
        info = ServiceInfo(
            service="brain",
            instance="nszu",
            endpoint="localhost:50053",
            tenants=["nszu"],
        )
        assert info.serves_tenant("nszu") is True
        assert info.serves_tenant("traverse") is False

    def test_serves_tenant_multi(self):
        """Service serving multiple tenants."""
        info = ServiceInfo(
            service="brain",
            instance="shared",
            endpoint="localhost:50051",
            tenants=["traverse", "pinkpony"],
        )
        assert info.serves_tenant("traverse") is True
        assert info.serves_tenant("pinkpony") is True
        assert info.serves_tenant("nszu") is False


class TestRedisKey:
    """Test key formatting."""

    def test_default_prefix(self):
        key = _redis_key("brain", "shared")
        assert key == "contextunity:services:brain:shared"

    def test_custom_prefix(self):
        """Custom prefix via SERVICE_DISCOVERY_PREFIX env var (via load_shared_config_from_env)."""
        from unittest.mock import MagicMock

        mock_config = MagicMock()
        mock_config.service_discovery_prefix = "myapp:svc"
        mock_config.redis_url = None

        with patch("contextcore.discovery.load_shared_config_from_env", return_value=mock_config):
            key = _redis_key("router", "default")
        assert key == "myapp:svc:router:default"


class TestDiscoverServices:
    """Test synchronous discovery."""

    def test_no_redis_url_returns_empty(self):
        result = discover_services(redis_url=None)
        assert result == []

    def test_redis_not_installed_returns_empty(self):
        with patch.dict("sys.modules", {"redis": None}):
            result = discover_services(redis_url="redis://localhost:6379/0")
            assert isinstance(result, list)

    def test_discover_parses_redis_data(self):
        """Test parsing of Redis data when redis is available."""
        mock_redis = MagicMock()
        mock_redis.keys.return_value = [
            "contextunity:services:brain:shared",
            "contextunity:services:brain:nszu",
        ]
        mock_redis.get.side_effect = [
            json.dumps(
                {
                    "endpoint": "localhost:50051",
                    "service": "brain",
                    "instance": "shared",
                    "tenants": [],
                }
            ),
            json.dumps(
                {
                    "endpoint": "localhost:50053",
                    "service": "brain",
                    "instance": "nszu",
                    "tenants": ["nszu"],
                }
            ),
        ]

        with patch("redis.from_url", return_value=mock_redis):
            result = discover_services(service_type="brain", redis_url="redis://localhost:6379/0")

        assert len(result) == 2
        assert result[0].service == "brain"
        assert result[0].tenants == []  # shared
        assert result[1].tenants == ["nszu"]

    def test_discover_with_tenant_filter(self):
        """Test tenant-scoped discovery: traverse sees shared + traverse-scoped, not nszu."""
        mock_redis = MagicMock()
        mock_redis.keys.return_value = [
            "contextunity:services:brain:shared",
            "contextunity:services:brain:nszu",
        ]
        mock_redis.get.side_effect = [
            json.dumps(
                {
                    "endpoint": "localhost:50051",
                    "service": "brain",
                    "instance": "shared",
                    "tenants": [],  # shared → visible to all
                }
            ),
            json.dumps(
                {
                    "endpoint": "localhost:50053",
                    "service": "brain",
                    "instance": "nszu",
                    "tenants": ["nszu"],  # scoped → only nszu
                }
            ),
        ]

        with patch("redis.from_url", return_value=mock_redis):
            # traverse should see shared but NOT nszu
            result = discover_services(
                service_type="brain",
                tenant_id="traverse",
                redis_url="redis://localhost:6379/0",
            )

        assert len(result) == 1
        assert result[0].instance == "shared"

    def test_discover_admin_sees_all(self):
        """Admin (no tenant_id) sees all instances."""
        mock_redis = MagicMock()
        mock_redis.keys.return_value = [
            "contextunity:services:brain:shared",
            "contextunity:services:brain:nszu",
        ]
        mock_redis.get.side_effect = [
            json.dumps(
                {
                    "endpoint": "localhost:50051",
                    "service": "brain",
                    "instance": "shared",
                    "tenants": [],
                }
            ),
            json.dumps(
                {
                    "endpoint": "localhost:50053",
                    "service": "brain",
                    "instance": "nszu",
                    "tenants": ["nszu"],
                }
            ),
        ]

        with patch("redis.from_url", return_value=mock_redis):
            result = discover_services(
                service_type="brain",
                tenant_id=None,  # admin
                redis_url="redis://localhost:6379/0",
            )

        assert len(result) == 2

    def test_discover_all_service_types(self):
        """Test discovering all service types at once."""
        mock_redis = MagicMock()
        mock_redis.keys.return_value = [
            "contextunity:services:brain:shared",
            "contextunity:services:router:default",
            "contextunity:services:worker:default",
        ]
        mock_redis.get.side_effect = [
            json.dumps(
                {
                    "endpoint": "localhost:50051",
                    "service": "brain",
                    "instance": "shared",
                    "tenants": [],
                }
            ),
            json.dumps(
                {
                    "endpoint": "localhost:50050",
                    "service": "router",
                    "instance": "default",
                    "tenants": [],
                }
            ),
            json.dumps(
                {
                    "endpoint": "localhost:7233",
                    "service": "worker",
                    "instance": "default",
                    "tenants": [],
                    "queues": ["harvest"],
                }
            ),
        ]

        with patch("redis.from_url", return_value=mock_redis):
            result = discover_services(redis_url="redis://localhost:6379/0")

        assert len(result) == 3
        services = {s.service for s in result}
        assert services == {"brain", "router", "worker"}

    def test_discover_handles_invalid_json(self):
        mock_redis = MagicMock()
        mock_redis.keys.return_value = ["contextunity:services:brain:broken"]
        mock_redis.get.return_value = "not-json"

        with patch("redis.from_url", return_value=mock_redis):
            result = discover_services(service_type="brain", redis_url="redis://localhost:6379/0")

        assert len(result) == 0


class TestDiscoverEndpoints:
    """Test the convenience endpoint discovery."""

    def test_returns_dict(self):
        mock_redis = MagicMock()
        mock_redis.keys.return_value = [
            "contextunity:services:brain:shared",
            "contextunity:services:brain:nszu",
        ]
        mock_redis.get.side_effect = [
            json.dumps(
                {
                    "endpoint": "localhost:50051",
                    "service": "brain",
                    "instance": "shared",
                    "tenants": [],
                }
            ),
            json.dumps(
                {
                    "endpoint": "localhost:50053",
                    "service": "brain",
                    "instance": "nszu",
                    "tenants": ["nszu"],
                }
            ),
        ]

        with patch("redis.from_url", return_value=mock_redis):
            result = discover_endpoints("brain", redis_url="redis://localhost:6379/0")

        assert result == {
            "shared": "localhost:50051",
            "nszu": "localhost:50053",
        }

    def test_with_tenant_filter(self):
        """discover_endpoints with tenant shows only relevant endpoints."""
        mock_redis = MagicMock()
        mock_redis.keys.return_value = [
            "contextunity:services:brain:shared",
            "contextunity:services:brain:nszu",
        ]
        mock_redis.get.side_effect = [
            json.dumps(
                {
                    "endpoint": "localhost:50051",
                    "service": "brain",
                    "instance": "shared",
                    "tenants": [],
                }
            ),
            json.dumps(
                {
                    "endpoint": "localhost:50053",
                    "service": "brain",
                    "instance": "nszu",
                    "tenants": ["nszu"],
                }
            ),
        ]

        with patch("redis.from_url", return_value=mock_redis):
            result = discover_endpoints("brain", tenant_id="traverse", redis_url="redis://localhost:6379/0")

        # traverse should see shared but not nszu
        assert result == {"shared": "localhost:50051"}

    def test_empty_when_no_services(self):
        mock_redis = MagicMock()
        mock_redis.keys.return_value = []

        with patch("redis.from_url", return_value=mock_redis):
            result = discover_endpoints("brain", redis_url="redis://localhost:6379/0")

        assert result == {}


class TestProjectRegistry:
    """Tests for project registry (register_project, verify_project_owner, get_registered_projects)."""

    def test_register_new_project(self):
        """First registration of a project succeeds."""
        from contextcore.discovery import register_project

        mock_redis = MagicMock()
        mock_redis.get.return_value = None  # Not registered yet

        with patch("redis.from_url", return_value=mock_redis):
            result = register_project("nszu", "nszu", tools=["execute_medical_sql"], redis_url="redis://localhost")

        assert result is True
        mock_redis.set.assert_called_once()

    def test_register_same_owner_idempotent(self):
        """Re-registering by same owner is idempotent."""
        from contextcore.discovery import register_project

        mock_redis = MagicMock()
        mock_redis.get.return_value = json.dumps(
            {
                "project_id": "nszu",
                "owner_tenant": "nszu",
                "tools": ["old_tool"],
            }
        )

        with patch("redis.from_url", return_value=mock_redis):
            result = register_project("nszu", "nszu", tools=["new_tool"], redis_url="redis://localhost")

        assert result is True
        mock_redis.set.assert_called_once()

    def test_register_different_owner_conflict(self):
        """Registering a project already owned by another tenant fails."""
        from contextcore.discovery import register_project

        mock_redis = MagicMock()
        mock_redis.get.return_value = json.dumps(
            {
                "project_id": "nszu",
                "owner_tenant": "nszu",
                "tools": [],
            }
        )

        with patch("redis.from_url", return_value=mock_redis):
            result = register_project("nszu", "attacker", tools=[], redis_url="redis://localhost")

        assert result is False
        mock_redis.set.assert_not_called()

    def test_verify_owner_matches(self):
        """verify_project_owner returns True when owner matches."""
        from contextcore.discovery import verify_project_owner

        mock_redis = MagicMock()
        mock_redis.get.return_value = json.dumps(
            {
                "project_id": "nszu",
                "owner_tenant": "nszu",
                "tools": [],
            }
        )

        with patch("redis.from_url", return_value=mock_redis):
            assert verify_project_owner("nszu", "nszu", redis_url="redis://localhost") is True

    def test_verify_owner_mismatch(self):
        """verify_project_owner returns False when owner doesn't match."""
        from contextcore.discovery import verify_project_owner

        mock_redis = MagicMock()
        mock_redis.get.return_value = json.dumps(
            {
                "project_id": "nszu",
                "owner_tenant": "nszu",
                "tools": [],
            }
        )

        with patch("redis.from_url", return_value=mock_redis):
            assert verify_project_owner("nszu", "attacker", redis_url="redis://localhost") is False

    def test_verify_unregistered_allows(self):
        """verify_project_owner allows unregistered projects (first-time)."""
        from contextcore.discovery import verify_project_owner

        mock_redis = MagicMock()
        mock_redis.get.return_value = None

        with patch("redis.from_url", return_value=mock_redis):
            assert verify_project_owner("new_project", "any_tenant", redis_url="redis://localhost") is True

    def test_get_registered_projects(self):
        """get_registered_projects returns all registered projects."""
        from contextcore.discovery import get_registered_projects

        mock_redis = MagicMock()
        mock_redis.keys.return_value = [
            "contextunity:projects:nszu",
            "contextunity:projects:traverse",
        ]
        mock_redis.get.side_effect = [
            json.dumps({"project_id": "nszu", "owner_tenant": "nszu", "tools": ["sql"]}),
            json.dumps({"project_id": "traverse", "owner_tenant": "traverse", "tools": []}),
        ]

        with patch("redis.from_url", return_value=mock_redis):
            projects = get_registered_projects(redis_url="redis://localhost")

        assert len(projects) == 2
        ids = {p["project_id"] for p in projects}
        assert ids == {"nszu", "traverse"}

    def test_graceful_degradation_no_redis(self):
        """Functions degrade gracefully without Redis."""
        from contextcore.discovery import get_registered_projects, register_project, verify_project_owner

        with patch.dict("sys.modules", {"redis": None}):
            assert register_project("x", "x") is True
            assert verify_project_owner("x", "x") is True
            assert get_registered_projects() == []
