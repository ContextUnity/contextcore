"""Tests for SharedConfig."""

from __future__ import annotations

import pytest
from contextunity.core import LogLevel, SharedConfig
from contextunity.core.config import get_core_config, reset_core_config
from contextunity.core.manifest.models import ContextUnityProject
from contextunity.core.sdk.config import ProjectBootstrapConfig


class TestSharedConfig:
    """Tests for SharedConfig model."""

    def test_create_default_config(self) -> None:
        """Test creating a SharedConfig with defaults."""
        config = SharedConfig()
        assert config.log_level == LogLevel.INFO
        assert config.redis.enabled is True
        assert config.redis.url == "redis://localhost:6379/0"
        assert config.service_name is None
        assert config.service_version is None
        assert config.router_url == "localhost:50050"
        assert config.brain_url == "localhost:50051"
        assert config.worker_url == "localhost:50052"
        assert config.shield_url == "localhost:50054"

    def test_local_mode_preserves_config(self) -> None:
        """Test that local_mode does not override explicit config values."""
        config = SharedConfig(local_mode=True)
        # shield keeps default — local_mode does not force anything
        assert config.shield_url == "localhost:50054"
        # Redis keeps its default (enabled=True) unless explicitly disabled
        assert config.redis.enabled is True

    def test_redis_disabled_clears_url(self) -> None:
        """Test that redis.enabled=False clears redis.url via model_post_init."""
        config = SharedConfig(redis={"enabled": False})
        assert config.redis.url == ""

    def test_create_custom_config(self) -> None:
        """Test creating a SharedConfig with custom values."""
        config = SharedConfig(
            log_level=LogLevel.DEBUG,
            redis={"url": "redis://localhost:6379/0"},
            service_name="test-service",
            service_version="1.0.0",
        )
        assert config.log_level == LogLevel.DEBUG
        assert config.redis.url == "redis://localhost:6379/0"
        assert config.service_name == "test-service"
        assert config.service_version == "1.0.0"

    def test_log_level_from_string(self) -> None:
        """Test creating config with log level as string."""
        config = SharedConfig(log_level="DEBUG")
        assert config.log_level == LogLevel.DEBUG

    def test_log_level_invalid(self) -> None:
        """Test creating config with invalid log level."""
        with pytest.raises(ValueError, match="Invalid log level"):
            SharedConfig(log_level="INVALID")

    def test_redis_url_validation_valid(self) -> None:
        """Test valid Redis URL formats."""
        valid_urls = [
            "redis://localhost:6379/0",
            "rediss://localhost:6379/0",
            "unix:///tmp/redis.sock",
        ]
        for url in valid_urls:
            config = SharedConfig(redis={"url": url})
            assert config.redis.url == url

    def test_redis_url_validation_invalid(self) -> None:
        """Test invalid Redis URL formats."""
        invalid_urls = [
            "http://localhost:6379",
            "invalid://localhost:6379",
            "localhost:6379",
        ]
        for url in invalid_urls:
            with pytest.raises(ValueError):
                SharedConfig(redis={"url": url})

    def test_redis_url_empty(self) -> None:
        """Test Redis URL can be empty."""
        config = SharedConfig(redis={"url": ""})
        assert config.redis.url == ""

    def test_extra_fields_forbidden(self) -> None:
        """Test that extra fields are forbidden."""
        with pytest.raises(Exception):  # Pydantic validation error
            SharedConfig(extra_field="value")  # type: ignore[call-arg]


class TestGetCoreConfig:
    """Tests for get_core_config singleton (env-only, no YAML)."""

    def test_load_defaults(self, monkeypatch) -> None:
        """Test loading config with no environment variables."""
        monkeypatch.delenv("REDIS_URL", raising=False)
        monkeypatch.delenv("LOG_LEVEL", raising=False)
        monkeypatch.delenv("CU_LOCAL_MODE", raising=False)
        # Suppress YAML file reading to test pure defaults
        monkeypatch.setattr("contextunity.core.config.factory.read_service_file", lambda *_a, **_kw: None)
        reset_core_config()
        try:
            config = get_core_config()
            assert config.log_level == LogLevel.INFO
            assert config.redis.enabled is True
            assert config.redis.url == "redis://localhost:6379/0"
            assert config.router_url == "localhost:50050"
            assert config.brain_url == "localhost:50051"
            assert config.worker_url == "localhost:50052"
        finally:
            reset_core_config()

    def test_load_from_env(self, monkeypatch) -> None:
        """Test loading config from environment variables."""
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")
        monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
        monkeypatch.setenv("SERVICE_NAME", "test-service")
        monkeypatch.setenv("SERVICE_VERSION", "1.0.0")
        # Suppress YAML file reading to test env-only
        monkeypatch.setattr("contextunity.core.config.factory.read_service_file", lambda *_a, **_kw: None)
        reset_core_config()
        try:
            config = get_core_config()
            assert config.log_level == LogLevel.DEBUG
            assert config.redis.url == "redis://localhost:6379/0"
            assert config.service_name == "test-service"
            assert config.service_version == "1.0.0"
        finally:
            reset_core_config()


class TestProjectBootstrapConfig:
    """Contract tests for SDK bootstrap config helpers."""

    @staticmethod
    def _manifest_with_node_secrets() -> ContextUnityProject:
        return ContextUnityProject.model_validate(
            {
                "apiVersion": "contextunity/v1alpha7",
                "kind": "ContextUnityProject",
                "project": {"id": "proj", "name": "Project"},
                "services": {"router": {"enabled": True}},
                "router": {
                    "default_graph": "demo",
                    "graph": {
                        "demo": {
                            "nodes": [
                                {
                                    "name": "planner",
                                    "type": "llm",
                                    "model": "openai/gpt-5-mini",
                                    "model_secret_ref": "OPENAI_KEY",
                                }
                            ],
                            "edges": [
                                {"from_node": "__start__", "to_node": "planner"},
                                {"from_node": "planner", "to_node": "__end__"},
                            ],
                        }
                    },
                    "policy": {"models": {"llm": {"default": "openai/gpt-5-mini"}}},
                },
            }
        )

    def test_resolve_secrets_uses_secure_node_path_contract(self, monkeypatch) -> None:
        manifest = self._manifest_with_node_secrets()
        monkeypatch.setenv("OPENAI_KEY", "secret-value")

        secrets = ProjectBootstrapConfig().resolve_secrets(manifest)

        assert secrets == {"planner/model_secret_ref": "secret-value"}

    def test_resolve_secrets_warns_on_node_name_collision(self, monkeypatch, caplog) -> None:
        manifest = ContextUnityProject.model_validate(
            {
                "apiVersion": "contextunity/v1alpha7",
                "kind": "ContextUnityProject",
                "project": {"id": "proj", "name": "Project"},
                "services": {"router": {"enabled": True}},
                "router": {
                    "default_graph": "g1",
                    "graph": {
                        "g1": {
                            "nodes": [
                                {
                                    "name": "planner",
                                    "type": "llm",
                                    "model": "openai/gpt-5-mini",
                                    "model_secret_ref": "OPENAI_KEY_A",
                                }
                            ],
                            "edges": [
                                {"from_node": "__start__", "to_node": "planner"},
                                {"from_node": "planner", "to_node": "__end__"},
                            ],
                        },
                        "g2": {
                            "nodes": [
                                {
                                    "name": "planner",
                                    "type": "llm",
                                    "model": "openai/gpt-5-mini",
                                    "model_secret_ref": "OPENAI_KEY_B",
                                }
                            ],
                            "edges": [
                                {"from_node": "__start__", "to_node": "planner"},
                                {"from_node": "planner", "to_node": "__end__"},
                            ],
                        },
                    },
                    "policy": {"models": {"llm": {"default": "openai/gpt-5-mini"}}},
                },
            }
        )
        monkeypatch.setenv("OPENAI_KEY_A", "secret-a")
        monkeypatch.setenv("OPENAI_KEY_B", "secret-b")

        secrets = ProjectBootstrapConfig().resolve_secrets(manifest)

        assert secrets["planner/model_secret_ref"] == "secret-b"
        assert "Per-node secret collision at planner/model_secret_ref" in caplog.text

    def test_resolve_secrets_includes_policy_langfuse_refs(self, monkeypatch) -> None:
        manifest = ContextUnityProject.model_validate(
            {
                "apiVersion": "contextunity/v1alpha7",
                "kind": "ContextUnityProject",
                "project": {"id": "proj", "name": "Project"},
                "services": {"router": {"enabled": True}},
                "router": {
                    "default_graph": "g1",
                    "graph": {
                        "g1": {
                            "template": "yaml:demo",
                        },
                    },
                    "policy": {
                        "models": {"llm": {"default": "openai/gpt-5-mini"}},
                        "langfuse": {
                            "tracing_enabled": True,
                            "public_key_ref": "LF_PUB",
                            "secret_key_ref": "LF_SEC",
                        },
                    },
                },
            }
        )
        monkeypatch.setenv("LF_PUB", "pk-test")
        monkeypatch.setenv("LF_SEC", "sk-test")

        secrets = ProjectBootstrapConfig().resolve_secrets(manifest)

        assert secrets["LF_PUB"] == "pk-test"
        assert secrets["LF_SEC"] == "sk-test"

    def test_resolve_secrets_skips_langfuse_when_tracing_disabled(self, monkeypatch) -> None:
        manifest = ContextUnityProject.model_validate(
            {
                "apiVersion": "contextunity/v1alpha7",
                "kind": "ContextUnityProject",
                "project": {"id": "proj", "name": "Project"},
                "services": {"router": {"enabled": True}},
                "router": {
                    "default_graph": "g1",
                    "graph": {"g1": {"template": "yaml:demo"}},
                    "policy": {
                        "models": {"llm": {"default": "openai/gpt-5-mini"}},
                        "langfuse": {
                            "tracing_enabled": False,
                            "public_key_ref": "LF_PUB",
                        },
                    },
                },
            }
        )
        monkeypatch.delenv("LF_PUB", raising=False)

        secrets = ProjectBootstrapConfig().resolve_secrets(manifest)

        assert "LF_PUB" not in secrets


class TestServiceConfigRegistry:
    """Tests for ServiceConfigRegistry lifecycle and core config propagation."""

    def test_propagation_and_lifecycle(self) -> None:
        """Test that ServiceConfigRegistry get, set, and reset propagate config to get_core_config."""
        from contextunity.core.config import ServiceConfig, ServiceConfigRegistry
        from pydantic import Field

        class MockServiceConfig(ServiceConfig):
            service_name: str = "mock-service"
            custom_val: str = Field(default="hello")

        registry = ServiceConfigRegistry(lambda: MockServiceConfig(redis={"url": "redis://localhost:1234/1"}))

        reset_core_config()
        registry.reset()

        try:
            # 1. Before loading, get_core_config should be default core config
            core_cfg = get_core_config()
            # It might load from environment, but should not have our mock registry's custom Redis URL
            assert core_cfg.redis.url != "redis://localhost:1234/1"

            # 2. Accessing registry via .get() should propagate
            svc_cfg = registry.get()
            assert svc_cfg.custom_val == "hello"

            core_cfg_after = get_core_config()
            assert core_cfg_after is svc_cfg
            assert core_cfg_after.redis.url == "redis://localhost:1234/1"

            # 3. Setting a new instance should propagate
            new_cfg = MockServiceConfig(redis={"url": "redis://localhost:5678/2"})
            registry.set(new_cfg)
            assert get_core_config() is new_cfg

            # 4. Resetting the registry should reset the core config
            registry.reset()
            assert get_core_config() is not new_cfg
        finally:
            reset_core_config()
            registry.reset()


pytestmark = pytest.mark.unit
