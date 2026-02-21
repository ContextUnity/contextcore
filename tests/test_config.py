"""Tests for SharedConfig."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from contextcore import LogLevel, SharedConfig, load_shared_config_from_env


class TestSharedConfig:
    """Tests for SharedConfig model."""

    def test_create_default_config(self) -> None:
        """Test creating a SharedConfig with defaults."""
        config = SharedConfig()
        assert config.log_level == LogLevel.INFO
        assert config.redis_url is None
        assert config.otel_enabled is False
        assert config.otel_endpoint is None
        assert config.service_name is None
        assert config.service_version is None
        assert config.tenant_id is None

    def test_create_custom_config(self) -> None:
        """Test creating a SharedConfig with custom values."""
        config = SharedConfig(
            log_level=LogLevel.DEBUG,
            redis_url="redis://localhost:6379/0",
            otel_enabled=True,
            otel_endpoint="http://localhost:4318",
            service_name="test-service",
            service_version="1.0.0",
            tenant_id="tenant-123",
        )
        assert config.log_level == LogLevel.DEBUG
        assert config.redis_url == "redis://localhost:6379/0"
        assert config.otel_enabled is True
        assert config.otel_endpoint == "http://localhost:4318"
        assert config.service_name == "test-service"
        assert config.service_version == "1.0.0"
        assert config.tenant_id == "tenant-123"

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
            config = SharedConfig(redis_url=url)
            assert config.redis_url == url

    def test_redis_url_validation_invalid(self) -> None:
        """Test invalid Redis URL formats."""
        invalid_urls = [
            "http://localhost:6379",
            "invalid://localhost:6379",
            "localhost:6379",
        ]
        for url in invalid_urls:
            with pytest.raises(ValueError, match="Redis URL must start with"):
                SharedConfig(redis_url=url)

    def test_redis_url_none(self) -> None:
        """Test Redis URL can be None."""
        config = SharedConfig(redis_url=None)
        assert config.redis_url is None

    def test_extra_fields_forbidden(self) -> None:
        """Test that extra fields are forbidden."""
        with pytest.raises(Exception):  # Pydantic validation error
            SharedConfig(extra_field="value")  # type: ignore[call-arg]


class TestLoadSharedConfigFromEnv:
    """Tests for load_shared_config_from_env function."""

    @patch.dict(os.environ, {}, clear=True)
    def test_load_defaults(self) -> None:
        """Test loading config with no environment variables."""
        config = load_shared_config_from_env()
        assert config.log_level == LogLevel.INFO
        assert config.redis_url is None
        assert config.otel_enabled is False

    @patch.dict(
        os.environ,
        {
            "LOG_LEVEL": "DEBUG",
            "REDIS_URL": "redis://localhost:6379/0",
            "OTEL_ENABLED": "true",
            "OTEL_ENDPOINT": "http://localhost:4318",
            "SERVICE_NAME": "test-service",
            "SERVICE_VERSION": "1.0.0",
            "TENANT_ID": "tenant-123",
        },
        clear=True,
    )
    def test_load_from_env(self) -> None:
        """Test loading config from environment variables."""
        config = load_shared_config_from_env()
        assert config.log_level == LogLevel.DEBUG
        assert config.redis_url == "redis://localhost:6379/0"
        assert config.otel_enabled is True
        assert config.otel_endpoint == "http://localhost:4318"
        assert config.service_name == "test-service"
        assert config.service_version == "1.0.0"
        assert config.tenant_id == "tenant-123"

    @patch.dict(os.environ, {"OTEL_ENABLED": "1"}, clear=True)
    def test_otel_enabled_variants(self) -> None:
        """Test OTEL_ENABLED accepts various true values."""
        for value in ("true", "1", "yes", "on"):
            with patch.dict(os.environ, {"OTEL_ENABLED": value}, clear=True):
                config = load_shared_config_from_env()
                assert config.otel_enabled is True

    @patch.dict(os.environ, {"OTEL_ENABLED": "false"}, clear=True)
    def test_otel_enabled_false(self) -> None:
        """Test OTEL_ENABLED false values."""
        config = load_shared_config_from_env()
        assert config.otel_enabled is False
