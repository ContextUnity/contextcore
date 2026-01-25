"""Tests for contextcore.logging module."""

from __future__ import annotations

import json
import logging
from uuid import UUID, uuid4

import pytest

from contextcore import (
    ContextUnit,
    LogLevel,
    SharedConfig,
    get_context_unit_logger,
    redact_secrets,
    safe_log_value,
    safe_preview,
    setup_logging,
)


class TestSafePreview:
    """Tests for safe_preview function."""

    def test_none_value(self) -> None:
        """Test that None returns empty string."""
        assert safe_preview(None) == ""

    def test_string_value(self) -> None:
        """Test string values are preserved."""
        assert safe_preview("hello") == "hello"

    def test_string_with_whitespace(self) -> None:
        """Test that whitespace is normalized."""
        assert safe_preview("hello\n\tworld  test") == "hello world test"

    def test_string_truncation(self) -> None:
        """Test that long strings are truncated."""
        long_string = "a" * 300
        result = safe_preview(long_string, limit=100)
        assert len(result) == 100
        assert result.endswith("…")

    def test_dict_value(self) -> None:
        """Test that dicts are converted to JSON."""
        data = {"key": "value", "num": 42}
        result = safe_preview(data)
        assert "key" in result
        assert "value" in result

    def test_list_value(self) -> None:
        """Test that lists are converted to JSON."""
        data = [1, 2, 3, "test"]
        result = safe_preview(data)
        assert "test" in result


class TestRedactSecrets:
    """Tests for redact_secrets function."""

    def test_password_pattern(self) -> None:
        """Test password redaction."""
        text = 'password: "secret123"'
        result = redact_secrets(text)
        assert "[REDACTED]" in result
        assert "secret123" not in result

    def test_api_key_pattern(self) -> None:
        """Test API key redaction."""
        text = "api_key: sk-1234567890abcdef"
        result = redact_secrets(text)
        assert "[REDACTED]" in result

    def test_bearer_token(self) -> None:
        """Test bearer token redaction."""
        text = "Authorization: Bearer abc123def456"
        result = redact_secrets(text)
        assert "[REDACTED]" in result

    def test_no_secrets(self) -> None:
        """Test that normal text is not modified."""
        text = "This is a normal message without secrets"
        result = redact_secrets(text)
        assert result == text

    def test_custom_replacement(self) -> None:
        """Test custom replacement string."""
        text = "password: secret123"
        result = redact_secrets(text, replacement="[HIDDEN]")
        assert "[HIDDEN]" in result


class TestSafeLogValue:
    """Tests for safe_log_value function."""

    def test_with_redaction(self) -> None:
        """Test that secrets are redacted."""
        text = "api_key: sk-1234567890"
        result = safe_log_value(text, redact=True)
        assert "[REDACTED]" in result

    def test_without_redaction(self) -> None:
        """Test that redaction can be disabled."""
        text = "api_key: sk-1234567890"
        result = safe_log_value(text, redact=False)
        # Should still contain the key (though truncated)
        assert "api_key" in result or "sk-" in result

    def test_truncation(self) -> None:
        """Test that long values are truncated."""
        long_text = "a" * 500
        result = safe_log_value(long_text, limit=100)
        assert len(result) <= 100


class TestSetupLogging:
    """Tests for setup_logging function."""

    def test_setup_with_config(self) -> None:
        """Test logging setup with SharedConfig."""
        config = SharedConfig(log_level=LogLevel.DEBUG)
        setup_logging(config=config, json_format=False)
        
        root_logger = logging.getLogger()
        assert root_logger.level == logging.DEBUG

    def test_setup_with_env(self) -> None:
        """Test logging setup loading from environment."""
        import os
        os.environ["LOG_LEVEL"] = "WARNING"
        
        setup_logging(json_format=False)
        
        root_logger = logging.getLogger()
        assert root_logger.level == logging.WARNING
        
        # Cleanup
        os.environ.pop("LOG_LEVEL", None)

    def test_json_format(self, capsys: pytest.CaptureFixture) -> None:
        """Test JSON format output."""
        import json
        
        config = SharedConfig(log_level=LogLevel.INFO)
        setup_logging(config=config, json_format=True)
        
        logger = logging.getLogger("test")
        logger.info("Test message")
        
        # Capture stderr output (where StreamHandler writes)
        captured = capsys.readouterr()
        stderr_output = captured.err.strip()
        
        # Verify it's valid JSON
        assert stderr_output.startswith("{")
        data = json.loads(stderr_output)
        assert data["level"] == "INFO"
        assert data["message"] == "Test message"
        assert data["logger"] == "test"

    def test_plain_format(self, capsys: pytest.CaptureFixture) -> None:
        """Test plain text format output."""
        config = SharedConfig(log_level=LogLevel.INFO)
        setup_logging(config=config, json_format=False)
        
        logger = logging.getLogger("test")
        logger.info("Test message")
        
        # Capture stderr output (where StreamHandler writes)
        captured = capsys.readouterr()
        stderr_output = captured.err.strip()
        
        # Verify it's plain text format
        assert "INFO" in stderr_output
        assert "test" in stderr_output
        assert "Test message" in stderr_output
        assert not stderr_output.startswith("{")  # Not JSON


class TestContextUnitLogger:
    """Tests for ContextUnit logger adapter."""

    def test_logger_with_trace_id(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test logger with trace_id."""
        trace_id = uuid4()
        logger = get_context_unit_logger("test", trace_id=trace_id)
        
        with caplog.at_level(logging.INFO):
            logger.info("Test message")
        
        assert len(caplog.records) > 0
        record = caplog.records[0]
        assert hasattr(record, "trace_id") or str(trace_id) in str(record)

    def test_logger_with_unit(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test logger with ContextUnit."""
        unit = ContextUnit(
            unit_id=uuid4(),
            trace_id=uuid4(),
            payload={"test": "data"},
        )
        
        logger = get_context_unit_logger("test")
        
        with caplog.at_level(logging.INFO):
            logger.info("Processing unit", unit=unit)
        
        assert len(caplog.records) > 0

    def test_logger_without_context(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test logger without trace context."""
        logger = get_context_unit_logger("test")
        
        with caplog.at_level(logging.INFO):
            logger.info("Test message")
        
        assert len(caplog.records) > 0


class TestContextUnitFormatter:
    """Tests for ContextUnitFormatter."""

    def test_json_format(self) -> None:
        """Test JSON formatter."""
        from contextcore.logging import ContextUnitFormatter
        
        formatter = ContextUnitFormatter(json_format=True)
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.trace_id = uuid4()
        
        result = formatter.format(record)
        
        # Should be valid JSON
        data = json.loads(result)
        assert data["level"] == "INFO"
        assert "trace_id" in data

    def test_plain_format(self) -> None:
        """Test plain text formatter."""
        from contextcore.logging import ContextUnitFormatter
        
        formatter = ContextUnitFormatter(json_format=False)
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.trace_id = uuid4()
        
        result = formatter.format(record)
        
        # Should be plain text
        assert "INFO" in result
        assert "Test message" in result
        assert "trace_id" in result
