"""Tests for contextunity.core.logging module."""

from __future__ import annotations

import json
import logging
from uuid import uuid4

import pytest
from contextunity.core import (
    ContextUnit,
    LogLevel,
    SharedConfig,
    get_contextunit_logger,
    redact_secrets,
    safe_preview,
    setup_logging,
)


class TestSafePreview:
    """Tests for safe_preview function.

    Score 3: +2 behavior (observability contract), +1 fast.
    """

    @pytest.mark.parametrize(
        ("value", "limit", "check"),
        [
            (None, 200, lambda r: r == ""),
            ("hello", 200, lambda r: r == "hello"),
            ("hello\n\tworld  test", 200, lambda r: r == "hello world test"),
            ("a" * 300, 100, lambda r: len(r) == 100 and r.endswith("\u2026")),
            ({"key": "value"}, 200, lambda r: "key" in r and "value" in r),
            ([1, 2, "test"], 200, lambda r: "test" in r),
        ],
        ids=["none", "string", "whitespace", "truncation", "dict", "list"],
    )
    def test_safe_preview(self, value, limit, check) -> None:
        result = safe_preview(value, limit=limit)
        assert check(result), f"Failed for {value!r}: got {result!r}"


class TestRedactSecrets:
    """Tests for redact_secrets function.

    Score 4: +2 protects security (secret leakage prevention), +2 fails when broken.
    """

    @pytest.mark.parametrize(
        ("text", "must_contain", "must_not_contain"),
        [
            ('password: "secret123"', "[REDACTED]", "secret123"),
            ("api_key: sk-1234567890abcdef", "[REDACTED]", "sk-1234567890"),
            ("Authorization: Bearer abc123def456", "[REDACTED]", "abc123def456"),
        ],
        ids=["password", "api-key", "bearer"],
    )
    def test_secrets_redacted(self, text, must_contain, must_not_contain) -> None:
        result = redact_secrets(text)
        assert must_contain in result
        assert must_not_contain not in result

    def test_normal_text_unchanged(self) -> None:
        """Normal text without secrets passes through unchanged."""
        text = "This is a normal message without secrets"
        assert redact_secrets(text) == text

    def test_custom_replacement(self) -> None:
        """Custom replacement string is used."""
        result = redact_secrets("password: secret123", replacement="[HIDDEN]")
        assert "[HIDDEN]" in result


class TestSetupLogging:
    """Tests for setup_logging function."""

    @pytest.fixture(autouse=True)
    def _restore_log_level(self):
        """Restore root logger state after each test to prevent contamination."""
        root = logging.getLogger()
        original_level = root.level
        original_handlers = root.handlers[:]
        yield
        root.setLevel(original_level)
        root.handlers = original_handlers

    def test_setup_with_config(self) -> None:
        """Test logging setup with SharedConfig."""
        config = SharedConfig(log_level=LogLevel.DEBUG)
        setup_logging(config=config, json_format=False)

        root_logger = logging.getLogger()
        assert root_logger.level == logging.DEBUG

    def test_setup_with_env(self) -> None:
        """Test logging setup loading from environment."""
        import os

        from contextunity.core.config import reset_core_config

        os.environ["LOG_LEVEL"] = "WARNING"
        reset_core_config()
        try:
            setup_logging(json_format=False)
            root_logger = logging.getLogger()
            assert root_logger.level == logging.WARNING
        finally:
            os.environ.pop("LOG_LEVEL", None)
            reset_core_config()

    def test_json_format(self, capsys: pytest.CaptureFixture) -> None:
        """Test JSON format output."""
        import json

        config = SharedConfig(log_level=LogLevel.INFO)
        setup_logging(config=config, json_format=True)

        logger = get_contextunit_logger("test")
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

        logger = get_contextunit_logger("test")
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
        logger = get_contextunit_logger("test", trace_id=trace_id)

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

        logger = get_contextunit_logger("test")

        with caplog.at_level(logging.INFO):
            logger.info("Processing unit", unit=unit)

        assert len(caplog.records) > 0

    def test_logger_without_context(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test logger without trace context."""
        logger = get_contextunit_logger("test")

        with caplog.at_level(logging.INFO):
            logger.info("Test message")

        assert len(caplog.records) > 0


class TestContextUnitFormatter:
    """Tests for ContextUnitFormatter."""

    def test_json_format(self) -> None:
        """Test JSON formatter."""
        from contextunity.core.logging import ContextUnitFormatter

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
        from contextunity.core.logging import ContextUnitFormatter

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


pytestmark = pytest.mark.unit
