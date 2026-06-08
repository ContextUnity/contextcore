"""Centralized logging utilities for ContextUnity services.

This module provides:
- Logging configuration from SharedConfig
- Safe preview utilities for sensitive data
- Secret redaction
- Structured logging with ContextUnit integration
- Automatic trace_id propagation
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping, MutableMapping
from typing import Literal, override
from uuid import UUID

from .config import LogLevel, SharedConfig
from .parsing import json_dumps
from .types import JsonValue, is_object_dict, is_object_list

SECRET_PATTERNS = [
    r'(?i)(?:password|passwd|pwd|secret|token|key|api[_-]?key|auth[_-]?token)\s*[:=]\s*["\']?([^"\'\s]+)',
    r"(?i)(?:bearer|basic)\s+([a-zA-Z0-9+/=]+)",
    r"(?i)(?:sk-|pk-)[a-zA-Z0-9]{32,}",
    r'(?i)(?:x-api-key|x-auth-token|x-access-token)\s*[:=]\s*["\']?([^"\'\s]+)',
    r"[a-f0-9]{32,}",  # Long hex strings (could be hashes or keys)
    r"(?i)(?:-----BEGIN\s+(?:RSA\s+)?(?:PRIVATE\s+)?KEY-----).*?(?:-----END\s+(?:RSA\s+)?(?:PRIVATE\s+)?KEY-----)",
]


def safe_preview(value: object, limit: int = 240) -> str:
    """Create a safe, length-bounded preview of a value for logging."""
    if value is None:
        return ""

    if isinstance(value, str):
        s = value
    elif is_object_dict(value):
        try:
            s = json_dumps(value, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            s = str(value)
    elif is_object_list(value):
        try:
            s = json_dumps(value, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            s = str(value)
    else:
        s = str(value)

    s = " ".join(s.split())

    if len(s) > limit:
        return s[: limit - 1] + "…"

    return s


def redact_secrets(text: str, replacement: str = "[REDACTED]") -> str:
    """Redact secret patterns from text."""
    result = text
    for pattern in SECRET_PATTERNS:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE | re.DOTALL)

    return result


def safe_log_value(value: object, limit: int = 240, redact: bool = True) -> str:
    """Create a safe log value with preview and optional redaction."""
    preview = safe_preview(value, limit=limit)
    if redact:
        preview = redact_secrets(preview)
    return preview


def _record_fields(record: logging.LogRecord) -> Mapping[str, object]:
    """Return stdlib ``LogRecord`` attributes as a read-only mapping."""
    return vars(record)


def _normalize_log_extra(extra_obj: object) -> dict[str, object]:
    """Coerce logging ``extra`` to a mutable string-key dict."""
    if is_object_dict(extra_obj):
        return dict(extra_obj)
    return {}


def _merge_trace_context(
    extra: Mapping[str, object],
    *,
    trace_id: object | None,
    unit_id: object | None,
) -> dict[str, object]:
    """Merge trace/unit identifiers into a logging ``extra`` mapping."""
    merged: dict[str, object] = dict(extra)
    if trace_id:
        merged["trace_id"] = trace_id
    if unit_id:
        merged["unit_id"] = unit_id
    return merged


class ContextUnitFormatter(logging.Formatter):
    """Custom formatter that includes trace_id and structured JSON output."""

    include_trace_id: bool
    json_format: bool
    redact_secrets: bool

    def __init__(
        self,
        include_trace_id: bool = True,
        json_format: bool = True,
        redact_secrets: bool = True,
        fmt: str | None = None,
        datefmt: str | None = None,
        style: Literal["%", "{", "$"] = "%",
    ) -> None:
        super().__init__(fmt=fmt, datefmt=datefmt, style=style)
        self.include_trace_id = include_trace_id
        self.json_format = json_format
        self.redact_secrets = redact_secrets

    @override
    def format(self, record: logging.LogRecord) -> str:
        trace_id = getattr(record, "trace_id", None)
        unit_id = getattr(record, "unit_id", None)

        trace_id_value: object | None = trace_id
        unit_id_value: object | None = unit_id

        log_data: dict[str, JsonValue] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        if self.include_trace_id:
            if trace_id_value is not None:
                log_data["trace_id"] = str(trace_id_value)
            if unit_id_value is not None:
                log_data["unit_id"] = str(unit_id_value)

        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        reserved_keys = {
            "name",
            "msg",
            "args",
            "created",
            "filename",
            "funcName",
            "levelname",
            "levelno",
            "lineno",
            "module",
            "msecs",
            "message",
            "pathname",
            "process",
            "processName",
            "relativeCreated",
            "thread",
            "threadName",
            "exc_info",
            "exc_text",
            "stack_info",
            "trace_id",
            "unit_id",
        }
        record_fields = _record_fields(record)
        for key, value in record_fields.items():
            if key not in reserved_keys:
                log_data[key] = safe_log_value(value, redact=self.redact_secrets)

        if self.redact_secrets:
            message = log_data["message"]
            if isinstance(message, str):
                log_data["message"] = redact_secrets(message)

        if self.json_format:
            return json_dumps(log_data, default=str, ensure_ascii=False)

        ts = str(log_data["timestamp"])
        lvl = str(log_data["level"])
        name = str(log_data["logger"])
        msg = str(log_data["message"])
        base = f"{ts} [{lvl}] {name}: {msg}"
        if trace_id:
            base = f"{ts} [{lvl}] {name} trace_id={log_data.get('trace_id', '')}: {msg}"
        return base


class ContextUnitLoggerAdapter(logging.LoggerAdapter[logging.Logger]):
    """Logger adapter that automatically adds trace_id and unit_id to log records."""

    trace_id: UUID | str | None
    unit_id: UUID | str | None

    def __init__(
        self,
        logger: logging.Logger,
        trace_id: UUID | str | None = None,
        unit_id: UUID | str | None = None,
    ) -> None:
        super().__init__(logger, {})
        self.trace_id = trace_id
        self.unit_id = unit_id

    @override
    def process(self, msg: object, kwargs: MutableMapping[str, object]) -> tuple[object, MutableMapping[str, object]]:
        trace_id = kwargs.pop("trace_id", self.trace_id)
        unit_id = kwargs.pop("unit_id", self.unit_id)

        unit = kwargs.pop("unit", None)
        if unit is not None and getattr(unit, "__class__", None) and unit.__class__.__name__ == "ContextUnit":
            trace_id = trace_id or getattr(unit, "trace_id", None)
            unit_id = unit_id or getattr(unit, "unit_id", None)

        extra = _merge_trace_context(
            _normalize_log_extra(kwargs.get("extra")),
            trace_id=trace_id,
            unit_id=unit_id,
        )
        kwargs["extra"] = extra

        return msg, kwargs

    def error_exc(self, msg: str, *args: object, exc: BaseException | None = None) -> None:
        if exc is None:
            import sys

            exc = sys.exc_info()[1]
        if exc is not None:
            exc_brief = f"{type(exc).__name__}: {exc}"
            msg = f"{msg}: %s"
            args = (*args, exc_brief)
        self.error(msg, *args)


def setup_logging(
    config: SharedConfig | None = None,
    json_format: bool | None = None,
    redact_secrets: bool = True,
    service_name: str | None = None,
) -> None:
    if config is None:
        from .config import get_core_config

        config = get_core_config()

    if json_format is None:
        json_format = getattr(config, "log_json", False)

    level_map = {
        LogLevel.DEBUG: logging.DEBUG,
        LogLevel.INFO: logging.INFO,
        LogLevel.WARNING: logging.WARNING,
        LogLevel.ERROR: logging.ERROR,
        LogLevel.CRITICAL: logging.CRITICAL,
    }
    log_level = level_map.get(config.log_level, logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)

    formatter = ContextUnitFormatter(
        include_trace_id=True,
        json_format=bool(json_format),
        redact_secrets=redact_secrets,
    )
    console_handler.setFormatter(formatter)

    root_logger.addHandler(console_handler)

    if service_name:
        logging.getLogger(service_name).setLevel(log_level)


def get_contextunit_logger(
    name: str | None = None,
    trace_id: UUID | str | None = None,
    unit_id: UUID | str | None = None,
) -> ContextUnitLoggerAdapter:
    if name is None:
        logger = logging.getLogger()
    else:
        logger = logging.getLogger(name)
    return ContextUnitLoggerAdapter(logger, trace_id=trace_id, unit_id=unit_id)


__all__ = [
    "safe_preview",
    "redact_secrets",
    "safe_log_value",
    "ContextUnitFormatter",
    "ContextUnitLoggerAdapter",
    "setup_logging",
    "get_contextunit_logger",
]
