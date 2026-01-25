"""Centralized logging utilities for ContextUnity services.

This module provides:
- Logging configuration from SharedConfig
- Safe preview utilities for sensitive data
- Secret redaction
- Structured logging with ContextUnit integration
- Automatic trace_id propagation
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional
from uuid import UUID

from .config import LogLevel, SharedConfig
from .sdk import ContextUnit


# Patterns for detecting secrets (common patterns to redact)
SECRET_PATTERNS = [
    r'(?i)(?:password|passwd|pwd|secret|token|key|api[_-]?key|auth[_-]?token)\s*[:=]\s*["\']?([^"\'\s]+)',
    r'(?i)(?:bearer|basic)\s+([a-zA-Z0-9+/=]+)',
    r'(?i)(?:sk-|pk-)[a-zA-Z0-9]{32,}',
    r'(?i)(?:x-api-key|x-auth-token|x-access-token)\s*[:=]\s*["\']?([^"\'\s]+)',
    r'[a-f0-9]{32,}',  # Long hex strings (could be hashes or keys)
    r'(?i)(?:-----BEGIN\s+(?:RSA\s+)?(?:PRIVATE\s+)?KEY-----).*?(?:-----END\s+(?:RSA\s+)?(?:PRIVATE\s+)?KEY-----)',
]


def safe_preview(value: Any, limit: int = 240) -> str:
    """Create a safe, length-bounded preview of a value for logging.
    
    This function:
    - Converts any value to a single-line string
    - Truncates to the specified limit
    - Normalizes whitespace
    - Never logs full secrets or sensitive data
    
    Args:
        value: The value to preview (any type)
        limit: Maximum length of the preview (default: 240)
    
    Returns:
        A safe, truncated string representation
    """
    if value is None:
        return ""
    
    # Convert to string
    if isinstance(value, str):
        s = value
    elif isinstance(value, (dict, list)):
        # For structured data, use JSON but limit size
        try:
            s = json.dumps(value, default=str, ensure_ascii=False)
        except (TypeError, ValueError):
            s = str(value)
    else:
        s = str(value)
    
    # Normalize whitespace (replace newlines, tabs, multiple spaces with single space)
    s = " ".join(s.split())
    
    # Truncate if too long
    if len(s) > limit:
        return s[: limit - 1] + "…"
    
    return s


def redact_secrets(text: str, replacement: str = "[REDACTED]") -> str:
    """Redact secret patterns from text.
    
    This function removes or replaces common secret patterns:
    - API keys, tokens, passwords
    - Bearer tokens, basic auth
    - Private keys
    - Long hex strings that might be keys
    
    Args:
        text: The text to redact
        replacement: String to replace secrets with (default: "[REDACTED]")
    
    Returns:
        Text with secrets redacted
    """
    if not isinstance(text, str):
        return text
    
    result = text
    for pattern in SECRET_PATTERNS:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE | re.DOTALL)
    
    return result


def safe_log_value(value: Any, limit: int = 240, redact: bool = True) -> str:
    """Create a safe log value with preview and optional redaction.
    
    This is the main function to use when logging potentially sensitive data.
    It combines safe_preview() and redact_secrets().
    
    Args:
        value: The value to log
        limit: Maximum length of the preview
        redact: Whether to redact secrets (default: True)
    
    Returns:
        A safe string representation ready for logging
    """
    preview = safe_preview(value, limit=limit)
    if redact:
        preview = redact_secrets(preview)
    return preview


class ContextUnitFormatter(logging.Formatter):
    """Custom formatter that includes trace_id and structured JSON output.
    
    This formatter:
    - Extracts trace_id from log records (if available)
    - Formats logs as JSON for structured logging
    - Includes safe previews of data
    - Redacts secrets automatically
    """
    
    def __init__(
        self,
        include_trace_id: bool = True,
        json_format: bool = True,
        redact_secrets: bool = True,
        *args: Any,
        **kwargs: Any,
    ):
        """Initialize the formatter.
        
        Args:
            include_trace_id: Whether to include trace_id in logs
            json_format: Whether to output JSON (True) or plain text (False)
            redact_secrets: Whether to redact secrets from log messages
        """
        super().__init__(*args, **kwargs)
        self.include_trace_id = include_trace_id
        self.json_format = json_format
        self.redact_secrets = redact_secrets
    
    def format(self, record: logging.LogRecord) -> str:
        """Format a log record."""
        # Extract trace_id if available
        trace_id = getattr(record, "trace_id", None)
        unit_id = getattr(record, "unit_id", None)
        
        # Build base log data
        log_data: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        # Add trace context if available
        if self.include_trace_id:
            if trace_id:
                log_data["trace_id"] = str(trace_id) if isinstance(trace_id, UUID) else trace_id
            if unit_id:
                log_data["unit_id"] = str(unit_id) if isinstance(unit_id, UUID) else unit_id
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields from record
        for key, value in record.__dict__.items():
            if key not in {
                "name", "msg", "args", "created", "filename", "funcName",
                "levelname", "levelno", "lineno", "module", "msecs",
                "message", "pathname", "process", "processName", "relativeCreated",
                "thread", "threadName", "exc_info", "exc_text", "stack_info",
                "trace_id", "unit_id",
            }:
                # Safe preview for extra fields
                log_data[key] = safe_log_value(value, redact=self.redact_secrets)
        
        # Redact secrets from message if enabled
        if self.redact_secrets:
            log_data["message"] = redact_secrets(log_data["message"])
        
        # Format as JSON or plain text
        if self.json_format:
            return json.dumps(log_data, default=str, ensure_ascii=False)
        else:
            # Plain text format with trace_id
            parts = [
                f"[{log_data['timestamp']}]",
                f"{log_data['level']}",
                f"{log_data['logger']}",
            ]
            if trace_id:
                parts.append(f"trace_id={log_data.get('trace_id', '')}")
            parts.append(f": {log_data['message']}")
            return " ".join(parts)


class ContextUnitLoggerAdapter(logging.LoggerAdapter):
    """Logger adapter that automatically adds trace_id and unit_id to log records.
    
    Usage:
        logger = get_context_unit_logger(__name__)
        logger.info("Processing unit", unit=my_unit)
    """
    
    def __init__(
        self,
        logger: logging.Logger,
        trace_id: Optional[UUID | str] = None,
        unit_id: Optional[UUID | str] = None,
    ):
        """Initialize the adapter.
        
        Args:
            logger: The underlying logger
            trace_id: Optional trace_id to include in all logs
            unit_id: Optional unit_id to include in all logs
        """
        super().__init__(logger, {})
        self.trace_id = trace_id
        self.unit_id = unit_id
    
    def process(self, msg: str, kwargs: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Process log message and add trace context."""
        # Extract trace_id and unit_id from kwargs if provided
        trace_id = kwargs.pop("trace_id", self.trace_id)
        unit_id = kwargs.pop("unit_id", self.unit_id)
        
        # Extract ContextUnit if provided
        unit = kwargs.pop("unit", None)
        if isinstance(unit, ContextUnit):
            trace_id = trace_id or unit.trace_id
            unit_id = unit_id or unit.unit_id
        
        # Add to extra for formatter
        extra = kwargs.get("extra", {})
        if trace_id:
            extra["trace_id"] = trace_id
        if unit_id:
            extra["unit_id"] = unit_id
        kwargs["extra"] = extra
        
        return msg, kwargs


def setup_logging(
    config: Optional[SharedConfig] = None,
    json_format: bool = True,
    redact_secrets: bool = True,
    service_name: Optional[str] = None,
) -> None:
    """Configure logging for a ContextUnity service.
    
    This function:
    - Sets up logging level from SharedConfig
    - Configures JSON formatter for structured logging
    - Enables secret redaction
    - Sets up root logger with appropriate handlers
    
    Args:
        config: SharedConfig instance (if None, loads from environment)
        json_format: Whether to use JSON format (default: True)
        redact_secrets: Whether to redact secrets (default: True)
        service_name: Optional service name for logger identification
    """
    if config is None:
        from .config import load_shared_config_from_env
        config = load_shared_config_from_env()
    
    # Convert LogLevel enum to logging level
    level_map = {
        LogLevel.DEBUG: logging.DEBUG,
        LogLevel.INFO: logging.INFO,
        LogLevel.WARNING: logging.WARNING,
        LogLevel.ERROR: logging.ERROR,
        LogLevel.CRITICAL: logging.CRITICAL,
    }
    log_level = level_map.get(config.log_level, logging.INFO)
    
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Remove existing handlers to avoid duplicates
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    
    # Create formatter
    formatter = ContextUnitFormatter(
        include_trace_id=True,
        json_format=json_format,
        redact_secrets=redact_secrets,
    )
    console_handler.setFormatter(formatter)
    
    # Add handler to root logger
    root_logger.addHandler(console_handler)
    
    # Set service name if provided
    if service_name:
        logging.getLogger(service_name).setLevel(log_level)


def get_context_unit_logger(
    name: str,
    trace_id: Optional[UUID | str] = None,
    unit_id: Optional[UUID | str] = None,
) -> ContextUnitLoggerAdapter:
    """Get a logger adapter with ContextUnit support.
    
    This is the recommended way to get a logger in ContextUnity services.
    It returns a ContextUnitLoggerAdapter that automatically includes trace_id
    and unit_id in log records.
    
    Args:
        name: Logger name (typically __name__)
        trace_id: Optional trace_id to include in all logs
        unit_id: Optional unit_id to include in all logs
    
    Returns:
        ContextUnitLoggerAdapter instance
    
    Example:
        logger = get_context_unit_logger(__name__)
        logger.info("Processing request", unit=context_unit)
    """
    logger = logging.getLogger(name)
    return ContextUnitLoggerAdapter(logger, trace_id=trace_id, unit_id=unit_id)


__all__ = [
    "safe_preview",
    "redact_secrets",
    "safe_log_value",
    "ContextUnitFormatter",
    "ContextUnitLoggerAdapter",
    "setup_logging",
    "get_context_unit_logger",
]
