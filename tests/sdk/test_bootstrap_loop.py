"""Tests for bootstrap retry helpers."""

from __future__ import annotations

import grpc
import pytest
from contextunity.core.sdk.bootstrap.loop import (
    _format_bootstrap_error,
    _next_retry_delay,
)


class _RpcError(grpc.RpcError):
    def __init__(self, code: grpc.StatusCode, details: str) -> None:
        self._code = code
        self._details = details

    def code(self) -> grpc.StatusCode:
        return self._code

    def details(self) -> str:
        return self._details


def test_next_retry_delay_is_exponential_and_capped() -> None:
    delay = 15
    delays = []
    for _ in range(6):
        delays.append(delay)
        delay = _next_retry_delay(delay)

    assert delays == [15, 30, 60, 120, 240, 300]
    assert _next_retry_delay(300) == 300


def test_bootstrap_deadline_error_explains_timeout_context() -> None:
    error = _RpcError(grpc.StatusCode.DEADLINE_EXCEEDED, "Deadline Exceeded")

    message = _format_bootstrap_error(error, "registering manifest with Router")

    assert "gRPC DEADLINE_EXCEEDED: Deadline Exceeded" in message
    assert "Timeout while registering manifest with Router" in message
    assert "client deadline" in message
    assert "service availability" in message


def test_bootstrap_non_deadline_error_keeps_original_format() -> None:
    error = _RpcError(grpc.StatusCode.UNAVAILABLE, "connection refused")

    assert _format_bootstrap_error(error, "registering manifest with Router") == (
        "gRPC UNAVAILABLE: connection refused"
    )


pytestmark = pytest.mark.unit
