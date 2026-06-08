"""Test exception types for Graph Compiler — contract verification.

Each ContextUnityError subclass must:
1. Inherit from ContextUnityError
2. Have the correct error code
3. Preserve arbitrary **details
4. Be registered in the ErrorRegistry
5. Map to the correct gRPC status code
"""

import grpc
import pytest
from contextunity.core.exceptions import (
    ContextUnityError,
    PlatformServiceError,
    error_registry,
)
from contextunity.core.grpc_errors import get_grpc_status_code
from contextunity.router.core.exceptions import RouterLLMError, RouterToolTimeout


@pytest.mark.parametrize(
    ("exc_cls", "code", "grpc_status", "detail_kwargs"),
    [
        (
            RouterLLMError,
            "ROUTER_LLM_ERROR",
            grpc.StatusCode.INTERNAL,
            {"model": "gpt-5-mini", "node_name": "classifier"},
        ),
        (
            RouterToolTimeout,
            "ROUTER_TOOL_TIMEOUT",
            grpc.StatusCode.DEADLINE_EXCEEDED,
            {"tool_binding": "export_products", "timeout_seconds": 60},
        ),
        (
            PlatformServiceError,
            "PLATFORM_SERVICE_ERROR",
            grpc.StatusCode.UNAVAILABLE,
            {"service": "brain", "tool_binding": "brain_search"},
        ),
    ],
    ids=["RouterLLMError", "RouterToolTimeout", "PlatformServiceError"],
)
class TestExceptionContract:
    """Unified contract tests for all compiler exception types."""

    def test_inherits_context_unity_error(self, exc_cls, code, grpc_status, detail_kwargs):
        err = exc_cls(message="test")
        assert isinstance(err, ContextUnityError)

    def test_has_correct_code(self, exc_cls, code, grpc_status, detail_kwargs):
        err = exc_cls(message="test")
        assert err.code == code

    def test_preserves_details(self, exc_cls, code, grpc_status, detail_kwargs):
        err = exc_cls(message="test", **detail_kwargs)
        for key, value in detail_kwargs.items():
            assert err.details[key] == value

    def test_registered_in_error_registry(self, exc_cls, code, grpc_status, detail_kwargs):
        assert error_registry.get(code) is exc_cls

    def test_maps_to_grpc_status(self, exc_cls, code, grpc_status, detail_kwargs):
        err = exc_cls(message="fail")
        assert get_grpc_status_code(err) == grpc_status


pytestmark = pytest.mark.unit
