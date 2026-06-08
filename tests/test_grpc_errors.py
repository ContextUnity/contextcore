"""Tests for gRPC error-handler context extraction (grpc.aio compatibility)."""

from __future__ import annotations

import asyncio

import grpc
import pytest
from contextunity.core.exceptions import ConfigurationError
from contextunity.core.grpc_errors import _extract_request_context, grpc_error_handler
from contextunity.core.types import GrpcServicerContext


class _AioShapedContext:
    """Minimal context matching ``grpc.aio.ServicerContext`` surface used by core."""

    def __init__(self) -> None:
        self.code: object | None = None
        self.details: str | None = None
        self.trailing: tuple[tuple[str, str], ...] = ()

    def set_trailing_metadata(self, metadata: tuple[tuple[str, str], ...]) -> None:
        self.trailing = metadata

    async def abort(self, code: object, details: str) -> None:
        self.code = code
        self.details = details
        raise asyncio.CancelledError("aborted")

    def set_code(self, code: object) -> None:
        self.code = code

    def set_details(self, details: str) -> None:
        self.details = details

    def invocation_metadata(self) -> tuple[tuple[str, str | bytes], ...]:
        return ()


def test_grpc_servicer_context_protocol_matches_aio_shape() -> None:
    """``grpc.aio.ServicerContext`` lacks ``get_trailing_metadata``; protocol must not require it."""
    assert not hasattr(grpc.aio.ServicerContext, "get_trailing_metadata")
    assert isinstance(_AioShapedContext(), GrpcServicerContext)


def test_extract_request_context_accepts_aio_shaped_context() -> None:
    """Error handler must not raise when real aio context shape is passed."""
    request = object()
    context = _AioShapedContext()
    extracted_request, extracted_context = _extract_request_context(
        (object(), request, context),
    )
    assert extracted_request is request
    assert extracted_context is context


@pytest.mark.asyncio
async def test_grpc_error_handler_does_not_mask_with_context_typeerror() -> None:
    """Handler exceptions must map to gRPC status, not ``GrpcServicerContext`` TypeError."""

    class _Service:
        @grpc_error_handler
        async def FailingRpc(self, _request: object, context: _AioShapedContext) -> object:
            raise ConfigurationError("registration failed for test")

    svc = _Service()
    ctx = _AioShapedContext()
    with pytest.raises(asyncio.CancelledError, match="aborted"):
        await svc.FailingRpc(object(), ctx)
    assert ctx.code == grpc.StatusCode.FAILED_PRECONDITION
    assert ctx.details is not None
    assert "registration failed" in ctx.details
