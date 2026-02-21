"""BrainClient base - initialization and proto imports."""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from contextcore import ContextToken

logger = logging.getLogger(__name__)

# Proto imports (lazy, may not be available)
context_unit_pb2 = None
brain_pb2_grpc = None
commerce_pb2_grpc = None


def _ensure_protos():
    """Lazy load proto modules."""
    global context_unit_pb2, brain_pb2_grpc, commerce_pb2_grpc
    if context_unit_pb2 is None:
        try:
            from ... import brain_pb2_grpc as brain_grpc
            from ... import context_unit_pb2 as cu_pb2

            context_unit_pb2 = cu_pb2
            brain_pb2_grpc = brain_grpc

            try:
                from ... import commerce_pb2_grpc as commerce_grpc

                commerce_pb2_grpc = commerce_grpc
            except ImportError:
                pass
        except ImportError:
            raise ImportError("Brain gRPC protos not available")


def get_context_unit_pb2():
    """Get context_unit_pb2 module."""
    _ensure_protos()
    return context_unit_pb2


class BrainClientBase:
    """Base class for BrainClient with connection management."""

    def __init__(
        self,
        host: str | None = None,
        mode: str | None = None,
        token: "ContextToken | None" = None,
    ):
        """Initialize BrainClient.

        Args:
            host: Brain gRPC endpoint (e.g., "brain:50051")
            mode: "grpc" or "local"
            token: Optional ContextToken for authorization
        """

        self.mode = mode or os.getenv("CONTEXT_BRAIN_MODE", "grpc")
        self.host = host or os.getenv("CONTEXT_BRAIN_URL", "localhost:50051")
        self.token: ContextToken | None = token
        self._stub = None
        self._commerce_stub = None
        self._service = None
        self.channel = None

        if self.mode == "grpc":
            _ensure_protos()
            from contextcore.grpc_utils import create_channel

            self.channel = create_channel(self.host)
            self._stub = brain_pb2_grpc.BrainServiceStub(self.channel)
            if commerce_pb2_grpc:
                self._commerce_stub = commerce_pb2_grpc.CommerceServiceStub(self.channel)
        else:
            try:
                from contextbrain import BrainService

                self._service = BrainService()
            except ImportError:
                logger.error("Brain local mode requested but contextbrain not installed")
                raise

    def _get_metadata(self) -> list[tuple[str, str]]:
        """Get gRPC metadata with token for requests.

        Returns:
            List of (key, value) tuples for gRPC metadata
        """
        from contextcore import create_grpc_metadata_with_token

        return create_grpc_metadata_with_token(self.token)


__all__ = ["BrainClientBase", "get_context_unit_pb2", "logger"]
