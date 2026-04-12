"""BrainClient base - initialization and proto imports."""

from __future__ import annotations

from typing import TYPE_CHECKING

from contextunity.core.logging import get_contextunit_logger

if TYPE_CHECKING:
    from contextunity.core import ContextToken

logger = get_contextunit_logger(__name__)

# Proto imports (lazy, may not be available)
contextunit_pb2 = None
brain_pb2_grpc = None
commerce_pb2_grpc = None


def _ensure_protos():
    """Lazy load proto modules."""
    global contextunit_pb2, brain_pb2_grpc, commerce_pb2_grpc
    if contextunit_pb2 is None:
        try:
            from .... import brain_pb2_grpc as brain_grpc
            from .... import contextunit_pb2 as cu_pb2

            contextunit_pb2 = cu_pb2
            brain_pb2_grpc = brain_grpc

            try:
                from .... import commerce_pb2_grpc as commerce_grpc

                commerce_pb2_grpc = commerce_grpc
            except ImportError:
                pass
        except ImportError:
            raise ImportError("Brain gRPC protos not available")


def get_contextunit_pb2():
    """Get contextunit_pb2 module."""
    _ensure_protos()
    return contextunit_pb2


class BrainClientBase:
    """Base class for BrainClient with connection management."""

    def __init__(
        self,
        host: str | None = None,
        mode: str | None = None,
        token: "ContextToken | None" = None,
        tenant_id: str | None = None,
    ):
        """Initialize BrainClient.

        Args:
            host: Specific Brain gRPC endpoint (bypasses discovery)
            mode: "grpc" or "local"
            token: Optional ContextToken for authorization
            tenant_id: Explicit tenant to discover Brain for
        """

        from contextunity.core.config import get_core_config

        config = get_core_config()
        self.mode = mode or config.brain_mode
        self.host = host
        self.token = token
        self._stub = None
        self._commerce_stub = None
        self._service = None
        self.channel = None

        if self.mode == "grpc":
            from contextunity.core.discovery import resolve_service_endpoint
            from contextunity.core.sdk.identity import get_tenant_id

            t_id = tenant_id or get_tenant_id()
            self.host = host or resolve_service_endpoint(
                "brain", configured_host=config.brain_url, default_host="localhost:50051", tenant_id=t_id
            )
            _ensure_protos()
            from contextunity.core.grpc_utils import create_channel

            self.channel = create_channel(self.host)
            self._stub = brain_pb2_grpc.BrainServiceStub(self.channel)
            if commerce_pb2_grpc:
                self._commerce_stub = commerce_pb2_grpc.CommerceServiceStub(self.channel)
        else:
            try:
                from contextunity.brain import BrainService

                self._service = BrainService()
            except ImportError:
                logger.error("Brain local mode requested but cu.brain not installed")
                raise

    def _get_metadata(self) -> list[tuple[str, str]]:
        """Get gRPC metadata with token for requests.

        Returns:
            List of (key, value) tuples for gRPC metadata
        """
        from contextunity.core import create_grpc_metadata_with_token
        from contextunity.core.signing import get_signing_backend

        actual_token = self.token() if callable(self.token) else self.token
        if isinstance(actual_token, str):
            return [("authorization", f"Bearer {actual_token}")]

        backend = get_signing_backend()
        return create_grpc_metadata_with_token(actual_token, backend=backend)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.channel:
            await self.channel.close()


__all__ = ["BrainClientBase", "get_contextunit_pb2", "logger"]
