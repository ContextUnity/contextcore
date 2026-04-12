"""RouterClient - SDK client for cu.router service.

Uses ContextUnit protocol for all gRPC communication.
Provides execute_tool() and execute_agent() for calling
Router-managed tools and LangGraph agents remotely.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from contextunity.core.logging import get_contextunit_logger
from contextunity.core.sdk.identity import get_tenant_id

from ..contextunit import ContextUnit

if TYPE_CHECKING:
    from contextunity.core import ContextToken

logger = get_contextunit_logger(__name__)

# Proto imports (lazy, may not be available)
contextunit_pb2 = None
router_pb2_grpc = None


def _ensure_protos():
    """Lazy load proto modules."""
    global contextunit_pb2, router_pb2_grpc
    if contextunit_pb2 is None:
        try:
            from contextunity.core import contextunit_pb2 as cu_pb2
            from contextunity.core import router_pb2_grpc as router_grpc

            contextunit_pb2 = cu_pb2
            router_pb2_grpc = router_grpc
        except ImportError:
            raise ImportError("Router gRPC protos not available")


class RouterClient:
    """Client for interacting with cu.router using ContextUnit protocol.

    Provides methods to execute tools (via BiDi-registered services)
    and LangGraph agents remotely, without importing any Router code.

    Example:
        async with RouterClient(token=my_token) as client:
            result = await client.execute_tool(
                "export_catalogs_as_parquet",
                {"dealer": "abris"},
                target_project="traverse",
            )

            result = await client.execute_agent(
                "matcher",
                {"intent": "match", "unmatched_products": [...]},
            )
    """

    def __init__(
        self,
        host: str | None = None,
        token: "ContextToken | None" = None,
    ):
        """Initialize RouterClient.

        Args:
            host: Router gRPC endpoint (e.g., "router:50051").
                  If not provided, uses SharedConfig.router_url.
            token: Optional ContextToken for authorization
        """
        _ensure_protos()
        from contextunity.core.config import get_core_config
        from contextunity.core.grpc_utils import create_channel

        config = get_core_config()
        self.host = host or config.router_url
        self.token = token
        self.channel = create_channel(self.host)
        self._stub = router_pb2_grpc.RouterServiceStub(self.channel)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self):
        """Close the gRPC channel."""
        if self.channel:
            await self.channel.close()

    def _get_metadata(self, custom_metadata: dict | None = None) -> list[tuple[str, str]]:
        """Get gRPC metadata with token for requests."""
        from contextunity.core import create_grpc_metadata_with_token
        from contextunity.core.sdk.identity import mint_client_token
        from contextunity.core.signing import get_signing_backend

        actual_token = self.token() if callable(self.token) else self.token
        if actual_token is None:
            user_id = custom_metadata.get("user_id") if custom_metadata else None
            actual_token = mint_client_token(user_id=user_id)

        if isinstance(actual_token, str):
            return [("authorization", f"Bearer {actual_token}")]

        backend = get_signing_backend()
        return create_grpc_metadata_with_token(actual_token, backend=backend)

    def _build_default_metadata(self) -> dict[str, Any]:
        from contextunity.core.config import get_core_config

        config = get_core_config()

        meta: dict[str, Any] = {"tenant_id": get_tenant_id()}
        if config.cu_platform:
            meta["platform"] = config.cu_platform

        meta["langfuse_enabled"] = config.langfuse_enabled

        if config.langfuse_project_id:
            meta["langfuse_project_id"] = config.langfuse_project_id

        if config.langfuse_host:
            meta["langfuse_host"] = config.langfuse_host

        return meta

    async def execute_tool(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
        target_project: str = "",
    ) -> dict[str, Any]:
        """Execute a BiDi-registered tool via Router.

        Router dispatches the call to the service that registered
        the tool (e.g., Commerce via ToolExecutorStream).

        Args:
            tool_name: Name of the tool to execute.
            args: Tool arguments.
            target_project: Project/tenant to route the tool call to.

        Returns:
            Tool execution result as a dict.
        """
        # ExecuteAgentPayload: {agent_id, input, config}
        unit = ContextUnit(
            payload={
                "agent_id": "tool_executor",
                "input": {
                    "tool": tool_name,
                    "args": args or {},
                    "target_project": target_project,
                },
            },
            provenance=["sdk:router_client:execute_tool"],
        )

        req = unit.to_protobuf(contextunit_pb2)
        metadata = self._get_metadata()
        response_pb = await self._stub.ExecuteAgent(req, metadata=metadata)
        response = ContextUnit.from_protobuf(response_pb)
        return dict(response.payload)

    async def execute_agent(
        self,
        graph_name: str,
        payload: dict[str, Any] | None = None,
        tenant_id: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute a LangGraph agent via Router.

        Args:
            graph_name: Name of the registered graph (e.g., "matcher", "commerce").
            payload: Graph input state (becomes the "input" field).
            tenant_id: Tenant identifier.
            metadata: Key-value pairs merged into input.metadata on the Router side.
                      Use this to pass per-call settings such as ``langfuse_enabled``,
                      ``langfuse_project_id``, etc.  The caller is responsible for
                      reading these from its own config layer.

        Returns:
            Graph execution result as a dict.
        """
        input_payload = dict(payload or {})
        default_meta = self._build_default_metadata()

        if metadata or default_meta:
            existing_meta = input_payload.get("metadata", {})
            if not isinstance(existing_meta, dict):
                existing_meta = {}
            # caller metadata and explicit input override defaults
            input_payload["metadata"] = {**default_meta, **existing_meta, **(metadata or {})}

        unit = ContextUnit(
            payload={
                "agent_id": graph_name,
                "input": input_payload,
            },
            provenance=["sdk:router_client:execute_agent"],
        )

        req = unit.to_protobuf(contextunit_pb2)
        grpc_metadata = self._get_metadata(metadata)
        response_pb = await self._stub.ExecuteAgent(req, metadata=grpc_metadata)
        response = ContextUnit.from_protobuf(response_pb)
        return dict(response.payload)

    async def stream_agent(
        self,
        graph_name: str,
        payload: dict[str, Any] | None = None,
        tenant_id: str = "",
        metadata: dict[str, Any] | None = None,
    ):
        """Stream a LangGraph agent via Router.

        Yields:
            tuple: (event_type, event_data, metrics)
        """
        import time

        input_payload = dict(payload or {})
        default_meta = self._build_default_metadata()

        if metadata or default_meta:
            existing_meta = input_payload.get("metadata", {})
            if not isinstance(existing_meta, dict):
                existing_meta = {}
            # caller metadata and explicit input override defaults
            input_payload["metadata"] = {**default_meta, **existing_meta, **(metadata or {})}

        unit = ContextUnit(
            payload={
                "agent_id": graph_name,
                "input": input_payload,
            },
            provenance=["sdk:router_client:stream_agent"],
        )

        req = unit.to_protobuf(contextunit_pb2)
        grpc_metadata = self._get_metadata(metadata)
        t0 = time.monotonic()

        async for response_pb in self._stub.StreamAgent(req, metadata=grpc_metadata, timeout=120):
            response = ContextUnit.from_protobuf(response_pb)
            res = response.payload
            event_type = res.get("event_type", "unknown")
            metrics = response.metrics

            if event_type == "progress":
                yield ("progress", res, None)
            elif event_type == "result":
                wall_ms = (time.monotonic() - t0) * 1000
                if metrics and not metrics.latency_ms:
                    metrics.latency_ms = int(wall_ms)
                yield ("result", res, metrics)
            elif event_type in ("done", "error"):
                yield (event_type, res, metrics)


class SyncRouterClient:
    """Synchronous client for interacting with cu.router (e.g. for Django views)."""

    def __init__(
        self,
        host: str | None = None,
        token: "ContextToken | None" = None,
    ):
        _ensure_protos()
        from contextunity.core.config import get_core_config
        from contextunity.core.grpc_utils import create_channel_sync

        config = get_core_config()
        self.host = host or config.router_url
        self.token = token
        self.channel = create_channel_sync(self.host)
        self._stub = router_pb2_grpc.RouterServiceStub(self.channel)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        """Close the gRPC channel."""
        if self.channel:
            self.channel.close()

    def _get_metadata(self, custom_metadata: dict | None = None) -> list[tuple[str, str]]:
        from contextunity.core import create_grpc_metadata_with_token
        from contextunity.core.sdk.identity import mint_client_token
        from contextunity.core.signing import get_signing_backend

        actual_token = self.token() if callable(self.token) else self.token
        if actual_token is None:
            user_id = custom_metadata.get("user_id") if custom_metadata else None
            actual_token = mint_client_token(user_id=user_id)

        if isinstance(actual_token, str):
            return [("authorization", f"Bearer {actual_token}")]

        backend = get_signing_backend()
        return create_grpc_metadata_with_token(actual_token, backend=backend)

    def _build_default_metadata(self) -> dict[str, Any]:
        from contextunity.core.config import get_core_config

        config = get_core_config()

        meta: dict[str, Any] = {"tenant_id": get_tenant_id()}
        if config.cu_platform:
            meta["platform"] = config.cu_platform

        meta["langfuse_enabled"] = config.langfuse_enabled

        if config.langfuse_project_id:
            meta["langfuse_project_id"] = config.langfuse_project_id

        if config.langfuse_host:
            meta["langfuse_host"] = config.langfuse_host

        return meta

    def execute_agent(
        self,
        graph_name: str,
        payload: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], Any]:
        """Execute agent synchronously. Returns (result_payload, metrics)."""
        import time

        input_payload = dict(payload or {})
        default_meta = self._build_default_metadata()

        if metadata or default_meta:
            existing_meta = input_payload.get("metadata", {})
            if not isinstance(existing_meta, dict):
                existing_meta = {}
            input_payload["metadata"] = {**default_meta, **existing_meta, **(metadata or {})}

        unit = ContextUnit(
            payload={
                "agent_id": graph_name,
                "input": input_payload,
            },
            provenance=["sdk:sync_router_client:execute_agent"],
        )

        req = unit.to_protobuf(contextunit_pb2)
        grpc_metadata = self._get_metadata(metadata)
        t0 = time.monotonic()
        response_pb = self._stub.ExecuteAgent(req, metadata=grpc_metadata, timeout=120)
        wall_ms = (time.monotonic() - t0) * 1000

        response = ContextUnit.from_protobuf(response_pb)
        res = dict(response.payload)
        metrics = response.metrics
        if metrics and not metrics.latency_ms:
            metrics.latency_ms = int(wall_ms)

        return res, metrics

    def stream_agent(
        self,
        graph_name: str,
        payload: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ):
        """Stream agent execution synchronously. Yields (event_type, event_data, metrics)."""
        import time

        input_payload = dict(payload or {})
        default_meta = self._build_default_metadata()

        if metadata or default_meta:
            existing_meta = input_payload.get("metadata", {})
            if not isinstance(existing_meta, dict):
                existing_meta = {}
            input_payload["metadata"] = {**default_meta, **existing_meta, **(metadata or {})}

        unit = ContextUnit(
            payload={
                "agent_id": graph_name,
                "input": input_payload,
            },
            provenance=["sdk:sync_router_client:stream_agent"],
        )

        req = unit.to_protobuf(contextunit_pb2)
        grpc_metadata = self._get_metadata(metadata)
        t0 = time.monotonic()

        for response_pb in self._stub.StreamAgent(req, metadata=grpc_metadata, timeout=120):
            response = ContextUnit.from_protobuf(response_pb)
            res = response.payload
            event_type = res.get("event_type", "unknown")
            metrics = response.metrics

            if event_type == "progress":
                yield ("progress", res, None)
            elif event_type == "result":
                wall_ms = (time.monotonic() - t0) * 1000
                if metrics and not metrics.latency_ms:
                    metrics.latency_ms = int(wall_ms)
                yield ("result", res, metrics)
            elif event_type in ("done", "error"):
                yield (event_type, res, metrics)


__all__ = ["RouterClient", "SyncRouterClient"]
