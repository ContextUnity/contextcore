"""RouterClient - SDK client for ContextRouter service.

Uses ContextUnit protocol for all gRPC communication.
Provides execute_tool() and execute_agent() for calling
Router-managed tools and LangGraph agents remotely.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from .context_unit import ContextUnit

if TYPE_CHECKING:
    from contextcore import ContextToken

logger = logging.getLogger(__name__)

# Proto imports (lazy, may not be available)
context_unit_pb2 = None
router_pb2_grpc = None


def _ensure_protos():
    """Lazy load proto modules."""
    global context_unit_pb2, router_pb2_grpc
    if context_unit_pb2 is None:
        try:
            from .. import context_unit_pb2 as cu_pb2
            from .. import router_pb2_grpc as router_grpc

            context_unit_pb2 = cu_pb2
            router_pb2_grpc = router_grpc
        except ImportError:
            raise ImportError("Router gRPC protos not available")


class RouterClient:
    """Client for interacting with ContextRouter using ContextUnit protocol.

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
        from contextcore.config import get_core_config
        from contextcore.grpc_utils import create_channel

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

    def _get_metadata(self) -> list[tuple[str, str]]:
        """Get gRPC metadata with token for requests."""
        from contextcore import create_grpc_metadata_with_token

        actual_token = self.token() if callable(self.token) else self.token
        return create_grpc_metadata_with_token(actual_token)

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

        req = unit.to_protobuf(context_unit_pb2)
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
        if metadata:
            existing_meta = input_payload.get("metadata", {})
            if not isinstance(existing_meta, dict):
                existing_meta = {}
            # caller metadata merges on top of any payload-supplied metadata
            input_payload["metadata"] = {**existing_meta, **metadata}

        unit = ContextUnit(
            tenant_id=tenant_id,
            payload={
                "agent_id": graph_name,
                "input": input_payload,
            },
            provenance=["sdk:router_client:execute_agent"],
        )

        req = unit.to_protobuf(context_unit_pb2)
        grpc_metadata = self._get_metadata()
        response_pb = await self._stub.ExecuteAgent(req, metadata=grpc_metadata)
        response = ContextUnit.from_protobuf(response_pb)
        return dict(response.payload)


__all__ = ["RouterClient"]
