"""RouterClient — async gRPC client for contextunity.router.
Uses ContextUnit protocol for all gRPC communication.
Provides execute_agent()/stream_agent()/execute_node() for calling
Router-managed graphs and callbacks remotely.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, ClassVar

from contextunity.core.grpc_client_errors import wrap_client_error
from contextunity.core.router_pb2_grpc import RouterServiceStub
from contextunity.core.sdk.payload import copy_wire_payload, get_dict, get_str
from contextunity.core.sdk.responses import (
    StreamPayload,
    is_brain_event,
    is_progress_event,
    is_result_event,
    is_terminal_event,
)
from contextunity.core.types import ContextUnitPayload, JsonDict

from .._base import BaseServiceClient
from .base import ContextUnit, build_default_metadata

if TYPE_CHECKING:
    from typing import TypeAlias

    from contextunity.core import ContextToken
    from contextunity.core.router_pb2_grpc import RouterServiceAsyncStub
    from contextunity.core.sdk.models import UnitMetrics
    from contextunity.core.sdk.types import TokenProviderFactory

    _RouterBase: TypeAlias = BaseServiceClient[RouterServiceAsyncStub]
else:
    _RouterBase = BaseServiceClient


class RouterClient(_RouterBase):
    """Async client for interacting with contextunity.router using ContextUnit protocol.

    Example:
        async with RouterClient(token=my_token) as client:
            result = await client.execute_agent(
                "rlm_bulk_matcher",
                {"intent": "match", "unmatched_products": [...]},
            )
    """

    _service_name: ClassVar[str] = "router"
    _default_port: ClassVar[str] = "50051"
    _config_url_attr: ClassVar[str] = "router_url"
    _stub_class: ClassVar[type] = RouterServiceStub

    def __init__(
        self,
        host: str | None = None,
        token: ContextToken | TokenProviderFactory | None = None,
    ) -> None:
        """Initialize the async RouterClient.

        Args:
            host: Optional explicit gRPC host address.
            token: Token object or lazy pre-signed bearer provider for Router access.
        """
        super().__init__(host=host, token=token)

    async def execute_node(
        self,
        graph_name: str,
        node_name: str,
        state: ContextUnitPayload,
        metadata: JsonDict | None = None,
    ) -> ContextUnitPayload:
        """Execute a specific graph node via Router.

        Args:
            graph_name: Name of the compiled graph (e.g., "rlm_bulk_matcher").
            node_name: Node to execute (must be in router_callbacks).
            state: State dictionary to pass to the node.
            metadata: Additional metadata. Tenant identity is derived from
                the ContextToken on the server — never passed in-band.

        Returns:
            Full ExecuteNode wire payload (``output``, ``node_name``, tracing, …).
        """
        input_payload: ContextUnitPayload = {
            "graph_name": graph_name,
            "node_name": node_name,
            "state": state,
        }
        if metadata:
            input_payload["metadata"] = dict(metadata)

        unit = ContextUnit(
            payload=input_payload,
            provenance=["sdk:router_client:execute_node"],
        )
        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        with wrap_client_error("Router", "ExecuteNode"):
            response_pb = await self._stub.ExecuteNode(req, metadata=grpc_metadata)

        response = ContextUnit.from_protobuf(response_pb)
        return copy_wire_payload(response.payload)

    async def execute_agent(
        self,
        graph_name: str,
        payload: ContextUnitPayload | None = None,
        metadata: JsonDict | None = None,
    ) -> ContextUnitPayload:
        """Execute a LangGraph agent via Router.

        Args:
            graph_name: Name of the registered graph (e.g., "rlm_bulk_matcher", "gardener").
            payload: Graph input state (becomes the "input" field).
            metadata: Key-value pairs merged into input.metadata on the Router side.
                      Use this to pass per-call settings such as ``langfuse_enabled``,
                      ``langfuse_project_id``, etc.  The caller is responsible for
                      reading these from its own config layer. Tenant identity is
                      derived from the ContextToken — never passed in-band.

        Returns:
            Full graph execution state from the Router wire payload.
        """
        input_payload = dict(payload or {})
        default_meta = build_default_metadata()

        if metadata or default_meta:
            existing_meta = get_dict(input_payload, "metadata")
            # caller metadata and explicit input override defaults
            input_payload["metadata"] = {**default_meta, **existing_meta, **(metadata or {})}

        unit = ContextUnit(
            payload={
                "agent_id": graph_name,
                "input": input_payload,
            },
            provenance=["sdk:router_client:execute_agent"],
        )

        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        with wrap_client_error("Router", "ExecuteAgent"):
            response_pb = await self._stub.ExecuteAgent(req, metadata=grpc_metadata)

        response = ContextUnit.from_protobuf(response_pb)
        return copy_wire_payload(response.payload)

    async def stream_agent(
        self,
        graph_name: str,
        payload: ContextUnitPayload | None = None,
        metadata: JsonDict | None = None,
    ) -> AsyncIterator[tuple[str, StreamPayload, UnitMetrics | None]]:
        """Stream a LangGraph agent via the Router.

        Args:
            graph_name: Name of the registered graph (e.g., "rlm_bulk_matcher").
            payload: Graph input state (mapped to the "input" field).
            metadata: Additional key-value metadata to merge into the input.
                Tenant identity is implicitly derived from the ContextToken.

        Yields:
            tuple[str, StreamPayload, UnitMetrics | None]: ``event_type`` tag (for SSE),
            open Router stream payload (discriminant ``payload["event_type"]``), metrics.

        Raises:
            PlatformServiceError: If the remote stream execution fails.
        """
        import time

        input_payload = dict(payload or {})
        default_meta = build_default_metadata()

        if metadata or default_meta:
            existing_meta = get_dict(input_payload, "metadata")
            # caller metadata and explicit input override defaults
            input_payload["metadata"] = {**default_meta, **existing_meta, **(metadata or {})}

        unit = ContextUnit(
            payload={
                "agent_id": graph_name,
                "input": input_payload,
            },
            provenance=["sdk:router_client:stream_agent"],
        )

        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        t0 = time.monotonic()

        with wrap_client_error("Router", "StreamAgent"):
            async for response_pb in self._stub.StreamAgent(req, metadata=grpc_metadata, timeout=120):
                response = ContextUnit.from_protobuf(response_pb)
                res = response.payload
                event_type = get_str(res, "event_type", "unknown")
                metrics = response.metrics

                if is_progress_event(res):
                    yield ("progress", res, None)
                elif is_result_event(res):
                    wall_ms = (time.monotonic() - t0) * 1000
                    if metrics and not metrics.latency_ms:
                        metrics.latency_ms = int(wall_ms)
                    yield ("result", res, metrics)
                elif is_brain_event(res):
                    yield ("brain_event", res, metrics)
                elif is_terminal_event(res):
                    yield (event_type, res, metrics)


__all__ = ["RouterClient"]
