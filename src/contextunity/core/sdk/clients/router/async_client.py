"""RouterClient — async gRPC client for contextunity.router.
Uses ContextUnit protocol for all gRPC communication.
Provides execute_agent()/stream_agent()/execute_node() for calling
Router-managed graphs and callbacks remotely.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, ClassVar
from uuid import UUID

from contextunity.core.grpc_client_errors import wrap_client_error
from contextunity.core.router_pb2_grpc import RouterServiceStub
from contextunity.core.sdk.clients.router.fault_spool_models import (
    FaultSpoolBatchResult,
    FaultSpoolOperatorRecord,
    FaultSpoolOperatorStatus,
    FaultSpoolTerminalPurgeResult,
)
from contextunity.core.sdk.payload import (
    copy_wire_payload,
    get_dict,
    get_json_dict,
    get_json_dict_list,
    get_str,
)
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
            metadata: Bounded execution metadata merged into input.metadata.
                      Tenant identity is derived from the ContextToken and is never
                      accepted in-band.

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

    async def get_fault_spool_status(self) -> FaultSpoolOperatorStatus:
        """Read Router-local bounded spool state through the authorized RPC."""
        unit = ContextUnit(payload={}, provenance=["sdk:router_client:get_fault_spool_status"])
        with wrap_client_error("Router", "GetFaultSpoolStatus"):
            response_pb = await self._stub.GetFaultSpoolStatus(
                unit.to_protobuf(self._cu_pb2), metadata=self._get_metadata()
            )
        response = ContextUnit.from_protobuf(response_pb)
        return FaultSpoolOperatorStatus.model_validate(get_json_dict(response.payload, "fault_spool"))

    async def list_fault_spool_records(self, *, limit: int = 20) -> list[FaultSpoolOperatorRecord]:
        """Read at most 100 sanitized records without their tenant or delivery payload."""
        if limit < 1 or limit > 100:
            raise ValueError("fault spool limit must be between 1 and 100")
        unit = ContextUnit(
            payload={"limit": limit},
            provenance=["sdk:router_client:list_fault_spool_records"],
        )
        with wrap_client_error("Router", "ListFaultSpoolRecords"):
            response_pb = await self._stub.ListFaultSpoolRecords(
                unit.to_protobuf(self._cu_pb2), metadata=self._get_metadata()
            )
        response = ContextUnit.from_protobuf(response_pb)
        return [
            FaultSpoolOperatorRecord.model_validate(record)
            for record in get_json_dict_list(response.payload, "records")
        ]

    async def replay_fault_spool(self) -> FaultSpoolBatchResult:
        """Request one C0-bounded Router-local replay batch as an authorized operator."""
        unit = ContextUnit(payload={}, provenance=["sdk:router_client:replay_fault_spool"])
        with wrap_client_error("Router", "ReplayFaultSpool"):
            response_pb = await self._stub.ReplayFaultSpool(
                unit.to_protobuf(self._cu_pb2), metadata=self._get_metadata()
            )
        response = ContextUnit.from_protobuf(response_pb)
        return FaultSpoolBatchResult.model_validate(get_json_dict(response.payload, "batch"))

    async def discard_fault_spool_record(
        self,
        *,
        record_id: UUID,
        disposition_id: str,
        reason_code: str,
    ) -> FaultSpoolOperatorRecord:
        """Persist one explicit authorized policy disposition; it never deletes a row."""
        unit = ContextUnit(
            payload={
                "record_id": str(record_id),
                "disposition_id": disposition_id,
                "reason_code": reason_code,
            },
            provenance=["sdk:router_client:discard_fault_spool_record"],
        )
        with wrap_client_error("Router", "DiscardFaultSpoolRecord"):
            response_pb = await self._stub.DiscardFaultSpoolRecord(
                unit.to_protobuf(self._cu_pb2), metadata=self._get_metadata()
            )
        response = ContextUnit.from_protobuf(response_pb)
        return FaultSpoolOperatorRecord.model_validate(get_json_dict(response.payload, "record"))

    async def purge_fault_spool_terminal_records(self) -> FaultSpoolTerminalPurgeResult:
        """Purge one C0-bounded terminal retention batch as an authorized operator."""
        unit = ContextUnit(
            payload={},
            provenance=["sdk:router_client:purge_fault_spool_terminal_records"],
        )
        with wrap_client_error("Router", "PurgeFaultSpoolTerminalRecords"):
            response_pb = await self._stub.PurgeFaultSpoolTerminalRecords(
                unit.to_protobuf(self._cu_pb2), metadata=self._get_metadata()
            )
        response = ContextUnit.from_protobuf(response_pb)
        return FaultSpoolTerminalPurgeResult.model_validate(get_json_dict(response.payload, "purge"))

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
