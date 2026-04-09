"""WorkerClient - SDK client for ContextWorker service.

Uses ContextUnit protocol for all gRPC communication.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from contextcore.logging import get_context_unit_logger

from ..context_unit import ContextUnit

if TYPE_CHECKING:
    from contextcore import ContextToken

logger = get_context_unit_logger(__name__)

# Proto imports (lazy, may not be available)
context_unit_pb2 = None
worker_pb2_grpc = None


def _ensure_protos():
    """Lazy load proto modules."""
    global context_unit_pb2, worker_pb2_grpc
    if context_unit_pb2 is None:
        try:
            from contextcore import context_unit_pb2 as cu_pb2
            from contextcore import worker_pb2_grpc as worker_grpc

            context_unit_pb2 = cu_pb2
            worker_pb2_grpc = worker_grpc
        except ImportError:
            raise ImportError("Worker gRPC protos not available")


class WorkerClient:
    """Client for interacting with ContextWorker using ContextUnit protocol.

    Supports 'grpc' (network) and 'local' (direct Temporal client) modes.

    Example:
        client = WorkerClient(host="localhost:50052", token=my_token)
        result = await client.start_workflow(ContextUnit(
            payload={"workflow_type": "harvest", "supplier_code": "xyz"}
        ))
    """

    def __init__(
        self,
        host: str | None = None,
        mode: str | None = None,
        token: "ContextToken | None" = None,
        tenant_id: str | None = None,
    ):
        """Initialize WorkerClient.

        Args:
            host: Specific Worker gRPC endpoint (bypasses discovery)
            mode: "grpc" or "local"
            token: Optional ContextToken for authorization
            tenant_id: Explicit tenant to discover Worker for
        """

        from contextcore.config import get_core_config

        config = get_core_config()
        self.mode = mode or config.worker_mode
        self.temporal_host = config.temporal_host
        self.token = token
        self._stub = None
        self.channel = None
        self.host = host

        if self.mode == "grpc":
            from contextcore.discovery import resolve_service_endpoint
            from contextcore.sdk.identity import get_tenant_id

            t_id = tenant_id or get_tenant_id()
            self.host = host or resolve_service_endpoint(
                "worker", configured_host=config.worker_url, default_host="localhost:50052", tenant_id=t_id
            )
            _ensure_protos()
            from contextcore.grpc_utils import create_channel

            self.channel = create_channel(self.host)
            self._stub = worker_pb2_grpc.WorkerServiceStub(self.channel)

    def _get_metadata(self) -> list[tuple[str, str]]:
        """Get gRPC metadata with token for requests.

        Returns:
            List of (key, value) tuples for gRPC metadata
        """
        from contextcore import create_grpc_metadata_with_token
        from contextcore.signing import get_signing_backend

        actual_token = self.token() if callable(self.token) else self.token
        if isinstance(actual_token, str):
            return [("authorization", f"Bearer {actual_token}")]

        backend = get_signing_backend()
        return create_grpc_metadata_with_token(actual_token, backend=backend)

    async def start_workflow(self, unit: ContextUnit) -> ContextUnit:
        """Start a durable workflow via Temporal.

        Args:
            unit: ContextUnit with workflow_type and parameters in payload.
                  Expected payload keys:
                  - workflow_type: "harvest", "gardener", "sync", etc.
                  - tenant_id: Tenant identifier.
                  - Additional workflow-specific parameters.

        Returns:
            ContextUnit with workflow_id and run_id in payload.
        """
        # Add provenance (create new list to avoid mutating caller's data)
        unit.provenance = list(unit.provenance) + ["sdk:worker_client:start_workflow"]

        if self.mode == "grpc":
            req = unit.to_protobuf(context_unit_pb2)
            metadata = self._get_metadata()  # Include token in metadata
            response_pb = await self._stub.StartWorkflow(req, metadata=metadata)
            return ContextUnit.from_protobuf(response_pb)
        else:
            from contextworker.workflows import HarvesterImportWorkflow
            from temporalio.client import Client

            client = await Client.connect(self.temporal_host)
            url = unit.payload.get("url")
            handle = await client.start_workflow(
                HarvesterImportWorkflow.run,
                url,
                id=f"harvest-{unit.unit_id}",
                task_queue="harvester-tasks",
            )
            unit.payload["workflow_id"] = handle.id
            return unit

    async def register_schedules(self, unit: ContextUnit) -> ContextUnit:
        """Register schedules via ContextWorker.

        Args:
            unit: ContextUnit with schedules data in payload
                  - schedules: list of schedule dicts
                  - project_id: string
                  - tenant_id: string
        """
        unit.provenance = list(unit.provenance) + ["sdk:worker_client:register_schedules"]

        if self.mode == "grpc":
            req = unit.to_protobuf(context_unit_pb2)
            metadata = self._get_metadata()
            response_pb = await self._stub.RegisterSchedules(req, metadata=metadata)
            return ContextUnit.from_protobuf(response_pb)
        else:
            from contextworker.schedules import ScheduleConfig, create_schedule
            from temporalio.client import Client

            client = await Client.connect(self.temporal_host)
            schedules = unit.payload.get("schedules", [])
            tenant_id = unit.payload.get("tenant_id")

            registered_count = 0
            for sched_data in schedules:
                config = ScheduleConfig(**sched_data)
                await create_schedule(client, config, tenant_id=tenant_id)
                registered_count += 1

            unit.payload["registered_count"] = registered_count
            unit.payload["status"] = "ok"
            return unit

    async def get_task_status(self, workflow_id: str) -> ContextUnit:
        """Get status of a running workflow.

        Args:
            workflow_id: Workflow identifier.

        Returns:
            ContextUnit with status, result, or error in payload.
        """
        unit = ContextUnit(
            payload={"workflow_id": workflow_id},
            provenance=["sdk:worker_client:get_task_status"],
        )

        if self.mode == "grpc":
            req = unit.to_protobuf(context_unit_pb2)
            metadata = self._get_metadata()  # Include token in metadata
            response_pb = await self._stub.GetTaskStatus(req, metadata=metadata)
            return ContextUnit.from_protobuf(response_pb)
        else:
            raise NotImplementedError("Local mode get_task_status not implemented")


__all__ = ["WorkerClient"]
