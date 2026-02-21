"""WorkerClient - SDK client for ContextWorker service.

Uses ContextUnit protocol for all gRPC communication.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

from .context_unit import ContextUnit

if TYPE_CHECKING:
    from contextcore import ContextToken

logger = logging.getLogger(__name__)

# Proto imports (lazy, may not be available)
context_unit_pb2 = None
worker_pb2_grpc = None


def _ensure_protos():
    """Lazy load proto modules."""
    global context_unit_pb2, worker_pb2_grpc
    if context_unit_pb2 is None:
        try:
            from .. import context_unit_pb2 as cu_pb2
            from .. import worker_pb2_grpc as worker_grpc

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
    ):
        """Initialize WorkerClient.

        Args:
            host: Worker gRPC endpoint (e.g., "worker:50052")
            mode: "grpc" or "local"
            token: Optional ContextToken for authorization
        """

        self.mode = mode or os.getenv("CONTEXT_WORKER_MODE", "grpc")
        self.host = host or os.getenv("CONTEXT_WORKER_URL", "localhost:50052")
        self.temporal_host = os.getenv("TEMPORAL_HOST", "localhost:7233")
        self.token: ContextToken | None = token
        self._stub = None
        self.channel = None

        if self.mode == "grpc":
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

        return create_grpc_metadata_with_token(self.token)

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

    async def get_task_status(self, workflow_id: str) -> ContextUnit:
        """Get status of a running workflow.

        Args:
            workflow_id: The workflow ID to check.

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
