"""WorkerClient - SDK client for ContextWorker service.

Uses ContextUnit protocol for all gRPC communication.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

import grpc

from .context_unit import ContextUnit

if TYPE_CHECKING:
    pass

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
        client = WorkerClient(host="localhost:50052")
        result = await client.start_workflow(ContextUnit(
            payload={"workflow_type": "harvest", "supplier_code": "xyz"}
        ))
    """

    def __init__(self, host: str | None = None, mode: str | None = None):
        self.mode = mode or os.getenv("CONTEXT_WORKER_MODE", "grpc")
        self.host = host or os.getenv("CONTEXT_WORKER_URL", "localhost:50052")
        self.temporal_host = os.getenv("TEMPORAL_HOST", "localhost:7233")
        self._stub = None
        self.channel = None

        if self.mode == "grpc":
            _ensure_protos()
            self.channel = grpc.insecure_channel(self.host)
            self._stub = worker_pb2_grpc.WorkerServiceStub(self.channel)

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
        # Add provenance
        unit.provenance.append("sdk:worker_client:start_workflow")

        if self.mode == "grpc":
            req = unit.to_protobuf(context_unit_pb2)
            response_pb = self._stub.StartWorkflow(req)
            return ContextUnit.from_protobuf(response_pb)
        else:
            from temporalio.client import Client

            from contextworker.workflows import HarvesterImportWorkflow

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
            response_pb = self._stub.GetTaskStatus(req)
            return ContextUnit.from_protobuf(response_pb)
        else:
            raise NotImplementedError("Local mode get_task_status not implemented")


__all__ = ["WorkerClient"]
