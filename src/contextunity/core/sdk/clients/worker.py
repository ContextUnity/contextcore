"""WorkerClient - SDK client for contextunity.worker service.

Unary RPCs follow the platform SDK contract: typed kwargs on input,
``ContextUnitPayload`` wire on output. ``ContextUnit`` envelopes are built
internally for gRPC transport (provenance, trace_id, …).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar
from uuid import UUID

from contextunity.core.grpc_client_errors import wrap_client_error
from contextunity.core.sdk.execution_trace_artifacts import (
    ExecutionTraceArtifactArchiveReceipt,
    ProtectedExecutionTraceArtifactEnvelope,
)
from contextunity.core.sdk.payload import copy_wire_payload
from contextunity.core.sdk.types import UnaryContextUnitRpc
from contextunity.core.types import ContextUnitPayload, JsonValue
from contextunity.core.worker_pb2_grpc import WorkerServiceStub

from ..contextunit import ContextUnit
from ._base import BaseServiceClient

if TYPE_CHECKING:
    from typing import TypeAlias

    from contextunity.core.worker_pb2_grpc import WorkerServiceAsyncStub

    _WorkerBase: TypeAlias = BaseServiceClient[WorkerServiceAsyncStub]
else:
    _WorkerBase = BaseServiceClient


class WorkerClient(_WorkerBase):
    """Client for interacting with contextunity.worker.

    Example:
        async with WorkerClient(host="localhost:50052", token=my_token) as client:
            wire = await client.start_workflow(
                workflow_type="sync",
                args=[],
            )
            workflow_id = wire.get("workflow_id")
    """

    _service_name: ClassVar[str] = "worker"
    _default_port: ClassVar[str] = "50052"
    _config_url_attr: ClassVar[str] = "worker_url"
    _stub_class: ClassVar[type] = WorkerServiceStub

    def _request_unit(
        self,
        payload: ContextUnitPayload,
        *,
        rpc_name: str,
        provenance: list[str] | None = None,
        trace_id: UUID | None = None,
        parent_unit_id: UUID | None = None,
    ) -> ContextUnit:
        """Build a transport ``ContextUnit`` for Worker unary RPCs."""
        chain = list(provenance or [])
        chain.append(f"sdk:worker_client:{rpc_name}")
        if trace_id is not None and parent_unit_id is not None:
            return ContextUnit(
                payload=payload,
                provenance=chain,
                trace_id=trace_id,
                parent_unit_id=parent_unit_id,
            )
        if trace_id is not None:
            return ContextUnit(payload=payload, provenance=chain, trace_id=trace_id)
        if parent_unit_id is not None:
            return ContextUnit(payload=payload, provenance=chain, parent_unit_id=parent_unit_id)
        return ContextUnit(payload=payload, provenance=chain)

    async def _dispatch_unary(
        self,
        rpc: UnaryContextUnitRpc,
        payload: ContextUnitPayload,
        *,
        rpc_name: str,
        provenance: list[str] | None = None,
        trace_id: UUID | None = None,
        parent_unit_id: UUID | None = None,
    ) -> ContextUnitPayload:
        unit = self._request_unit(
            payload,
            rpc_name=rpc_name,
            provenance=provenance,
            trace_id=trace_id,
            parent_unit_id=parent_unit_id,
        )
        req = unit.to_protobuf(self._cu_pb2)
        metadata = self._get_metadata()
        with wrap_client_error("Worker", rpc_name):
            response_pb = await rpc(req, metadata=metadata)
        return copy_wire_payload(ContextUnit.from_protobuf(response_pb).payload)

    async def start_workflow(
        self,
        *,
        workflow_type: str,
        args: JsonValue | None = None,
        task_queue: str | None = None,
        timeout_seconds: int | None = None,
        wire: ContextUnitPayload | None = None,
        provenance: list[str] | None = None,
        trace_id: UUID | None = None,
        parent_unit_id: UUID | None = None,
    ) -> ContextUnitPayload:
        """Start a durable workflow via Temporal/Huey.

        Args:
            workflow_type: Registered workflow name.
            args: Workflow arguments (server expects a JSON array).
            task_queue: Target queue; server defaults to ``{tenant}-tasks``.
            timeout_seconds: Optional execution timeout hint for the engine.
            wire: Open payload extension for evolving Worker RPC fields.
            provenance: Caller lineage labels appended before SDK transport tag.
            trace_id: Optional distributed trace id for the envelope.
            parent_unit_id: Optional parent ContextUnit id for lineage.

        Returns:
            Full server wire payload (``workflow_id``, ``run_id``, ``status``, …).
        """
        payload: ContextUnitPayload = dict(wire or {})
        payload["workflow_type"] = workflow_type
        if args is not None:
            payload["args"] = args
        if task_queue is not None:
            payload["task_queue"] = task_queue
        if timeout_seconds is not None:
            payload["timeout_seconds"] = timeout_seconds

        return await self._dispatch_unary(
            self._stub.StartWorkflow,
            payload,
            rpc_name="StartWorkflow",
            provenance=provenance,
            trace_id=trace_id,
            parent_unit_id=parent_unit_id,
        )

    async def register_schedules(
        self,
        *,
        project_id: str,
        schedules: list[ContextUnitPayload],
        provenance: list[str] | None = None,
    ) -> ContextUnitPayload:
        """Register recurring workflow schedules.

        Args:
            project_id: Project identifier owning the schedules.
            schedules: Schedule definitions (``schedule_id``, ``cron``, …).
            provenance: Caller lineage labels appended before SDK transport tag.

        Returns:
            Full server wire payload (``status``, ``registered_count``, …).
        """
        payload: ContextUnitPayload = {
            "project_id": project_id,
            "schedules": schedules,
        }

        return await self._dispatch_unary(
            self._stub.RegisterSchedules,
            payload,
            rpc_name="RegisterSchedules",
            provenance=provenance,
        )

    async def get_task_status(self, workflow_id: str) -> ContextUnitPayload:
        """Get status of a running workflow.

        Tenant identity is carried by the ``ContextToken`` — not an argument.

        Args:
            workflow_id: Workflow identifier.

        Returns:
            Full server wire payload (``status``, ``result``, ``error``, …).
        """
        payload = await self._call_unary(
            self._stub.GetTaskStatus,
            {"workflow_id": workflow_id},
            rpc_name="GetTaskStatus",
        )
        return copy_wire_payload(payload)

    async def execute_code(
        self,
        *,
        code: str,
        language: str = "python",
        timeout_seconds: int = 30,
        sandbox: bool = True,
    ) -> ContextUnitPayload:
        """Execute source code securely via contextunity.worker.

        Args:
            code: The source code string to execute.
            language: The runtime language (e.g., "python").
            timeout_seconds: Maximum allowed execution time in seconds.
            sandbox: Whether to execute the code in an isolated sandbox environment.

        Returns:
            Full server wire payload (``stdout``, ``stderr``, ``exit_code``, …).

        Raises:
            PlatformServiceError: If the execution request fails.
        """
        payload = await self._call_unary(
            self._stub.ExecuteCode,
            {
                "code": code,
                "language": language,
                "timeout": timeout_seconds,
                "sandbox": sandbox,
            },
            rpc_name="ExecuteCode",
        )
        return copy_wire_payload(payload)

    async def archive_execution_trace_artifact(
        self,
        envelope: ProtectedExecutionTraceArtifactEnvelope,
        *,
        offload_profile_id: str,
        source_revision: int,
    ) -> ExecutionTraceArtifactArchiveReceipt:
        """Store one opaque protected envelope and return a URI-free receipt."""
        payload = await self._call_unary(
            self._stub.ArchiveExecutionTraceArtifact,
            {
                "envelope": envelope.model_dump(mode="json"),
                "offload_profile_id": offload_profile_id,
                "source_revision": source_revision,
            },
            rpc_name="ArchiveExecutionTraceArtifact",
        )
        return ExecutionTraceArtifactArchiveReceipt.model_validate(payload)

    async def restore_execution_trace_artifact(
        self,
        receipt: ExecutionTraceArtifactArchiveReceipt,
    ) -> ProtectedExecutionTraceArtifactEnvelope:
        """Restore and validate one exact archived protected envelope."""
        payload = await self._call_unary(
            self._stub.RestoreExecutionTraceArtifact,
            {"receipt": receipt.model_dump(mode="json")},
            rpc_name="RestoreExecutionTraceArtifact",
        )
        return ProtectedExecutionTraceArtifactEnvelope.model_validate(payload)

    async def purge_execution_trace_artifact_archive(
        self,
        receipt: ExecutionTraceArtifactArchiveReceipt,
    ) -> None:
        """Delete one exact archived ciphertext object."""
        _ = await self._call_unary(
            self._stub.PurgeExecutionTraceArtifactArchive,
            {"receipt": receipt.model_dump(mode="json")},
            rpc_name="PurgeExecutionTraceArtifactArchive",
        )


__all__ = ["WorkerClient"]
