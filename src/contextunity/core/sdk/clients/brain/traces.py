"""Trace methods - agent execution trace persistence.

All operations are delegated to the Brain gRPC service.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from contextunity.core.grpc_client_errors import wrap_client_error
from contextunity.core.narrowing import as_json_dict
from contextunity.core.sdk.execution_trace_artifacts import (
    ExecutionTraceArtifactFinalizationReceipt,
    ExecutionTraceArtifactIdentity,
    ExecutionTraceArtifactReservationReceipt,
    ModelIOContentPart,
    ModelIOProviderStatus,
)
from contextunity.core.sdk.payload import (
    get_dict_list,
    get_int,
    get_json_dict,
    get_json_dict_list,
    get_str,
    get_str_list,
)
from contextunity.core.sdk.responses import TraceFinalizationReceipt, TraceRecord
from contextunity.core.sdk.types import TerminalTraceWire
from contextunity.core.types import ContextUnitPayload, JsonDict

from ...contextunit import ContextUnit

if TYPE_CHECKING:
    from .base import BrainClientBase as _MixinBase
else:
    _MixinBase = object


class TraceMixin(_MixinBase):
    """Mixin with agent trace operations via gRPC."""

    async def log_trace(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        session_id: str | None = None,
        user_id: str | None = None,
        graph_name: str | None = None,
        tool_calls: list[ContextUnitPayload] | None = None,
        token_usage: JsonDict | None = None,
        timing_ms: int | None = None,
        security_flags: JsonDict | None = None,
        metadata: JsonDict | None = None,
        provenance: list[str] | None = None,
    ) -> str:
        """Log an agent execution trace.

        Args:
            tenant_id: Tenant identifier for isolation.
            agent_id: Agent that produced the trace.
            session_id: Optional session identifier.
            user_id: Optional user identifier.
            graph_name: Which graph was executed.
            tool_calls: List of tool call records.
            token_usage: LLM token usage breakdown.
            timing_ms: Total wall-clock time in ms.
            security_flags: Shield/security audit flags.
            metadata: Additional metadata.
            provenance: Data-journey labels (e.g. ["contextmed:chat", "tool:execute_sql"]).

        Returns:
            The ID of the stored trace.
        """
        # Provenance: use caller-provided chain as-is (don't add SDK transport labels)
        full_provenance = list(provenance or [])

        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "session_id": session_id or "",
                "user_id": user_id,
                "graph_name": graph_name or "",
                "tool_calls": tool_calls or [],
                "token_usage": token_usage or {},
                "timing_ms": timing_ms or 0,
                "security_flags": security_flags or {},
                "metadata": metadata or {},
                "provenance": full_provenance,
            },
            provenance=full_provenance,
        )

        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        with wrap_client_error("Brain", "LogTrace"):
            response_pb = await self._stub.LogTrace(req, metadata=grpc_metadata)
        result = ContextUnit.from_protobuf(response_pb)
        return get_str(result.payload, "id", str(result.unit_id))

    async def finalize_execution_trace(
        self,
        *,
        terminal_trace: TerminalTraceWire,
    ) -> TraceFinalizationReceipt:
        """Finalize one terminal execution trace through the existing LogTrace RPC."""
        payload: ContextUnitPayload = {"terminal_trace": terminal_trace}
        unit = ContextUnit(payload=payload, provenance=["sdk:brain_client:finalize_trace"])
        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        with wrap_client_error("Brain", "LogTrace"):
            response_pb = await self._stub.LogTrace(req, metadata=grpc_metadata)
        result = ContextUnit.from_protobuf(response_pb)
        return TraceFinalizationReceipt(
            trace_id=get_str(result.payload, "trace_id"),
            graph_run_id=get_str(result.payload, "graph_run_id"),
            digest=get_str(result.payload, "digest"),
            outcome=("duplicate" if get_str(result.payload, "outcome") == "duplicate" else "created"),
        )

    async def reserve_execution_trace_artifact(
        self,
        *,
        identity: ExecutionTraceArtifactIdentity,
        artifact_id: UUID,
        lifecycle_profile_id: str,
        request_parts: list[ModelIOContentPart],
    ) -> ExecutionTraceArtifactReservationReceipt:
        """Protect and reserve exact provider-bound request content."""
        payload: ContextUnitPayload = {
            "identity": identity.model_dump(mode="json"),
            "artifact_id": str(artifact_id),
            "lifecycle_profile_id": lifecycle_profile_id,
            "capture_policy_version": "contextunity.model-io-capture/v1",
            "request_parts": [part.model_dump(mode="json") for part in request_parts],
        }
        unit = ContextUnit(payload=payload, provenance=["sdk:brain_client:reserve_trace_artifact"])
        with wrap_client_error("Brain", "ReserveExecutionTraceArtifact"):
            response_pb = await self._stub.ReserveExecutionTraceArtifact(
                unit.to_protobuf(self._cu_pb2),
                metadata=self._get_metadata(),
            )
        result = ContextUnit.from_protobuf(response_pb)
        return ExecutionTraceArtifactReservationReceipt.model_validate(result.payload)

    async def finalize_execution_trace_artifact(
        self,
        *,
        identity: ExecutionTraceArtifactIdentity,
        artifact_id: UUID,
        expected_revision: int,
        provider_status: ModelIOProviderStatus,
        response_parts: list[ModelIOContentPart],
    ) -> ExecutionTraceArtifactFinalizationReceipt:
        """Protect and CAS-finalize the visible provider response."""
        payload: ContextUnitPayload = {
            "identity": identity.model_dump(mode="json"),
            "artifact_id": str(artifact_id),
            "expected_revision": expected_revision,
            "provider_status": provider_status,
            "response_parts": [part.model_dump(mode="json") for part in response_parts],
        }
        unit = ContextUnit(payload=payload, provenance=["sdk:brain_client:finalize_trace_artifact"])
        with wrap_client_error("Brain", "FinalizeExecutionTraceArtifact"):
            response_pb = await self._stub.FinalizeExecutionTraceArtifact(
                unit.to_protobuf(self._cu_pb2),
                metadata=self._get_metadata(),
            )
        result = ContextUnit.from_protobuf(response_pb)
        return ExecutionTraceArtifactFinalizationReceipt.model_validate(result.payload)

    async def archive_execution_trace_artifact(
        self,
        *,
        tenant_id: str,
        project_id: str,
        artifact_id: UUID,
        expected_revision: int,
        lifecycle_profile_id: str,
    ) -> JsonDict:
        """Move one hot protected artifact to its C0-selected cold profile."""
        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "project_id": project_id,
                "artifact_id": str(artifact_id),
                "expected_revision": expected_revision,
                "lifecycle_profile_id": lifecycle_profile_id,
            },
            provenance=["sdk:brain_client:archive_trace_artifact"],
        )
        with wrap_client_error("Brain", "ArchiveExecutionTraceArtifact"):
            response_pb = await self._stub.ArchiveExecutionTraceArtifact(
                unit.to_protobuf(self._cu_pb2), metadata=self._get_metadata()
            )
        return as_json_dict(ContextUnit.from_protobuf(response_pb).payload)

    async def restore_execution_trace_artifact(
        self,
        *,
        tenant_id: str,
        project_id: str,
        artifact_id: UUID,
        expected_revision: int,
        lifecycle_profile_id: str,
    ) -> JsonDict:
        """Restore one cold protected artifact through Worker readback CAS."""
        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "project_id": project_id,
                "artifact_id": str(artifact_id),
                "expected_revision": expected_revision,
                "lifecycle_profile_id": lifecycle_profile_id,
            },
            provenance=["sdk:brain_client:restore_trace_artifact"],
        )
        with wrap_client_error("Brain", "RestoreExecutionTraceArtifact"):
            response_pb = await self._stub.RestoreExecutionTraceArtifact(
                unit.to_protobuf(self._cu_pb2), metadata=self._get_metadata()
            )
        return as_json_dict(ContextUnit.from_protobuf(response_pb).payload)

    async def get_traces(
        self,
        *,
        tenant_id: str,
        agent_id: str | None = None,
        session_id: str | None = None,
        limit: int = 20,
        since: str | None = None,
    ) -> list[TraceRecord]:
        """Get agent execution traces.

        Args:
            tenant_id: Tenant identifier for isolation.
            agent_id: Optional filter by agent.
            session_id: Optional filter by session.
            limit: Maximum number of traces to return.
            since: ISO timestamp — only return traces after this time.

        Returns:
            List of trace dicts with id, agent_id, graph_name, etc.
        """
        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "agent_id": agent_id or "",
                "session_id": session_id or "",
                "limit": limit,
                "since": since or "",
            },
            provenance=["sdk:brain_client:get_traces"],
        )

        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        traces: list[TraceRecord] = []
        with wrap_client_error("Brain", "GetTraces"):
            async for response_pb in self._stub.GetTraces(req, metadata=grpc_metadata):
                result = ContextUnit.from_protobuf(response_pb)
                p = result.payload
                traces.append(
                    TraceRecord(
                        id=get_str(p, "id"),
                        agent_id=get_str(p, "agent_id"),
                        graph_name=get_str(p, "graph_name"),
                        session_id=get_str(p, "session_id"),
                        user_id=get_str(p, "user_id"),
                        tool_calls=get_dict_list(p, "tool_calls"),
                        token_usage=get_json_dict(p, "token_usage"),
                        timing_ms=get_int(p, "timing_ms"),
                        security_flags=get_json_dict(p, "security_flags"),
                        metadata=get_json_dict(p, "metadata"),
                        provenance=get_str_list(p, "provenance"),
                        graph_run_id=get_str(p, "graph_run_id"),
                        payload_digest=get_str(p, "payload_digest"),
                        terminal_status=get_str(p, "terminal_status"),
                        terminal_reason=get_str(p, "terminal_reason"),
                        trace_schema_version=get_str(p, "trace_schema_version"),
                        prompt_evidence=get_json_dict_list(p, "prompt_evidence"),
                        steps=get_json_dict_list(p, "steps"),
                        created_at=get_str(p, "created_at"),
                    )
                )
                if len(traces) >= limit:
                    break
        return traces


__all__ = ["TraceMixin"]
