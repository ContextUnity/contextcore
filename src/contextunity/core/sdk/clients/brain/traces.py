"""Trace methods - agent execution trace persistence.

All operations are delegated to the Brain gRPC service.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from contextunity.core.grpc_client_errors import wrap_client_error
from contextunity.core.sdk.payload import get_dict_list, get_int, get_json_dict, get_str, get_str_list
from contextunity.core.sdk.responses import TraceRecord
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
                        created_at=get_str(p, "created_at"),
                    )
                )
                if len(traces) >= limit:
                    break
        return traces


__all__ = ["TraceMixin"]
