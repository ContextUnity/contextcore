"""Trace methods - agent execution trace persistence.

Supports both gRPC and local modes for flexibility in development.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..context_unit import ContextUnit
from .base import BrainClientBase, get_context_unit_pb2

if TYPE_CHECKING:
    pass


class TraceMixin:
    """Mixin with agent trace operations.

    All methods support:
    - gRPC mode: Network calls to Brain service
    - local mode: Direct library calls (for development)
    """

    async def log_trace(
        self: BrainClientBase,
        *,
        tenant_id: str,
        agent_id: str,
        session_id: str | None = None,
        user_id: str | None = None,
        graph_name: str | None = None,
        tool_calls: list[dict[str, Any]] | None = None,
        token_usage: dict[str, Any] | None = None,
        timing_ms: int | None = None,
        security_flags: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
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
        # Build provenance: caller-provided chain + SDK label
        full_provenance = list(provenance or [])
        full_provenance.append("sdk:brain_client:log_trace")

        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "session_id": session_id or "",
                "user_id": user_id or "",
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

        if self.mode == "grpc":
            pb2 = get_context_unit_pb2()
            req = unit.to_protobuf(pb2)
            grpc_metadata = self._get_metadata()
            response_pb = await self._stub.LogTrace(req, metadata=grpc_metadata)
            result = ContextUnit.from_protobuf(response_pb)
            return result.payload.get("id", str(result.unit_id))
        else:
            return await self._local_log_trace(
                tenant_id=tenant_id,
                agent_id=agent_id,
                session_id=session_id,
                user_id=user_id,
                graph_name=graph_name,
                tool_calls=tool_calls,
                token_usage=token_usage,
                timing_ms=timing_ms,
                security_flags=security_flags,
                metadata=metadata,
                provenance=full_provenance,
            )

    async def _local_log_trace(
        self: BrainClientBase,
        tenant_id: str,
        agent_id: str,
        session_id: str | None,
        user_id: str | None,
        graph_name: str | None,
        tool_calls: list | None,
        token_usage: dict | None,
        timing_ms: int | None,
        security_flags: dict | None,
        metadata: dict | None,
        provenance: list[str] | None = None,
    ) -> str:
        """Local mode implementation of log_trace."""
        return await self._service.storage.log_trace(
            tenant_id=tenant_id,
            agent_id=agent_id,
            session_id=session_id,
            user_id=user_id,
            graph_name=graph_name,
            tool_calls=tool_calls,
            token_usage=token_usage,
            timing_ms=timing_ms,
            security_flags=security_flags,
            metadata=metadata,
            provenance=provenance,
        )

    async def get_traces(
        self: BrainClientBase,
        *,
        tenant_id: str,
        agent_id: str | None = None,
        session_id: str | None = None,
        limit: int = 20,
        since: str | None = None,
    ) -> list[dict]:
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

        if self.mode == "grpc":
            pb2 = get_context_unit_pb2()
            req = unit.to_protobuf(pb2)
            grpc_metadata = self._get_metadata()
            traces = []
            async for response_pb in self._stub.GetTraces(req, metadata=grpc_metadata):
                result = ContextUnit.from_protobuf(response_pb)
                traces.append(result.payload)
                if len(traces) >= limit:
                    break
            return traces
        else:
            return await self._local_get_traces(
                tenant_id=tenant_id,
                agent_id=agent_id,
                session_id=session_id,
                limit=limit,
                since=since,
            )

    async def _local_get_traces(
        self: BrainClientBase,
        tenant_id: str,
        agent_id: str | None,
        session_id: str | None,
        limit: int,
        since: str | None,
    ) -> list[dict]:
        """Local mode implementation of get_traces."""
        rows = await self._service.storage.get_traces(
            tenant_id=tenant_id,
            agent_id=agent_id,
            session_id=session_id,
            limit=limit,
            since=since,
        )
        return [
            {
                "id": str(row.get("id", "")),
                "agent_id": row.get("agent_id", ""),
                "session_id": row.get("session_id", ""),
                "user_id": row.get("user_id", ""),
                "graph_name": row.get("graph_name", ""),
                "tool_calls": row.get("tool_calls", []),
                "token_usage": row.get("token_usage", {}),
                "timing_ms": row.get("timing_ms"),
                "security_flags": row.get("security_flags", {}),
                "metadata": row.get("metadata", {}),
                "provenance": row.get("provenance", []),
                "created_at": str(row.get("created_at", "")),
            }
            for row in rows
        ]


__all__ = ["TraceMixin"]
