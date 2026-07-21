"""Conversation History, Blackboard, and retention methods.

All operations are delegated to the Brain gRPC service.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Literal
from uuid import UUID

from contextunity.core.grpc_client_errors import wrap_client_error
from contextunity.core.sdk.conversation import (
    ConversationAppendReceipt,
    ConversationHistoryStats,
    ConversationKind,
    ConversationProjection,
    ConversationRecord,
    ConversationRetentionReceipt,
    ConversationRole,
)
from contextunity.core.sdk.payload import copy_wire_payload, get_int
from contextunity.core.types import ContextUnitPayload, JsonDict

from ...contextunit import ContextUnit

if TYPE_CHECKING:
    from .base import BrainClientBase as _MixinBase
else:
    _MixinBase = object


class MemoryMixin(_MixinBase):
    """Mixin with Conversation History and Blackboard operations via gRPC."""

    # =========================================
    # Conversation History
    # =========================================

    async def append_conversation_record(
        self,
        *,
        record_id: UUID,
        tenant_id: str,
        user_id: str,
        session_id: str | None,
        role: ConversationRole,
        kind: ConversationKind,
        content: str,
        content_hash: str,
        source_hash: str,
        graph_run_id: UUID | None,
        metadata_version: Literal[1] = 1,
        idempotency_key: str,
        metadata: JsonDict | None = None,
    ) -> ConversationAppendReceipt:
        """Append one provenance-complete immutable conversation record."""
        if metadata_version != 1:
            raise ValueError("metadata_version must be 1")
        unit = ContextUnit(
            payload={
                "record_id": str(record_id),
                "tenant_id": tenant_id,
                "user_id": user_id,
                "session_id": session_id,
                "role": role,
                "kind": kind,
                "content": content,
                "content_hash": content_hash,
                "source_hash": source_hash,
                "graph_run_id": str(graph_run_id) if graph_run_id is not None else None,
                "metadata_version": metadata_version,
                "idempotency_key": idempotency_key,
                "metadata": metadata or {},
            },
            provenance=["sdk:brain_client:append_conversation_record"],
        )

        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        with wrap_client_error("Brain", "AppendConversationRecord"):
            response_pb = await self._stub.AppendConversationRecord(req, metadata=grpc_metadata)
        result = ContextUnit.from_protobuf(response_pb)
        return ConversationAppendReceipt.model_validate(copy_wire_payload(result.payload))

    async def query_conversation_history(
        self,
        *,
        tenant_id: str,
        projection: ConversationProjection,
        user_id: str | None = None,
        session_id: str | None = None,
        graph_run_id: UUID | None = None,
        older_than_days: int | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ConversationRecord]:
        """Run one bounded canonical history projection."""
        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "projection": projection,
                "user_id": user_id,
                "session_id": session_id,
                "graph_run_id": str(graph_run_id) if graph_run_id is not None else None,
                "older_than_days": older_than_days,
                "limit": limit,
                "offset": offset,
            },
            provenance=["sdk:brain_client:query_conversation_history"],
        )

        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        records: list[ConversationRecord] = []
        with wrap_client_error("Brain", "QueryConversationHistory"):
            async for response_pb in self._stub.QueryConversationHistory(req, metadata=grpc_metadata):
                result = ContextUnit.from_protobuf(response_pb)
                records.append(ConversationRecord.model_validate(copy_wire_payload(result.payload)))
                if len(records) >= limit:
                    break
        return records

    # =========================================
    # Blackboard (Pass-by-Reference)
    # =========================================

    async def write_blackboard(
        self,
        *,
        tenant_id: str,
        scope_path: str,
        content: ContextUnitPayload,
        metadata: JsonDict | None = None,
        ttl_seconds: int | None = None,
        created_by: str | None = None,
    ) -> ContextUnitPayload:
        """Write a Blackboard record for pass-by-reference between graph nodes.

        Args:
            tenant_id: Tenant identifier for isolation (validated against the token).
            scope_path: LTREE-shaped scope path, e.g. ``"tenant.project.session.step"``.
            content: JSON-serializable payload to store.
            metadata: Optional metadata dict.
            ttl_seconds: Optional TTL in seconds. ``None`` means no expiry.
            created_by: Optional agent_id or node_name provenance tag.

        Returns:
            The service response payload unchanged: ``{id, scope_path, created_at}``.
        """
        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "scope_path": scope_path,
                "content": content,
                "metadata": metadata or {},
                "ttl_seconds": ttl_seconds,
                "created_by": created_by,
            },
            provenance=["sdk:brain_client:write_blackboard"],
        )

        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        with wrap_client_error("Brain", "WriteBlackboard"):
            response_pb = await self._stub.WriteBlackboard(req, metadata=grpc_metadata)
        result = ContextUnit.from_protobuf(response_pb)
        return copy_wire_payload(result.payload)

    async def read_blackboard(
        self,
        *,
        ids: list[str],
        tenant_id: str,
    ) -> ContextUnitPayload:
        """Read Blackboard records by UUID — strictly batched, single round trip.

        Args:
            ids: UUID strings to resolve. The server excludes expired records.
            tenant_id: Tenant identifier. Not sent over the wire — the server
                resolves the read tenant from the verified token
                (``ReadBlackboardPayload`` has no ``tenant_id`` field by
                design — a token-first contract). Kept as an explicit
                parameter for call-site symmetry with ``write_blackboard`` and
                for local ContextUnit provenance.

        Returns:
            The service response payload unchanged: ``{records: [...]}``.
        """
        _ = tenant_id
        unit = ContextUnit(
            payload={"ids": ids},
            provenance=["sdk:brain_client:read_blackboard"],
        )

        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        with wrap_client_error("Brain", "ReadBlackboard"):
            response_pb = await self._stub.ReadBlackboard(req, metadata=grpc_metadata)
        result = ContextUnit.from_protobuf(response_pb)
        return copy_wire_payload(result.payload)

    # =========================================
    async def prune_expired_blackboard(self, *, tenant_id: str) -> int:
        """Prune expired Blackboard records for one tenant."""
        unit = ContextUnit(
            payload={"tenant_id": tenant_id},
            provenance=["sdk:brain_client:prune_expired_blackboard"],
        )
        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        with wrap_client_error("Brain", "PruneExpiredBlackboard"):
            response_pb = await self._stub.PruneExpiredBlackboard(req, metadata=grpc_metadata)
        result = ContextUnit.from_protobuf(response_pb)
        return get_int(result.payload, "deleted_count")

    # Retention and statistics
    # =========================================

    async def get_conversation_history_stats(
        self,
        *,
        tenant_id: str,
    ) -> ConversationHistoryStats:
        """Get content-free Conversation History statistics."""
        unit = ContextUnit(
            payload={"tenant_id": tenant_id},
            provenance=["sdk:brain_client:get_conversation_history_stats"],
        )
        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        with wrap_client_error("Brain", "GetConversationHistoryStats"):
            response_pb = await self._stub.GetConversationHistoryStats(req, metadata=grpc_metadata)
        result = ContextUnit.from_protobuf(response_pb)
        return ConversationHistoryStats.model_validate(copy_wire_payload(result.payload))

    async def apply_conversation_retention(
        self,
        *,
        tenant_id: str,
        record_ids: list[UUID],
        cutoff: datetime,
        hold_evidence_hash: str,
    ) -> ConversationRetentionReceipt:
        """Apply explicit evidence-backed Conversation History retention."""
        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "record_ids": [str(record_id) for record_id in record_ids],
                "cutoff": cutoff.isoformat(),
                "policy_version": "contextunity.conversation-retention/v1",
                "hold_evidence_hash": hold_evidence_hash,
            },
            provenance=["sdk:brain_client:apply_conversation_retention"],
        )
        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        with wrap_client_error("Brain", "ApplyConversationRetention"):
            response_pb = await self._stub.ApplyConversationRetention(req, metadata=grpc_metadata)
        result = ContextUnit.from_protobuf(response_pb)
        return ConversationRetentionReceipt.model_validate(copy_wire_payload(result.payload))

    async def apply_execution_trace_retention(
        self,
        *,
        tenant_id: str,
        older_than_days: int = 30,
    ) -> int:
        """Apply terminal Execution Trace retention."""
        unit = ContextUnit(
            payload={"tenant_id": tenant_id, "older_than_days": older_than_days},
            provenance=["sdk:brain_client:apply_execution_trace_retention"],
        )
        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        with wrap_client_error("Brain", "ApplyExecutionTraceRetention"):
            response_pb = await self._stub.ApplyExecutionTraceRetention(req, metadata=grpc_metadata)
        result = ContextUnit.from_protobuf(response_pb)
        return get_int(result.payload, "deleted_count")


__all__ = ["MemoryMixin"]
