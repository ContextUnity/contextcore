"""Memory methods - episodic events, user facts.

All operations are delegated to the Brain gRPC service.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from contextunity.core.grpc_client_errors import wrap_client_error
from contextunity.core.sdk.payload import (
    copy_wire_payload,
    get_int,
    get_json_dict,
    get_json_value,
    get_str,
)
from contextunity.core.sdk.responses import EpisodeRecord
from contextunity.core.types import ContextUnitPayload, JsonDict, JsonValue

from ...contextunit import ContextUnit
from .base import logger

if TYPE_CHECKING:
    from .base import BrainClientBase as _MixinBase
else:
    _MixinBase = object


class MemoryMixin(_MixinBase):
    """Mixin with episodic and entity memory operations via gRPC."""

    # =========================================
    # Episodic Memory
    # =========================================

    async def add_episode(
        self,
        *,
        tenant_id: str,
        user_id: str | None = None,
        content: str,
        session_id: str | None = None,
        metadata: JsonDict | None = None,
    ) -> str:
        """Add a conversation episode to Brain's episodic memory.

        Args:
            tenant_id: Tenant identifier for isolation.
            user_id: User identifier.
            content: Episode content (conversation summary/note).
            session_id: Optional session identifier.
            metadata: Additional metadata.

        Returns:
            The ID of the stored episode.
        """
        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "user_id": user_id,
                "content": content,
                "session_id": session_id or "",
                "metadata": metadata or {},
            },
            provenance=["sdk:brain_client:add_episode"],
        )

        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        with wrap_client_error("Brain", "AddEpisode"):
            response_pb = await self._stub.AddEpisode(req, metadata=grpc_metadata)
        result = ContextUnit.from_protobuf(response_pb)
        return str(result.unit_id)

    async def get_recent_episodes(
        self,
        *,
        tenant_id: str,
        user_id: str,
        limit: int = 5,
    ) -> list[EpisodeRecord]:
        """Get recent episodes for a user from Brain's episodic memory.

        Args:
            tenant_id: Tenant identifier for isolation.
            user_id: User identifier.
            limit: Maximum number of episodes to return.

        Returns:
            List of episode dicts with id, content, metadata, created_at.
        """
        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "user_id": user_id,
                "limit": limit,
            },
            provenance=["sdk:brain_client:get_recent_episodes"],
        )

        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        episodes: list[EpisodeRecord] = []
        with wrap_client_error("Brain", "GetRecentEpisodes"):
            async for response_pb in self._stub.GetRecentEpisodes(req, metadata=grpc_metadata):
                result = ContextUnit.from_protobuf(response_pb)
                p = result.payload
                episodes.append(
                    EpisodeRecord(
                        id=get_str(p, "id"),
                        user_id=get_str(p, "user_id"),
                        content=get_str(p, "content"),
                        session_id=get_str(p, "session_id"),
                        metadata=get_json_dict(p, "metadata"),
                        created_at=get_str(p, "created_at"),
                    )
                )
                if len(episodes) >= limit:
                    break
        return episodes

    # =========================================
    # Entity Memory (User Facts)
    # =========================================

    async def upsert_fact(
        self,
        *,
        tenant_id: str,
        user_id: str,
        key: str,
        value: object,
        confidence: float = 1.0,
        source_id: str | None = None,
    ) -> None:
        """Upsert a persistent fact about a user.

        Args:
            tenant_id: Tenant identifier for isolation.
            user_id: User identifier.
            key: Fact key (e.g., "language", "specialty").
            value: Fact value.
            confidence: Confidence score (0-1).
            source_id: Optional source episode ID.
        """
        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "user_id": user_id,
                "key": key,
                "value": value,
                "confidence": confidence,
                "source_id": source_id or "",
            },
            provenance=["sdk:brain_client:upsert_fact"],
        )

        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        with wrap_client_error("Brain", "UpsertFact"):
            _ = await self._stub.UpsertFact(req, metadata=grpc_metadata)

    async def get_user_facts(
        self,
        *,
        tenant_id: str,
        user_id: str,
    ) -> dict[str, JsonValue]:
        """Get all known facts about a user.

        Args:
            tenant_id: Tenant identifier for isolation.
            user_id: User identifier.

        Returns:
            Dict mapping fact_key -> fact_value (JSON-serializable values).
        """
        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "user_id": user_id,
            },
            provenance=["sdk:brain_client:get_user_facts"],
        )

        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        facts: dict[str, JsonValue] = {}
        with wrap_client_error("Brain", "GetUserFacts"):
            async for response_pb in self._stub.GetUserFacts(req, metadata=grpc_metadata):
                result = ContextUnit.from_protobuf(response_pb)
                fact_key = get_str(result.payload, "fact_key")
                fact_value = get_json_value(result.payload, "fact_value")
                if fact_key:
                    facts[fact_key] = fact_value
        return facts

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
    # Retention & Distillation
    # =========================================

    async def retention_cleanup(
        self,
        *,
        tenant_id: str = "default",
        older_than_days: int = 30,
        episode_ids: list[str] | None = None,
    ) -> int:
        """Delete old episodic events (retention policy).

        Args:
            tenant_id: Tenant identifier.
            older_than_days: Delete episodes older than this many days.
            episode_ids: Optional specific episode IDs to delete.

        Returns:
            Number of deleted episodes.
        """
        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "older_than_days": older_than_days,
                "episode_ids": episode_ids,
            },
            provenance=["sdk:brain_client:retention_cleanup"],
        )

        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        with wrap_client_error("Brain", "RetentionCleanup"):
            response_pb = await self._stub.RetentionCleanup(req, metadata=grpc_metadata)
        result = ContextUnit.from_protobuf(response_pb)
        return get_int(result.payload, "deleted_count")

    async def get_old_episodes(
        self,
        *,
        tenant_id: str = "default",
        older_than_days: int = 30,
        limit: int = 100,
    ) -> list[EpisodeRecord]:
        """Get episodes older than N days (for distillation).

        Args:
            tenant_id: Tenant identifier.
            older_than_days: Threshold in days.
            limit: Maximum batch size.

        Returns:
            List of episode dicts with id, user_id, content, metadata, created_at.
        """
        # TODO: implement dedicated GetOldEpisodes streaming RPC
        logger.warning(
            "get_old_episodes via gRPC not yet implemented, returning empty (tenant_id=%s, older_than_days=%s, limit=%s)",
            tenant_id,
            older_than_days,
            limit,
        )
        return []

    async def get_episode_stats(
        self,
        *,
        tenant_id: str = "default",
    ) -> ContextUnitPayload:
        """Get episode count and date range for a tenant."""
        unit = ContextUnit(
            payload={"tenant_id": tenant_id},
            provenance=["sdk:brain_client:get_episode_stats"],
        )

        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        with wrap_client_error("Brain", "GetEpisodeStats"):
            response_pb = await self._stub.GetEpisodeStats(req, metadata=grpc_metadata)
        result = ContextUnit.from_protobuf(response_pb)
        return copy_wire_payload(result.payload)


__all__ = ["MemoryMixin"]
