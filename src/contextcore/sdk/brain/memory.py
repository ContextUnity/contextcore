"""Memory methods - episodic events, user facts.

Supports both gRPC and local modes for flexibility in development.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..context_unit import ContextUnit
from .base import BrainClientBase, get_context_unit_pb2, logger

if TYPE_CHECKING:
    pass


class MemoryMixin:
    """Mixin with episodic and entity memory operations.

    All methods support:
    - gRPC mode: Network calls to Brain service
    - local mode: Direct library calls (for development)
    """

    # =========================================
    # Episodic Memory
    # =========================================

    async def add_episode(
        self: BrainClientBase,
        *,
        tenant_id: str,
        user_id: str,
        content: str,
        session_id: str | None = None,
        metadata: dict[str, Any] | None = None,
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

        if self.mode == "grpc":
            pb2 = get_context_unit_pb2()
            req = unit.to_protobuf(pb2)
            grpc_metadata = self._get_metadata()
            response_pb = await self._stub.AddEpisode(req, metadata=grpc_metadata)
            result = ContextUnit.from_protobuf(response_pb)
            return str(result.unit_id)
        else:
            return await self._local_add_episode(
                tenant_id=tenant_id,
                user_id=user_id,
                content=content,
                session_id=session_id,
                metadata=metadata,
            )

    async def _local_add_episode(
        self: BrainClientBase,
        tenant_id: str,
        user_id: str,
        content: str,
        session_id: str | None,
        metadata: dict | None,
    ) -> str:
        """Local mode implementation of add_episode."""
        import uuid

        episode_id = str(uuid.uuid4())
        await self._service.storage.add_episode(
            id=episode_id,
            tenant_id=tenant_id,
            user_id=user_id,
            content=content,
            session_id=session_id,
            metadata=metadata or {},
        )
        return episode_id

    async def get_recent_episodes(
        self: BrainClientBase,
        *,
        tenant_id: str,
        user_id: str,
        limit: int = 5,
    ) -> list[dict]:
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

        if self.mode == "grpc":
            pb2 = get_context_unit_pb2()
            req = unit.to_protobuf(pb2)
            grpc_metadata = self._get_metadata()
            episodes = []
            async for response_pb in self._stub.GetRecentEpisodes(req, metadata=grpc_metadata):
                result = ContextUnit.from_protobuf(response_pb)
                episodes.append(result.payload)
                if len(episodes) >= limit:
                    break
            return episodes
        else:
            return await self._local_get_recent_episodes(
                tenant_id=tenant_id,
                user_id=user_id,
                limit=limit,
            )

    async def _local_get_recent_episodes(
        self: BrainClientBase,
        tenant_id: str,
        user_id: str,
        limit: int,
    ) -> list[dict]:
        """Local mode implementation of get_recent_episodes."""
        rows = await self._service.storage.get_recent_episodes(
            user_id=user_id,
            tenant_id=tenant_id,
            limit=limit,
        )
        return [
            {
                "id": str(row.get("id", "")),
                "content": row.get("content", ""),
                "metadata": row.get("metadata", {}),
                "created_at": str(row.get("created_at", "")),
            }
            for row in rows
        ]

    # =========================================
    # Entity Memory (User Facts)
    # =========================================

    async def upsert_fact(
        self: BrainClientBase,
        *,
        tenant_id: str,
        user_id: str,
        key: str,
        value: Any,
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

        if self.mode == "grpc":
            pb2 = get_context_unit_pb2()
            req = unit.to_protobuf(pb2)
            grpc_metadata = self._get_metadata()
            await self._stub.UpsertFact(req, metadata=grpc_metadata)
        else:
            await self._local_upsert_fact(
                tenant_id=tenant_id,
                user_id=user_id,
                key=key,
                value=value,
                confidence=confidence,
                source_id=source_id,
            )

    async def _local_upsert_fact(
        self: BrainClientBase,
        tenant_id: str,
        user_id: str,
        key: str,
        value: Any,
        confidence: float,
        source_id: str | None,
    ) -> None:
        """Local mode implementation of upsert_fact."""
        await self._service.storage.upsert_fact(
            user_id=user_id,
            tenant_id=tenant_id,
            key=key,
            value=value,
            confidence=confidence,
            source_id=source_id,
        )

    async def get_user_facts(
        self: BrainClientBase,
        *,
        tenant_id: str,
        user_id: str,
    ) -> dict[str, Any]:
        """Get all known facts about a user.

        Args:
            tenant_id: Tenant identifier for isolation.
            user_id: User identifier.

        Returns:
            Dict mapping fact_key -> fact_value.
        """
        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "user_id": user_id,
            },
            provenance=["sdk:brain_client:get_user_facts"],
        )

        if self.mode == "grpc":
            pb2 = get_context_unit_pb2()
            req = unit.to_protobuf(pb2)
            grpc_metadata = self._get_metadata()
            facts = {}
            async for response_pb in self._stub.GetUserFacts(req, metadata=grpc_metadata):
                result = ContextUnit.from_protobuf(response_pb)
                fact_key = result.payload.get("fact_key", "")
                fact_value = result.payload.get("fact_value", "")
                if fact_key:
                    facts[fact_key] = fact_value
            return facts
        else:
            return await self._local_get_user_facts(
                tenant_id=tenant_id,
                user_id=user_id,
            )

    async def _local_get_user_facts(
        self: BrainClientBase,
        tenant_id: str,
        user_id: str,
    ) -> dict[str, Any]:
        """Local mode implementation of get_user_facts."""
        rows = await self._service.storage.get_user_facts(
            user_id=user_id,
            tenant_id=tenant_id,
        )
        return {row["fact_key"]: row["fact_value"] for row in rows}

    # =========================================
    # Retention & Distillation
    # =========================================

    async def retention_cleanup(
        self: BrainClientBase,
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

        if self.mode == "grpc":
            pb2 = get_context_unit_pb2()
            req = unit.to_protobuf(pb2)
            grpc_metadata = self._get_metadata()
            response_pb = await self._stub.RetentionCleanup(req, metadata=grpc_metadata)
            result = ContextUnit.from_protobuf(response_pb)
            return result.payload.get("deleted_count", 0)
        else:
            return await self._service.storage.delete_old_episodes(
                tenant_id=tenant_id,
                older_than_days=older_than_days,
                episode_ids=episode_ids,
            )

    async def get_old_episodes(
        self: BrainClientBase,
        *,
        tenant_id: str = "default",
        older_than_days: int = 30,
        limit: int = 100,
    ) -> list[dict]:
        """Get episodes older than N days (for distillation).

        Args:
            tenant_id: Tenant identifier.
            older_than_days: Threshold in days.
            limit: Maximum batch size.

        Returns:
            List of episode dicts with id, user_id, content, metadata, created_at.
        """
        if self.mode == "local":
            rows = await self._service.storage.get_old_episodes(
                tenant_id=tenant_id,
                older_than_days=older_than_days,
                limit=limit,
            )
            return [
                {
                    "id": str(row.get("id", "")),
                    "user_id": row.get("user_id", ""),
                    "content": row.get("content", ""),
                    "metadata": row.get("metadata", {}),
                    "created_at": str(row.get("created_at", "")),
                }
                for row in rows
            ]
        # gRPC — use GetRecentEpisodes with older_than filter
        # (for now, not yet a dedicated streaming RPC)
        logger.warning("get_old_episodes via gRPC not yet implemented, returning empty")
        return []

    async def get_episode_stats(
        self: BrainClientBase,
        *,
        tenant_id: str = "default",
    ) -> dict:
        """Get episode count and date range for a tenant.

        Returns:
            Dict with total, oldest, newest, tenant_id.
        """
        unit = ContextUnit(
            payload={"tenant_id": tenant_id},
            provenance=["sdk:brain_client:get_episode_stats"],
        )

        if self.mode == "grpc":
            pb2 = get_context_unit_pb2()
            req = unit.to_protobuf(pb2)
            grpc_metadata = self._get_metadata()
            response_pb = await self._stub.GetEpisodeStats(req, metadata=grpc_metadata)
            result = ContextUnit.from_protobuf(response_pb)
            return result.payload
        else:
            return await self._service.storage.count_episodes(
                tenant_id=tenant_id,
            )


__all__ = ["MemoryMixin"]
