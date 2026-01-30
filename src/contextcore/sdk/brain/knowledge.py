"""Knowledge methods - search, upsert, KG relations."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..context_unit import ContextUnit
from ..models import SearchResult
from .base import BrainClientBase, get_context_unit_pb2, logger

if TYPE_CHECKING:
    from typing import List


class KnowledgeMixin:
    """Mixin with core knowledge operations."""

    async def search(
        self: BrainClientBase,
        tenant_id: str,
        query_text: str,
        limit: int = 5,
        source_types: "List[str] | None" = None,
    ) -> "List[SearchResult]":
        """Search for similar content in Brain.

        Args:
            tenant_id: Tenant identifier for isolation.
            query_text: Search query text.
            limit: Maximum number of results.
            source_types: Filter by source types (e.g., ["news_fact", "document"]).

        Returns:
            List of SearchResult with content, score, and metadata.
        """
        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "query_text": query_text,
                "limit": limit,
                "source_types": source_types or [],
            },
            provenance=["sdk:brain_client:search"],
        )

        if self.mode == "grpc":
            pb2 = get_context_unit_pb2()
            req = unit.to_protobuf(pb2)
            results = []
            async for response_pb in self._stub.Search(req):
                result = ContextUnit.from_protobuf(response_pb)
                results.append(
                    SearchResult(
                        id=result.payload.get("id", ""),
                        content=result.payload.get("content", ""),
                        score=result.payload.get("score", 0.0),
                        source_type=result.payload.get("source_type", ""),
                        metadata=result.payload.get("metadata", {}),
                    )
                )
                if len(results) >= limit:
                    break
            return results
        else:
            logger.warning("Local mode search not fully implemented yet")
            return []

    async def upsert(
        self: BrainClientBase,
        tenant_id: str,
        content: str,
        source_type: str,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Upsert content to Brain.

        Args:
            tenant_id: Tenant identifier.
            content: Content to store.
            source_type: Type of source (e.g., "document", "news_fact").
            metadata: Additional metadata.

        Returns:
            The ID of the stored item.
        """
        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "content": content,
                "source_type": source_type,
                "metadata": metadata or {},
            },
            provenance=["sdk:brain_client:upsert"],
        )

        if self.mode == "grpc":
            pb2 = get_context_unit_pb2()
            req = unit.to_protobuf(pb2)
            response_pb = await self._stub.Upsert(req)
            result = ContextUnit.from_protobuf(response_pb)
            return result.payload.get("id", "")
        else:
            logger.warning("Local mode upsert not implemented yet")
            return ""

    async def create_kg_relation(
        self: BrainClientBase,
        tenant_id: str,
        source_type: str,
        source_id: str,
        relation: str,
        target_type: str,
        target_id: str,
    ) -> bool:
        """Create a Knowledge Graph relation.

        Args:
            tenant_id: Tenant identifier.
            source_type: Type of source node (e.g., 'product').
            source_id: Source node ID.
            relation: Relation type (e.g., 'MADE_BY', 'BELONGS_TO').
            target_type: Type of target node (e.g., 'brand', 'category').
            target_id: Target node ID.

        Returns:
            True if successful.
        """
        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "source_type": source_type,
                "source_id": source_id,
                "relation": relation,
                "target_type": target_type,
                "target_id": target_id,
            },
            provenance=["sdk:brain_client:create_kg"],
        )

        if self.mode == "grpc":
            pb2 = get_context_unit_pb2()
            req = unit.to_protobuf(pb2)
            response_pb = await self._stub.CreateKGRelation(req)
            result = ContextUnit.from_protobuf(response_pb)
            return result.payload.get("success", False)
        else:
            logger.warning("Local mode not implemented")
            return False


__all__ = ["KnowledgeMixin"]
