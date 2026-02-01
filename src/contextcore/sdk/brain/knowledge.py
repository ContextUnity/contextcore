"""Knowledge methods - search, upsert, KG relations.

Supports both gRPC and local modes for flexibility in development.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..context_unit import ContextUnit
from ..models import SearchResult
from .base import BrainClientBase, get_context_unit_pb2, logger

if TYPE_CHECKING:
    from typing import List


class KnowledgeMixin:
    """Mixin with core knowledge operations.

    All methods support:
    - gRPC mode: Network calls to Brain service
    - local mode: Direct library calls (for development)
    """

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
            # Local mode - direct library call
            return await self._local_search(
                tenant_id=tenant_id,
                query_text=query_text,
                limit=limit,
                source_types=source_types,
            )

    async def _local_search(
        self: BrainClientBase,
        tenant_id: str,
        query_text: str,
        limit: int,
        source_types: "List[str] | None",
    ) -> "List[SearchResult]":
        """Local mode implementation of search."""
        try:
            # Get embedder from service
            if hasattr(self._service, "embedder"):
                query_vec = await self._service.embedder.embed_async(query_text)
            else:
                query_vec = [0.1] * 1536

            # Call storage directly
            if hasattr(self._service, "storage"):
                raw_results = await self._service.storage.hybrid_search(
                    query_text=query_text,
                    query_vec=query_vec,
                    tenant_id=tenant_id,
                    limit=limit,
                    source_types=source_types if source_types else None,
                )
                return [
                    SearchResult(
                        id=r.node.id if hasattr(r, "node") else "",
                        content=r.node.content if hasattr(r, "node") else "",
                        score=r.score if hasattr(r, "score") else 0.0,
                        source_type=r.node.source_type if hasattr(r, "node") else "",
                        metadata=r.node.metadata if hasattr(r, "node") else {},
                    )
                    for r in raw_results
                ]
        except Exception as e:
            logger.warning(f"Local search failed: {e}")
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
            # Local mode - direct library call
            return await self._local_upsert(
                tenant_id=tenant_id,
                content=content,
                source_type=source_type,
                metadata=metadata or {},
            )

    async def _local_upsert(
        self: BrainClientBase,
        tenant_id: str,
        content: str,
        source_type: str,
        metadata: dict,
    ) -> str:
        """Local mode implementation of upsert."""
        try:
            if hasattr(self._service, "storage"):
                # Generate embedding
                if hasattr(self._service, "embedder"):
                    embedding = await self._service.embedder.embed_async(content)
                else:
                    embedding = [0.1] * 1536

                # Create node and upsert
                from contextbrain.storage.postgres.models import GraphNode

                node = GraphNode(
                    id="",  # Will be generated
                    content=content,
                    source_type=source_type,
                    embedding=embedding,
                    metadata=metadata,
                )
                result = await self._service.storage.upsert_knowledge(
                    node=node,
                    tenant_id=tenant_id,
                )
                return result.id if hasattr(result, "id") else str(result)
        except Exception as e:
            logger.warning(f"Local upsert failed: {e}")
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
            # Local mode
            return await self._local_create_kg_relation(
                tenant_id=tenant_id,
                source_type=source_type,
                source_id=source_id,
                relation=relation,
                target_type=target_type,
                target_id=target_id,
            )

    async def _local_create_kg_relation(
        self: BrainClientBase,
        tenant_id: str,
        source_type: str,
        source_id: str,
        relation: str,
        target_type: str,
        target_id: str,
    ) -> bool:
        """Local mode implementation of KG relation creation."""
        try:
            if hasattr(self._service, "storage"):
                from contextbrain.storage.postgres.models import GraphEdge

                edge = GraphEdge(
                    source_id=f"{source_type}:{source_id}",
                    target_id=f"{target_type}:{target_id}",
                    relation=relation,
                    weight=1.0,
                    metadata={},
                )
                await self._service.storage.upsert_graph(
                    nodes=[],
                    edges=[edge],
                    tenant_id=tenant_id,
                )
                return True
        except Exception as e:
            logger.warning(f"Local create_kg_relation failed: {e}")
        return False


__all__ = ["KnowledgeMixin"]
