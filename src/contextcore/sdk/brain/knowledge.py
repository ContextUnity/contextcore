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
            metadata = self._get_metadata()  # Include token in metadata
            results = []
            async for response_pb in self._stub.Search(req, metadata=metadata):
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
            logger.warning("Local search failed: %s", e)
        return []

    async def upsert(
        self: BrainClientBase,
        tenant_id: str,
        content: str,
        source_type: str,
        metadata: dict[str, Any] | None = None,
        doc_id: str | None = None,
    ) -> str:
        """Upsert content to Brain.

        Args:
            tenant_id: Tenant identifier.
            content: Content to store.
            source_type: Type of source (e.g., "document", "news_fact").
            metadata: Additional metadata.
            doc_id: Optional deterministic document ID for true upsert
                    (overwrites existing node with same ID via ON CONFLICT).
                    If None, a random UUID is generated.

        Returns:
            The ID of the stored item.
        """
        from uuid import UUID as _UUID

        unit_kwargs: dict[str, Any] = {
            "payload": {
                "tenant_id": tenant_id,
                "content": content,
                "source_type": source_type,
                "metadata": metadata or {},
            },
            "provenance": ["sdk:brain_client:upsert"],
        }
        if doc_id:
            unit_kwargs["unit_id"] = _UUID(doc_id) if isinstance(doc_id, str) else doc_id

        unit = ContextUnit(**unit_kwargs)

        if self.mode == "grpc":
            pb2 = get_context_unit_pb2()
            req = unit.to_protobuf(pb2)
            metadata = self._get_metadata()  # Include token in metadata
            response_pb = await self._stub.Upsert(req, metadata=metadata)
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
            logger.warning("Local upsert failed: %s", e)
        return ""

    async def create_kg_relation(
        self: BrainClientBase,
        tenant_id: str,
        source_type: str,
        source_id: str,
        relation: str,
        target_type: str,
        target_id: str,
        trace_id: "str | None" = None,
        parent_provenance: "List[str] | None" = None,
    ) -> bool:
        """Create a Knowledge Graph relation.

        Args:
            tenant_id: Tenant identifier.
            source_type: Type of source node (e.g., 'product').
            source_id: Source node ID.
            relation: Relation type (e.g., 'MADE_BY', 'BELONGS_TO').
            target_type: Type of target node (e.g., 'brand', 'category').
            target_id: Target node ID.
            trace_id: Optional trace ID for distributed tracing.
            parent_provenance: Optional provenance chain from parent.

        Returns:
            True if successful.
        """
        from uuid import UUID

        provenance = list(parent_provenance) if parent_provenance else []
        provenance.append("sdk:brain_client:create_kg")

        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "source_type": source_type,
                "source_id": source_id,
                "relation": relation,
                "target_type": target_type,
                "target_id": target_id,
            },
            trace_id=UUID(trace_id) if trace_id else None,
            provenance=provenance,
        )

        if self.mode == "grpc":
            pb2 = get_context_unit_pb2()
            req = unit.to_protobuf(pb2)
            metadata = self._get_metadata()  # Include token in metadata
            response_pb = await self._stub.CreateKGRelation(req, metadata=metadata)
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
            logger.warning("Local create_kg_relation failed: %s", e)
        return False

    async def graph_search(
        self: BrainClientBase,
        tenant_id: str,
        entrypoint_ids: "List[str]",
        max_hops: int = 2,
        allowed_relations: "List[str] | None" = None,
        max_results: int = 200,
        trace_id: "str | None" = None,
        parent_provenance: "List[str] | None" = None,
    ) -> dict[str, Any]:
        """Structural graph traversal.

        Walks knowledge graph edges starting from entrypoint_ids up to max_hops.
        Returns discovered nodes with attributes and traversed edges with weights.

        Args:
            tenant_id: Tenant identifier.
            entrypoint_ids: Starting node IDs for traversal.
            max_hops: Maximum traversal depth (default 2, max 10).
            allowed_relations: Optional filter — only traverse these edge types.
            max_results: Maximum edges to return (default 200).
            trace_id: Optional trace ID for distributed tracing.
            parent_provenance: Optional provenance chain from parent.

        Returns:
            Dict with 'nodes' (list of node dicts) and 'edges' (list of edge dicts).
        """
        from uuid import UUID

        provenance = list(parent_provenance) if parent_provenance else []
        provenance.append("sdk:brain_client:graph_search")

        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "entrypoint_ids": entrypoint_ids,
                "max_hops": max_hops,
                "allowed_relations": allowed_relations or [],
                "max_results": max_results,
            },
            trace_id=UUID(trace_id) if trace_id else None,
            provenance=provenance,
        )

        if self.mode == "grpc":
            pb2 = get_context_unit_pb2()
            req = unit.to_protobuf(pb2)
            metadata = self._get_metadata()
            response_pb = await self._stub.GraphSearch(req, metadata=metadata)
            result = ContextUnit.from_protobuf(response_pb)
            return {
                "nodes": result.payload.get("nodes", []),
                "edges": result.payload.get("edges", []),
            }
        else:
            return await self._local_graph_search(
                tenant_id=tenant_id,
                entrypoint_ids=entrypoint_ids,
                max_hops=max_hops,
                allowed_relations=allowed_relations,
                max_results=max_results,
            )

    async def _local_graph_search(
        self: BrainClientBase,
        tenant_id: str,
        entrypoint_ids: "List[str]",
        max_hops: int,
        allowed_relations: "List[str] | None",
        max_results: int,
    ) -> dict[str, Any]:
        """Local mode implementation of graph search."""
        try:
            if hasattr(self._service, "storage"):
                return await self._service.storage.graph_search(
                    tenant_id=tenant_id,
                    entrypoint_ids=entrypoint_ids,
                    max_hops=max_hops,
                    allowed_relations=allowed_relations,
                    max_results=max_results,
                )
        except Exception as e:
            logger.warning("Local graph_search failed: %s", e)
        return {"nodes": [], "edges": []}


__all__ = ["KnowledgeMixin"]
