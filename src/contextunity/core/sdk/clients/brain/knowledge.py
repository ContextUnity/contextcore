"""Knowledge methods - search, upsert, KG relations.

All operations are delegated to the Brain gRPC service.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from contextunity.core.grpc_client_errors import wrap_client_error
from contextunity.core.sdk.payload import copy_wire_payload, get_bool, get_float, get_json_dict, get_str
from contextunity.core.types import ContextUnitPayload, JsonDict

from ...contextunit import ContextUnit
from ...models import SearchResult

if TYPE_CHECKING:
    from .base import BrainClientBase as _MixinBase
else:
    _MixinBase = object


class KnowledgeMixin(_MixinBase):
    """Mixin with core knowledge operations via gRPC."""

    async def search(
        self,
        tenant_id: str,
        query_text: str,
        limit: int = 5,
        source_types: list[str] | None = None,
    ) -> list[SearchResult]:
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

        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        results: list[SearchResult] = []
        with wrap_client_error("Brain", "Search"):
            async for response_pb in self._stub.Search(req, metadata=grpc_metadata):
                result = ContextUnit.from_protobuf(response_pb)
                p = result.payload
                results.append(
                    SearchResult(
                        id=get_str(p, "id"),
                        content=get_str(p, "content"),
                        score=get_float(p, "score"),
                        source_type=get_str(p, "source_type"),
                        metadata=get_json_dict(p, "metadata"),
                    )
                )
                if len(results) >= limit:
                    break
        return results

    async def upsert(
        self,
        tenant_id: str,
        content: str,
        source_type: str,
        metadata: JsonDict | None = None,
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
        unit = ContextUnit(
            payload={
                "tenant_id": tenant_id,
                "content": content,
                "source_type": source_type,
                "metadata": metadata or {},
            },
            provenance=["sdk:brain_client:upsert"],
            unit_id=UUID(doc_id) if doc_id else uuid4(),
        )

        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        with wrap_client_error("Brain", "Upsert"):
            response_pb = await self._stub.Upsert(req, metadata=grpc_metadata)
        result = ContextUnit.from_protobuf(response_pb)
        return get_str(result.payload, "id")

    async def create_kg_relation(
        self,
        tenant_id: str,
        source_type: str,
        source_id: str,
        relation: str,
        target_type: str,
        target_id: str,
        trace_id: str | None = None,
        parent_provenance: list[str] | None = None,
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
            provenance=provenance,
            trace_id=UUID(trace_id) if trace_id else uuid4(),
        )

        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        with wrap_client_error("Brain", "CreateKGRelation"):
            response_pb = await self._stub.CreateKGRelation(req, metadata=grpc_metadata)
        result = ContextUnit.from_protobuf(response_pb)
        return get_bool(result.payload, "success")

    async def graph_search(
        self,
        tenant_id: str,
        entrypoint_ids: list[str],
        max_hops: int = 2,
        allowed_relations: list[str] | None = None,
        max_results: int = 200,
        trace_id: str | None = None,
        parent_provenance: list[str] | None = None,
    ) -> ContextUnitPayload:
        """Structural graph traversal.

        Walks knowledge graph edges starting from entrypoint_ids up to max_hops.
        Returns discovered nodes with attributes and traversed edges with weights.
        """
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
            provenance=provenance,
            trace_id=UUID(trace_id) if trace_id else uuid4(),
        )

        req = unit.to_protobuf(self._cu_pb2)
        grpc_metadata = self._get_metadata()
        with wrap_client_error("Brain", "GraphSearch"):
            response_pb = await self._stub.GraphSearch(req, metadata=grpc_metadata)
        result = ContextUnit.from_protobuf(response_pb)
        return copy_wire_payload(result.payload)


__all__ = ["KnowledgeMixin"]
