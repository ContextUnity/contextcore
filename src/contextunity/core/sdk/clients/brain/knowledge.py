"""Knowledge methods - search, upsert, KG relations.

All operations are delegated to the Brain gRPC service.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import grpc
from contextunity.core.grpc_client_errors import wrap_client_error
from contextunity.core.sdk.payload import (
    copy_wire_payload,
    get_bool,
    get_float,
    get_json_dict,
    get_optional_str,
    get_str,
)
from contextunity.core.types import ContextUnitPayload, JsonDict

from ...contextunit import ContextUnit
from ...models import CellSearchResult

if TYPE_CHECKING:
    from .base import BrainClientBase as _MixinBase
else:
    _MixinBase = object


class KnowledgeMixin(_MixinBase):
    """Mixin with core knowledge operations via gRPC."""

    async def search_cells(
        self,
        *,
        query_text: str,
        tenant_id: str | None = None,
        user_id: str | None = None,
        limit: int = 5,
        min_score: float = 0.0,
        source_types: list[str] | None = None,
        scope_path: str | None = None,
        metadata_filter: JsonDict | None = None,
    ) -> list[CellSearchResult]:
        """Run canonical semantic/hybrid BrainCell retrieval."""
        payload: ContextUnitPayload = {
            "query_text": query_text,
            "limit": limit,
            "min_score": min_score,
            "source_types": source_types or [],
        }
        if tenant_id is not None:
            payload["tenant_id"] = tenant_id
        if user_id is not None:
            payload["user_id"] = user_id
        if scope_path is not None:
            payload["scope_path"] = scope_path
        if metadata_filter:
            payload["metadata_filter"] = metadata_filter
        unit = ContextUnit(payload=payload, provenance=["sdk:brain_client:search_cells"])
        req = unit.to_protobuf(self._cu_pb2)
        results: list[CellSearchResult] = []
        with wrap_client_error("Brain", "SearchCells"):
            async for response_pb in self._stub.SearchCells(req, metadata=self._get_metadata()):
                result = ContextUnit.from_protobuf(response_pb)
                p = result.payload
                results.append(
                    CellSearchResult(
                        id=get_str(p, "id"),
                        tenant_id=get_str(p, "tenant_id"),
                        cell_kind=get_str(p, "cell_kind"),
                        content=get_str(p, "content"),
                        score=get_float(p, "score"),
                        vector_score=(get_float(p, "vector_score") if p.get("vector_score") is not None else None),
                        text_score=(get_float(p, "text_score") if p.get("text_score") is not None else None),
                        source_type=get_str(p, "source_type"),
                        source_ref=get_optional_str(p, "source_ref"),
                        scope_path=get_optional_str(p, "scope_path"),
                        content_hash=get_optional_str(p, "content_hash"),
                        confidence=get_float(p, "confidence", 0.5),
                        visibility=get_str(p, "visibility", "tenant"),
                        metadata=get_json_dict(p, "metadata"),
                    )
                )
                if len(results) >= limit:
                    break
        return results

    async def ingest_document(
        self,
        *,
        content: str,
        source_type: str,
        tenant_id: str | None = None,
        user_id: str | None = None,
        metadata: JsonDict | None = None,
    ) -> str:
        """Run Brain's explicit document enrichment and ingestion pipeline."""
        payload: ContextUnitPayload = {
            "content": content,
            "source_type": source_type,
            "metadata": metadata or {},
        }
        if tenant_id is not None:
            payload["tenant_id"] = tenant_id
        if user_id is not None:
            payload["user_id"] = user_id
        unit = ContextUnit(payload=payload, provenance=["sdk:brain_client:ingest_document"])
        req = unit.to_protobuf(self._cu_pb2)
        with wrap_client_error("Brain", "IngestDocument"):
            response_pb = await self._stub.IngestDocument(req, metadata=self._get_metadata())
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

    async def upsert_cell(
        self,
        *,
        cell_kind: str,
        content: str,
        tenant_id: str | None = None,
        cell_id: str | None = None,
        user_id: str | None = None,
        metadata: JsonDict | None = None,
        scope_path: str | None = None,
        content_hash: str | None = None,
        source_type: str = "manual",
        source_ref: str | None = None,
        confidence: float = 0.5,
        visibility: str = "tenant",
    ) -> ContextUnitPayload:
        """Upsert a canonical BrainCell using content hash for idempotency and source metadata."""
        payload: ContextUnitPayload = {
            "cell_kind": cell_kind,
            "content": content,
            "metadata": metadata or {},
            "source_type": source_type,
            "confidence": confidence,
            "visibility": visibility,
        }
        if tenant_id is not None:
            payload["tenant_id"] = tenant_id
        if cell_id is not None:
            payload["cell_id"] = cell_id
        if user_id is not None:
            payload["user_id"] = user_id
        if scope_path is not None:
            payload["scope_path"] = scope_path
        if content_hash is not None:
            payload["content_hash"] = content_hash
        if source_ref is not None:
            payload["source_ref"] = source_ref
        unit = ContextUnit(payload=payload, provenance=["sdk:brain_client:upsert_cell"])
        req = unit.to_protobuf(self._cu_pb2)
        with wrap_client_error("Brain", "UpsertCell"):
            response_pb = await self._stub.UpsertCell(req, metadata=self._get_metadata())
        return copy_wire_payload(ContextUnit.from_protobuf(response_pb).payload)

    async def query_cells(
        self,
        *,
        tenant_id: str | None = None,
        query_text: str | None = None,
        cell_kind: str | None = None,
        source_type: str | None = None,
        scope_path: str | None = None,
        metadata_filter: JsonDict | None = None,
        limit: int = 10,
        offset: int = 0,
        user_id: str | None = None,
    ) -> list[ContextUnitPayload]:
        """Query canonical BrainCells with optional filters."""
        payload: ContextUnitPayload = {
            "query_text": query_text,
            "cell_kind": cell_kind,
            "source_type": source_type,
            "scope_path": scope_path,
            "metadata_filter": metadata_filter or {},
            "limit": limit,
            "offset": offset,
        }
        if tenant_id is not None:
            payload["tenant_id"] = tenant_id
        if user_id is not None:
            payload["user_id"] = user_id
        unit = ContextUnit(payload=payload, provenance=["sdk:brain_client:query_cells"])
        req = unit.to_protobuf(self._cu_pb2)
        out: list[ContextUnitPayload] = []
        with wrap_client_error("Brain", "QueryCells"):
            async for response_pb in self._stub.QueryCells(req, metadata=self._get_metadata()):
                out.append(copy_wire_payload(ContextUnit.from_protobuf(response_pb).payload))
        return out

    async def query_all_cells(
        self,
        *,
        tenant_id: str | None = None,
        query_text: str | None = None,
        cell_kind: str | None = None,
        source_type: str | None = None,
        scope_path: str | None = None,
        metadata_filter: JsonDict | None = None,
        user_id: str | None = None,
        max_items: int = 10_000,
        page_size: int = 100,
    ) -> list[ContextUnitPayload]:
        """Read a bounded complete cell result set through QueryCells pagination."""
        if max_items < 1 or page_size < 1 or page_size > 100:
            raise ValueError("query_all_cells requires max_items >= 1 and 1 <= page_size <= 100")
        records: list[ContextUnitPayload] = []
        offset = 0
        while len(records) < max_items:
            requested = min(page_size, max_items - len(records))
            page = await self.query_cells(
                tenant_id=tenant_id,
                query_text=query_text,
                cell_kind=cell_kind,
                source_type=source_type,
                scope_path=scope_path,
                metadata_filter=metadata_filter,
                user_id=user_id,
                limit=requested,
                offset=offset,
            )
            records.extend(page)
            if len(page) < requested:
                break
            offset += len(page)
        return records

    async def get_cell(
        self, *, cell_id: str, tenant_id: str | None = None, user_id: str | None = None
    ) -> ContextUnitPayload | None:
        """Retrieve a single canonical BrainCell by ID."""
        payload: ContextUnitPayload = {"cell_id": cell_id}
        if tenant_id is not None:
            payload["tenant_id"] = tenant_id
        if user_id is not None:
            payload["user_id"] = user_id
        unit = ContextUnit(payload=payload, provenance=["sdk:brain_client:get_cell"])
        req = unit.to_protobuf(self._cu_pb2)
        try:
            response_pb = await self._stub.GetCell(req, metadata=self._get_metadata())
        except grpc.RpcError as error:
            if error.code() == grpc.StatusCode.NOT_FOUND:
                return None
            with wrap_client_error("Brain", "GetCell"):
                raise
        return copy_wire_payload(ContextUnit.from_protobuf(response_pb).payload)

    async def delete_documentation_cells(
        self,
        *,
        targets: list[JsonDict],
        tenant_id: str | None = None,
    ) -> ContextUnitPayload:
        """Atomically delete exact documentation cells or return a version conflict."""
        payload: ContextUnitPayload = {"targets": targets}
        if tenant_id is not None:
            payload["tenant_id"] = tenant_id
        unit = ContextUnit(
            payload=payload,
            provenance=["sdk:brain_client:delete_documentation_cells"],
        )
        req = unit.to_protobuf(self._cu_pb2)
        with wrap_client_error("Brain", "DeleteDocumentationCells"):
            response_pb = await self._stub.DeleteDocumentationCells(
                req,
                metadata=self._get_metadata(),
            )
        return copy_wire_payload(ContextUnit.from_protobuf(response_pb).payload)


__all__ = ["KnowledgeMixin"]
