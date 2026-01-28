"""ContextUnit SDK - Core data structures for ContextUnity protocol."""

from __future__ import annotations

# IMPORTANT: Import google well-known types FIRST, before any other imports
# that might trigger loading of our pb2 files through circular imports.
# Our pb2 files depend on struct.proto and timestamp.proto
try:
    from google.protobuf import struct_pb2 as _struct_pb2  # noqa: F401
    from google.protobuf import timestamp_pb2 as _timestamp_pb2  # noqa: F401
except ImportError:
    pass  # protobuf not installed, gRPC features won't work

from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class CotStep(BaseModel):
    agent: str
    action: str
    status: str = "pending"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SearchResult(BaseModel):
    """Result from Brain semantic search."""

    id: str = ""
    content: str = ""
    score: float = 0.0
    source_type: str = ""
    metadata: dict[str, str] = Field(default_factory=dict)


class UnitMetrics(BaseModel):
    """Metrics for tracking unit processing costs and performance."""

    latency_ms: int = 0
    cost_usd: float = 0.0
    tokens_used: int = 0
    cost_limit_usd: float = 0.0


class SecurityScopes(BaseModel):
    read: list[str] = Field(default_factory=list)
    write: list[str] = Field(default_factory=list)


class ContextUnit(BaseModel):
    """Core data structure for ContextUnity protocol - atomic unit of data exchange."""

    unit_id: UUID = Field(default_factory=uuid4)
    trace_id: UUID = Field(default_factory=uuid4)
    parent_unit_id: UUID | None = None

    modality: str = "text"
    payload: dict[str, Any] = Field(default_factory=dict)

    provenance: list[str] = Field(default_factory=list)
    chain_of_thought: list["CotStep"] = Field(default_factory=list)

    metrics: UnitMetrics = Field(default_factory=UnitMetrics)
    security: SecurityScopes = Field(default_factory=SecurityScopes)

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_protobuf(self, pb_module):
        """Converts Pydantic model to Protobuf message."""
        from google.protobuf.struct_pb2 import Struct
        from google.protobuf.timestamp_pb2 import Timestamp

        payload_struct = Struct()
        payload_struct.update(self.payload)

        created_at_pb = Timestamp()
        created_at_pb.FromDatetime(self.created_at)

        # Convert chain_of_thought to protobuf CotStep messages
        cot_steps = []
        for step in self.chain_of_thought:
            step_timestamp = Timestamp()
            step_timestamp.FromDatetime(step.timestamp)
            cot_pb = pb_module.CotStep(
                agent=step.agent,
                action=step.action,
                status=step.status,
                timestamp=step_timestamp,
            )
            cot_steps.append(cot_pb)

        # Convert metrics to protobuf
        metrics_pb = None
        if self.metrics:
            metrics_pb = pb_module.UnitMetrics(
                latency_ms=self.metrics.latency_ms,
                cost_usd=self.metrics.cost_usd,
                tokens_used=self.metrics.tokens_used,
                cost_limit_usd=self.metrics.cost_limit_usd,
            )

        # Convert security scopes to protobuf
        security_pb = None
        if self.security:
            security_pb = pb_module.SecurityScopes(
                read=list(self.security.read),
                write=list(self.security.write),
            )

        unit_pb = pb_module.ContextUnit(
            unit_id=str(self.unit_id),
            trace_id=str(self.trace_id),
            parent_unit_id=str(self.parent_unit_id) if self.parent_unit_id else "",
            modality=0,  # Need mapping for enum
            payload=payload_struct,
            provenance=self.provenance,
            chain_of_thought=cot_steps,
            metrics=metrics_pb,
            security=security_pb,
            created_at=created_at_pb,
        )
        return unit_pb

    @classmethod
    def from_protobuf(cls, unit_pb):
        """Converts Protobuf message to Pydantic model."""
        # Convert chain_of_thought from protobuf
        cot_steps = []
        for step_pb in unit_pb.chain_of_thought:
            cot_steps.append(
                CotStep(
                    agent=step_pb.agent,
                    action=step_pb.action,
                    status=step_pb.status,
                    timestamp=step_pb.timestamp.ToDatetime(),
                )
            )

        # Convert metrics from protobuf
        metrics = None
        if unit_pb.metrics:
            metrics = UnitMetrics(
                latency_ms=unit_pb.metrics.latency_ms,
                cost_usd=unit_pb.metrics.cost_usd,
                tokens_used=unit_pb.metrics.tokens_used,
                cost_limit_usd=unit_pb.metrics.cost_limit_usd,
            )

        # Convert security scopes from protobuf
        security = None
        if unit_pb.security:
            security = SecurityScopes(
                read=list(unit_pb.security.read),
                write=list(unit_pb.security.write),
            )

        return cls(
            unit_id=UUID(unit_pb.unit_id),
            trace_id=UUID(unit_pb.trace_id),
            parent_unit_id=UUID(unit_pb.parent_unit_id)
            if unit_pb.parent_unit_id
            else None,
            payload=dict(unit_pb.payload),
            provenance=list(unit_pb.provenance),
            chain_of_thought=cot_steps,
            metrics=metrics,
            security=security,
            created_at=unit_pb.created_at.ToDatetime(),
        )


import grpc  # noqa: E402
import os  # noqa: E402
import logging  # noqa: E402
from typing import List  # noqa: E402

try:
    # Import our pb2 files (well-known types already imported at top of file)
    from . import context_unit_pb2
    from . import (
        brain_pb2,
        brain_pb2_grpc,
        worker_pb2,
        worker_pb2_grpc,
    )

    # Commerce-specific proto (optional)
    try:
        from . import commerce_pb2, commerce_pb2_grpc
    except ImportError:
        commerce_pb2, commerce_pb2_grpc = None, None
except ImportError:
    # Handle cases where protos aren't generated yet or different import path
    context_unit_pb2 = None
    brain_pb2, brain_pb2_grpc = None, None
    worker_pb2, worker_pb2_grpc = None, None
    commerce_pb2, commerce_pb2_grpc = None, None

logger = logging.getLogger(__name__)


class BrainClient:
    """
    Client for interacting with ContextBrain (core knowledge operations).
    Supports 'local' (library) and 'grpc' (network) modes.

    For commerce-specific operations (products, enrichment), use CommerceClient.

    Note: TLS/mTLS support is provided by ContextShield (premium feature).
    """

    def __init__(self, host: str | None = None, mode: str | None = None):
        self.mode = mode or os.getenv("CONTEXT_BRAIN_MODE", "grpc")
        self.host = host or os.getenv("CONTEXT_BRAIN_URL", "localhost:50051")
        self._stub = None
        self._commerce_stub = None
        self._service = None
        self.channel = None

        if self.mode == "grpc":
            if not brain_pb2_grpc:
                raise ImportError("Brain gRPC protos not available")

            # Connection via ContextShield for TLS/mTLS (see contextshield package)
            self.channel = grpc.aio.insecure_channel(self.host)

            self._stub = brain_pb2_grpc.BrainServiceStub(self.channel)
            # Commerce stub (optional, same channel)
            if commerce_pb2_grpc:
                self._commerce_stub = commerce_pb2_grpc.CommerceServiceStub(
                    self.channel
                )
        else:
            try:
                from contextbrain import BrainService

                self._service = BrainService()
            except ImportError:
                logger.error(
                    "Brain local mode requested but contextbrain not installed"
                )
                raise

    async def search(
        self,
        tenant_id: str,
        query_text: str,
        limit: int = 5,
        source_types: List[str] | None = None,
    ) -> List[SearchResult]:
        """Search for similar content in Brain.

        Returns:
            List of SearchResult with content, score, and metadata.
            Score is the semantic similarity (0.0 to 1.0).
        """
        if self.mode == "grpc":
            request = brain_pb2.SearchRequest(
                tenant_id=tenant_id,
                query_text=query_text,
                limit=limit,
                source_types=source_types or [],
            )
            response = await self._stub.Search(request)
            results = []
            for r in response.results:
                results.append(SearchResult(
                    id=r.id,
                    content=r.content,
                    score=r.score,
                    source_type=r.source_type,
                    metadata=dict(r.metadata),
                ))
            return results
        else:
            # Local mode - use service directly
            from contextbrain import BrainService
            if not self._service:
                self._service = BrainService()
            # For local, we'd need to implement this in BrainService
            logger.warning("Local mode search not fully implemented yet")
            return []

    async def upsert(
        self,
        tenant_id: str,
        content: str,
        source_type: str,
        metadata: Dict[str, str] | None = None,
    ) -> str:
        """Upsert content to Brain. Returns the ID of the stored item."""
        if self.mode == "grpc":
            request = brain_pb2.UpsertRequest(
                tenant_id=tenant_id,
                content=content,
                source_type=source_type,
                metadata=metadata or {},
            )
            response = await self._stub.Upsert(request)
            return response.id
        else:
            logger.warning("Local mode upsert not implemented yet")
            return ""

    async def query_memory(self, unit: ContextUnit) -> List[ContextUnit]:
        """Query memory (deprecated, use search instead)."""
        tenant_id = unit.payload.get("tenant_id", "default") if unit.payload else "default"
        return await self.search(
            tenant_id=tenant_id,
            query_text=unit.payload.get("content", "") if unit.payload else "",
            limit=5,
        )

    async def upsert_taxonomy(self, unit: ContextUnit) -> ContextUnit:
        """Upsert to taxonomy (deprecated, use upsert instead)."""
        tenant_id = unit.payload.get("tenant_id", "default") if unit.payload else "default"
        await self.upsert(
            tenant_id=tenant_id,
            content=unit.payload.get("content", "") if unit.payload else "",
            source_type=unit.payload.get("source_type", "unknown") if unit.payload else "unknown",
            metadata={},
        )
        return unit

    # =========================================================================
    # Commerce / Gardener Methods
    # =========================================================================

    async def get_products(
        self,
        tenant_id: str,
        product_ids: List[int],
    ) -> List[dict]:
        """Get products for enrichment by IDs.

        Args:
            tenant_id: Tenant identifier for isolation.
            product_ids: List of product IDs to fetch.

        Returns:
            List of product dictionaries with id, name, category, etc.
        """
        if self.mode != "grpc":
            raise NotImplementedError("get_products only supports gRPC mode")
        if not self._commerce_stub:
            raise ImportError("Commerce gRPC protos not available")

        request = commerce_pb2.GetProductsRequest(
            tenant_id=tenant_id,
            product_ids=list(product_ids),
        )
        response = await self._commerce_stub.GetProducts(request)

        products = []
        for p in response.products:
            products.append(
                {
                    "id": p.id,
                    "name": p.name,
                    "category": p.category,
                    "description": p.description,
                    "brand_name": p.brand_name,
                    "params": dict(p.params) if p.params else {},
                    "enrichment": dict(p.enrichment) if p.enrichment else {},
                }
            )
        return products

    async def update_enrichment(
        self,
        tenant_id: str,
        product_id: int,
        enrichment: dict,
        trace_id: str,
        status: str = "enriched",
    ) -> bool:
        """Update product enrichment data.

        Args:
            tenant_id: Tenant identifier.
            product_id: Product ID.
            enrichment: Enrichment data dictionary.
            trace_id: Trace ID for auditing.
            status: Enrichment status (e.g., 'enriched', 'failed').

        Returns:
            True if successful.
        """
        if self.mode != "grpc":
            raise NotImplementedError("update_enrichment only supports gRPC mode")
        if not self._commerce_stub:
            raise ImportError("Commerce gRPC protos not available")

        from google.protobuf.struct_pb2 import Struct

        enrichment_struct = Struct()
        enrichment_struct.update(enrichment)

        request = commerce_pb2.UpdateEnrichmentRequest(
            tenant_id=tenant_id,
            product_id=product_id,
            enrichment=enrichment_struct,
            trace_id=trace_id,
            status=status,
        )
        response = await self._commerce_stub.UpdateEnrichment(request)
        return response.success

    async def create_kg_relation(
        self,
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
        if self.mode != "grpc":
            raise NotImplementedError("create_kg_relation only supports gRPC mode")

        request = brain_pb2.CreateKGRelationRequest(
            tenant_id=tenant_id,
            source_type=source_type,
            source_id=source_id,
            relation=relation,
            target_type=target_type,
            target_id=target_id,
        )
        response = await self._stub.CreateKGRelation(request)
        return response.success

    async def upsert_dealer_product(
        self,
        tenant_id: str,
        dealer_code: str,
        dealer_name: str,
        sku: str,
        name: str = "",
        category: str = "",
        brand_name: str = "",
        quantity: int = 0,
        price_retail: float | None = None,
        currency: str = "UAH",
        params: dict | None = None,
        status: str = "raw",
        trace_id: str | None = None,
    ) -> int:
        """Upsert dealer product via Brain gRPC.

        Args:
            tenant_id: Tenant identifier.
            dealer_code: Supplier/dealer code.
            dealer_name: Human-readable dealer name.
            sku: Product SKU (unique per dealer).
            name: Product name.
            category: Product category path.
            brand_name: Brand name.
            quantity: Available quantity.
            price_retail: Retail price.
            currency: Currency code (default UAH).
            params: Additional product attributes.
            status: Product status (raw, enriched, pending_human).
            trace_id: Trace ID for observability.

        Returns:
            Database-assigned product ID.
        """
        if self.mode != "grpc":
            raise NotImplementedError("upsert_dealer_product only supports gRPC mode")
        if not self._commerce_stub:
            raise ImportError("Commerce gRPC protos not available")

        from google.protobuf.struct_pb2 import Struct

        params_struct = Struct()
        if params:
            params_struct.update(params)

        request = commerce_pb2.UpsertDealerProductRequest(
            tenant_id=tenant_id,
            dealer_code=dealer_code,
            dealer_name=dealer_name,
            sku=sku,
            name=name,
            category=category,
            brand_name=brand_name,
            quantity=quantity,
            price_retail=price_retail or 0.0,
            currency=currency,
            params=params_struct,
            status=status,
            trace_id=trace_id or "",
        )
        response = await self._commerce_stub.UpsertDealerProduct(request)

        if not response.success:
            raise RuntimeError(f"UpsertDealerProduct failed: {response.message}")

        return response.product_id


class WorkerClient:
    """
    Client for interacting with ContextWorker.
    Supports 'grpc' (network) and 'local' (direct Temporal client) modes.
    """

    def __init__(self, host: str | None = None, mode: str | None = None):
        self.mode = mode or os.getenv("CONTEXT_WORKER_MODE", "grpc")
        self.host = host or os.getenv("CONTEXT_WORKER_URL", "localhost:50052")
        self.temporal_host = os.getenv("TEMPORAL_HOST", "localhost:7233")
        self._stub = None

        if self.mode == "grpc":
            if not worker_pb2_grpc:
                raise ImportError("Worker gRPC protos not available")
            self.channel = grpc.insecure_channel(self.host)
            self._stub = worker_pb2_grpc.WorkerServiceStub(self.channel)

    async def start_workflow(self, unit: ContextUnit) -> ContextUnit:
        unit_pb = unit.to_protobuf(context_unit_pb2)

        if self.mode == "grpc":
            res_pb = self._stub.StartWorkflow(unit_pb)
            return ContextUnit.from_protobuf(res_pb)
        else:
            from temporalio.client import Client
            from contextworker.workflows import HarvesterImportWorkflow

            client = await Client.connect(self.temporal_host)
            url = unit.payload.get("url")
            handle = await client.start_workflow(
                HarvesterImportWorkflow.run,
                url,
                id=f"harvest-{unit.unit_id}",
                task_queue="harvester-tasks",
            )
            unit.payload["workflow_id"] = handle.id
            return unit
