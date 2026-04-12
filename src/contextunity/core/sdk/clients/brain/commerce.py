"""Commerce methods - products, enrichment, dealer products.

Supports both gRPC and local modes for development flexibility.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ...contextunit import ContextUnit
from .base import BrainClientBase, get_contextunit_pb2, logger

if TYPE_CHECKING:
    from typing import List


class CommerceMixin:
    """Mixin with Commerce/Gardener operations.

    All methods support:
    - gRPC mode: Network calls to Brain CommerceService
    - local mode: Direct library calls (for development)
    """

    async def get_products(
        self: BrainClientBase,
        tenant_id: str,
        product_ids: "List[int]",
        trace_id: "str | None" = None,
        parent_provenance: "List[str] | None" = None,
    ) -> "List[dict]":
        """Get products for enrichment by IDs.

        Args:
            tenant_id: Tenant identifier.
            product_ids: List of product IDs to fetch.
            trace_id: Optional trace ID for distributed tracing.
            parent_provenance: Optional provenance chain from parent.

        Returns:
            List of product dictionaries.
        """
        if self.mode == "grpc":
            if not self._commerce_stub:
                raise ImportError("Commerce gRPC protos not available")

            from uuid import UUID

            provenance = list(parent_provenance) if parent_provenance else []
            provenance.append("sdk:brain_client:get_products")

            unit = ContextUnit(
                payload={
                    "tenant_id": tenant_id,
                    "product_ids": list(product_ids),
                },
                trace_id=UUID(trace_id) if trace_id else None,
                provenance=provenance,
            )

            pb2 = get_contextunit_pb2()
            req = unit.to_protobuf(pb2)
            metadata = self._get_metadata()  # Include token in metadata
            products = []
            async for response_pb in self._commerce_stub.GetProducts(req, metadata=metadata):
                result = ContextUnit.from_protobuf(response_pb)
                products.append(result.payload)
            return products
        else:
            # Local mode
            return await self._local_get_products(tenant_id, product_ids)

    async def _local_get_products(
        self: BrainClientBase,
        tenant_id: str,
        product_ids: "List[int]",
    ) -> "List[dict]":
        """Local mode implementation."""
        try:
            if hasattr(self._service, "storage"):
                if hasattr(self._service.storage, "get_products_by_ids"):
                    return await self._service.storage.get_products_by_ids(
                        tenant_id=tenant_id,
                        product_ids=product_ids,
                    )
        except Exception as e:
            logger.warning("Local get_products failed: %s", e)
        return []

    async def update_enrichment(
        self: BrainClientBase,
        tenant_id: str,
        product_id: int,
        enrichment: dict[str, Any],
        trace_id: str,
        status: str = "enriched",
        parent_provenance: "List[str] | None" = None,
    ) -> bool:
        """Update product enrichment data.

        Args:
            tenant_id: Tenant identifier.
            product_id: Product ID.
            enrichment: Enrichment data dictionary.
            trace_id: Trace ID for auditing.
            status: Enrichment status.
            parent_provenance: Optional provenance chain from parent.

        Returns:
            True if successful.
        """
        if self.mode == "grpc":
            if not self._commerce_stub:
                raise ImportError("Commerce gRPC protos not available")

            from uuid import UUID

            provenance = list(parent_provenance) if parent_provenance else []
            provenance.append("sdk:brain_client:update_enrichment")

            unit = ContextUnit(
                payload={
                    "tenant_id": tenant_id,
                    "product_id": product_id,
                    "enrichment": enrichment,
                    "trace_id": trace_id,  # Also in payload for audit
                    "status": status,
                },
                trace_id=UUID(trace_id) if trace_id else None,
                provenance=provenance,
            )

            pb2 = get_contextunit_pb2()
            req = unit.to_protobuf(pb2)
            metadata = self._get_metadata()  # Include token in metadata
            response_pb = await self._commerce_stub.UpdateEnrichment(req, metadata=metadata)
            result = ContextUnit.from_protobuf(response_pb)
            return result.payload.get("success", False)
        else:
            # Local mode
            return await self._local_update_enrichment(tenant_id, product_id, enrichment, trace_id, status)

    async def _local_update_enrichment(
        self: BrainClientBase,
        tenant_id: str,
        product_id: int,
        enrichment: dict[str, Any],
        trace_id: str,
        status: str,
    ) -> bool:
        """Local mode implementation."""
        try:
            if hasattr(self._service, "storage"):
                if hasattr(self._service.storage, "update_product_enrichment"):
                    await self._service.storage.update_product_enrichment(
                        tenant_id=tenant_id,
                        product_id=product_id,
                        enrichment=enrichment,
                        trace_id=trace_id,
                        status=status,
                    )
                    return True
        except Exception as e:
            logger.warning("Local update_enrichment failed: %s", e)
        return False

    async def upsert_dealer_product(
        self: BrainClientBase,
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
        """Upsert dealer product via Brain.

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
            currency: Currency code.
            params: Additional product attributes.
            status: Product status.
            trace_id: Trace ID for observability.

        Returns:
            Database-assigned product ID.
        """
        if self.mode == "grpc":
            if not self._commerce_stub:
                raise ImportError("Commerce gRPC protos not available")

            unit = ContextUnit(
                payload={
                    "tenant_id": tenant_id,
                    "dealer_code": dealer_code,
                    "dealer_name": dealer_name,
                    "sku": sku,
                    "name": name,
                    "category": category,
                    "brand_name": brand_name,
                    "quantity": quantity,
                    "price_retail": price_retail or 0.0,
                    "currency": currency,
                    "params": params or {},
                    "status": status,
                    "trace_id": trace_id or "",
                },
                provenance=["sdk:brain_client:upsert_dealer_product"],
            )

            pb2 = get_contextunit_pb2()
            req = unit.to_protobuf(pb2)
            metadata = self._get_metadata()  # Include token in metadata
            response_pb = await self._commerce_stub.UpsertDealerProduct(req, metadata=metadata)
            result = ContextUnit.from_protobuf(response_pb)

            if not result.payload.get("success"):
                raise RuntimeError(f"UpsertDealerProduct failed: {result.payload.get('message')}")

            return result.payload.get("product_id", 0)
        else:
            # Local mode
            return await self._local_upsert_dealer_product(
                tenant_id=tenant_id,
                dealer_code=dealer_code,
                dealer_name=dealer_name,
                sku=sku,
                name=name,
                category=category,
                brand_name=brand_name,
                quantity=quantity,
                price_retail=price_retail,
                currency=currency,
                params=params,
                status=status,
            )

    async def _local_upsert_dealer_product(
        self: BrainClientBase,
        tenant_id: str,
        dealer_code: str,
        dealer_name: str,
        sku: str,
        name: str,
        category: str,
        brand_name: str,
        quantity: int,
        price_retail: float | None,
        currency: str,
        params: dict | None,
        status: str,
    ) -> int:
        """Local mode implementation."""
        try:
            if hasattr(self._service, "storage"):
                if hasattr(self._service.storage, "upsert_dealer_product"):
                    return await self._service.storage.upsert_dealer_product(
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
                        params=params or {},
                        status=status,
                    )
        except Exception as e:
            logger.warning("Local upsert_dealer_product failed: %s", e)
        # Return hash-based ID as fallback
        return hash(f"{dealer_code}:{sku}") % (2**31)

    async def match_duckdb(
        self: BrainClientBase,
        tenant_id: str,
        unmatched_url: str,
        canonical_url: str,
        leftovers_put_url: str,
        trace_id: str | None = None,
        parent_provenance: "List[str] | None" = None,
    ) -> dict[str, Any]:
        """Execute DuckDB fast matching over Parquet catalogs.

        Args:
            tenant_id: Tenant identifier.
            unmatched_url: Presigned URI or path to unmatched products parquet.
            canonical_url: Presigned URI or path to canonical products parquet.
            leftovers_put_url: Presigned URI for DuckDB to PUT unmatched leftovers to storage.
            trace_id: Optional trace ID.
            parent_provenance: Optional provenance chain.

        Returns:
            Dictionary containing 'duckdb_matches' and 'duckdb_leftovers' lists.
        """
        if self.mode == "grpc":
            if not self._stub:
                raise ImportError("Brain gRPC protos not available")

            from uuid import UUID

            provenance = list(parent_provenance) if parent_provenance else []
            provenance.append("sdk:brain_client:match_duckdb")

            kwargs = {}
            if trace_id:
                kwargs["trace_id"] = UUID(trace_id)

            unit = ContextUnit(
                payload={
                    "tenant_id": tenant_id,
                    "unmatched_url": unmatched_url,
                    "canonical_url": canonical_url,
                    "leftovers_put_url": leftovers_put_url,
                },
                provenance=provenance,
                **kwargs,
            )

            pb2 = get_contextunit_pb2()
            req = unit.to_protobuf(pb2)
            metadata = self._get_metadata()
            response_pb = await self._stub.MatchDuckDB(req, metadata=metadata)
            result = ContextUnit.from_protobuf(response_pb)
            return result.payload
        else:
            return await self._local_match_duckdb(tenant_id, unmatched_url, canonical_url, leftovers_put_url)

    async def _local_match_duckdb(
        self: BrainClientBase,
        tenant_id: str,
        unmatched_url: str,
        canonical_url: str,
        leftovers_put_url: str,
    ) -> dict[str, Any]:
        """Local mode implementation."""
        try:
            if hasattr(self._service, "duckdb"):
                if hasattr(self._service.duckdb, "match_catalogs"):
                    return await self._service.duckdb.match_catalogs(
                        tenant_id=tenant_id,
                        unmatched_url=unmatched_url,
                        canonical_url=canonical_url,
                        leftovers_put_url=leftovers_put_url,
                    )
        except Exception as e:
            logger.warning("Local match_duckdb failed: %s", e)
        return {"duckdb_matches": [], "duckdb_leftovers": []}


__all__ = ["CommerceMixin"]
