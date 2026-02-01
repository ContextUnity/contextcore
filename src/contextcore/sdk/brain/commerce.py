"""Commerce methods - products, enrichment, dealer products.

Supports both gRPC and local modes for development flexibility.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..context_unit import ContextUnit
from .base import BrainClientBase, get_context_unit_pb2, logger

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
    ) -> "List[dict]":
        """Get products for enrichment by IDs.

        Args:
            tenant_id: Tenant identifier.
            product_ids: List of product IDs to fetch.

        Returns:
            List of product dictionaries.
        """
        if self.mode == "grpc":
            if not self._commerce_stub:
                raise ImportError("Commerce gRPC protos not available")

            unit = ContextUnit(
                payload={
                    "tenant_id": tenant_id,
                    "product_ids": list(product_ids),
                },
                provenance=["sdk:brain_client:get_products"],
            )

            pb2 = get_context_unit_pb2()
            req = unit.to_protobuf(pb2)
            products = []
            async for response_pb in self._commerce_stub.GetProducts(req):
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
            logger.warning(f"Local get_products failed: {e}")
        return []

    async def update_enrichment(
        self: BrainClientBase,
        tenant_id: str,
        product_id: int,
        enrichment: dict[str, Any],
        trace_id: str,
        status: str = "enriched",
    ) -> bool:
        """Update product enrichment data.

        Args:
            tenant_id: Tenant identifier.
            product_id: Product ID.
            enrichment: Enrichment data dictionary.
            trace_id: Trace ID for auditing.
            status: Enrichment status.

        Returns:
            True if successful.
        """
        if self.mode == "grpc":
            if not self._commerce_stub:
                raise ImportError("Commerce gRPC protos not available")

            unit = ContextUnit(
                payload={
                    "tenant_id": tenant_id,
                    "product_id": product_id,
                    "enrichment": enrichment,
                    "trace_id": trace_id,
                    "status": status,
                },
                provenance=["sdk:brain_client:update_enrichment"],
            )

            pb2 = get_context_unit_pb2()
            req = unit.to_protobuf(pb2)
            response_pb = await self._commerce_stub.UpdateEnrichment(req)
            result = ContextUnit.from_protobuf(response_pb)
            return result.payload.get("success", False)
        else:
            # Local mode
            return await self._local_update_enrichment(
                tenant_id, product_id, enrichment, trace_id, status
            )

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
            logger.warning(f"Local update_enrichment failed: {e}")
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
                provenance=["sdk:brain_client:upsert_dealer"],
            )

            pb2 = get_context_unit_pb2()
            req = unit.to_protobuf(pb2)
            response_pb = await self._commerce_stub.UpsertDealerProduct(req)
            result = ContextUnit.from_protobuf(response_pb)

            if not result.payload.get("success"):
                raise RuntimeError(
                    f"UpsertDealerProduct failed: {result.payload.get('message')}"
                )

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
            logger.warning(f"Local upsert_dealer_product failed: {e}")
        # Return hash-based ID as fallback
        return hash(f"{dealer_code}:{sku}") % (2**31)


__all__ = ["CommerceMixin"]
