"""Brain SDK operations for durable cell embedding enrichment."""

from __future__ import annotations

from typing import TYPE_CHECKING

from contextunity.core.sdk.payload import copy_wire_payload, get_dict_list
from contextunity.core.sdk.types import ContextUnitPayload

if TYPE_CHECKING:
    from .base import BrainClientBase as _MixinBase
else:
    _MixinBase = object


class EmbeddingMixin(_MixinBase):
    """Typed SDK boundary for enqueue, lease, execution, and status."""

    async def enqueue_cell_embedding(self, *, tenant_id: str, cell_id: str, content_hash: str) -> ContextUnitPayload:
        """Durably enqueue one current cell hash."""
        payload: ContextUnitPayload = {
            "tenant_id": tenant_id,
            "cell_id": cell_id,
            "content_hash": content_hash,
        }
        result = await self._call_unary(
            self._stub.EnqueueCellEmbedding,
            payload,
            rpc_name="EnqueueCellEmbedding",
        )
        return copy_wire_payload(result)

    async def get_embedding_capability(self, *, tenant_id: str) -> ContextUnitPayload:
        """Read embedding gate and vector-backend readiness without provider I/O."""
        result = await self._call_unary(
            self._stub.GetEmbeddingCapability,
            {"tenant_id": tenant_id},
            rpc_name="GetEmbeddingCapability",
        )
        return copy_wire_payload(result)

    async def claim_cell_embedding_jobs(self, *, tenant_id: str, limit: int = 10) -> list[ContextUnitPayload]:
        """Claim a bounded set of reference-only jobs."""
        result = await self._call_unary(
            self._stub.ClaimCellEmbeddingJobs,
            {"tenant_id": tenant_id, "limit": limit},
            rpc_name="ClaimCellEmbeddingJobs",
        )
        return get_dict_list(result, "jobs")

    async def embed_claimed_cell(self, *, tenant_id: str, job_id: str, lease_id: str) -> ContextUnitPayload:
        """Ask Brain to generate and persist one leased vector."""
        result = await self._call_unary(
            self._stub.EmbedClaimedCell,
            {"tenant_id": tenant_id, "job_id": job_id, "lease_id": lease_id},
            rpc_name="EmbedClaimedCell",
        )
        return copy_wire_payload(result)

    async def fail_cell_embedding_job(
        self, *, tenant_id: str, job_id: str, lease_id: str, error_code: str
    ) -> ContextUnitPayload:
        """Record one terminal embedding failure."""
        result = await self._call_unary(
            self._stub.FailCellEmbeddingJob,
            {
                "tenant_id": tenant_id,
                "job_id": job_id,
                "lease_id": lease_id,
                "error_code": error_code,
            },
            rpc_name="FailCellEmbeddingJob",
        )
        return copy_wire_payload(result)

    async def get_cell_embedding_status(
        self,
        *,
        tenant_id: str,
        cell_id: str,
        content_hash: str | None = None,
    ) -> ContextUnitPayload:
        """Read job status and vector presence without returning content."""
        payload: ContextUnitPayload = {
            "tenant_id": tenant_id,
            "cell_id": cell_id,
        }
        if content_hash is not None:
            payload["content_hash"] = content_hash
        result = await self._call_unary(
            self._stub.GetCellEmbeddingStatus,
            payload,
            rpc_name="GetCellEmbeddingStatus",
        )
        return copy_wire_payload(result)


__all__ = ["EmbeddingMixin"]
