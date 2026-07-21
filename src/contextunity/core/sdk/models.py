"""Core data models for ContextUnit SDK.

These are Pydantic models used for SDK operations.
"""

from __future__ import annotations

from datetime import UTC, datetime

from contextunity.core.types import JsonDict
from pydantic import BaseModel, Field


class CotStep(BaseModel):
    """Chain of Thought step for agent reasoning."""

    agent: str
    action: str
    status: str = "pending"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class CellSearchResult(BaseModel):
    """Canonical ranked BrainCell semantic/hybrid search result."""

    id: str
    tenant_id: str
    cell_kind: str
    content: str
    score: float = Field(ge=0.0)
    vector_score: float | None = None
    text_score: float | None = None
    source_type: str
    source_ref: str | None = None
    scope_path: str | None = None
    content_hash: str | None = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    visibility: str = "tenant"
    metadata: JsonDict = Field(default_factory=dict)


class UnitMetrics(BaseModel):
    """Metrics for tracking unit processing costs and performance."""

    latency_ms: int = 0
    cost_usd: float = 0.0
    tokens_used: int = 0
    cost_limit_usd: float = 0.0

    # Observability — set by Router / client for deeper traceability
    network_ms: int = 0  # gRPC round-trip latency (measured by caller)
    wall_ms: int = 0  # Router-side wall-clock execution time


class SecurityScopes(BaseModel):
    """Capability-based access control scopes."""

    read: list[str] = Field(default_factory=list)
    write: list[str] = Field(default_factory=list)


__all__ = [
    "CellSearchResult",
    "CotStep",
    "UnitMetrics",
    "SecurityScopes",
]
