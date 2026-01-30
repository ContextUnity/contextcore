"""Core data models for ContextUnit SDK.

These are Pydantic models used for SDK operations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class CotStep(BaseModel):
    """Chain of Thought step for agent reasoning."""

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
    metadata: dict[str, Any] = Field(default_factory=dict)


class UnitMetrics(BaseModel):
    """Metrics for tracking unit processing costs and performance."""

    latency_ms: int = 0
    cost_usd: float = 0.0
    tokens_used: int = 0
    cost_limit_usd: float = 0.0


class SecurityScopes(BaseModel):
    """Capability-based access control scopes."""

    read: list[str] = Field(default_factory=list)
    write: list[str] = Field(default_factory=list)


__all__ = [
    "CotStep",
    "SearchResult",
    "UnitMetrics",
    "SecurityScopes",
]
