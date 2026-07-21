"""Closed operator-safe projection for terminal Execution Trace inspection."""

from __future__ import annotations

from datetime import datetime
from typing import Literal, cast
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

type TraceTerminalStatus = Literal["succeeded", "failed", "cancelled"]

_TRACE_TERMINAL_STATUSES = frozenset({"succeeded", "failed", "cancelled"})


def validate_trace_terminal_status(value: str) -> TraceTerminalStatus:
    """Validate one canonical terminal Trace status at a public boundary."""
    if value not in _TRACE_TERMINAL_STATUSES:
        raise ValueError("terminal Trace status must be succeeded, failed, or cancelled")
    return cast("TraceTerminalStatus", value)


class TraceInspection(BaseModel):
    """Allowlisted Trace fields safe for platform operator rendering.

    Legacy admin payload fields are ignored intentionally so metadata, prompts,
    tool arguments, steps, user identifiers, and security evidence never become
    output merely because the storage/admin response grows.
    """

    model_config = ConfigDict(extra="ignore", frozen=True)

    id: UUID
    tenant_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    graph_name: str | None = None
    graph_run_id: UUID | None = None
    timing_ms: int | None = Field(default=None, ge=0)
    terminal_status: TraceTerminalStatus | None = None
    created_at: datetime | None = None

    @field_validator("graph_run_id", "terminal_status", mode="before")
    @classmethod
    def _legacy_empty_optional_is_none(cls, value: object) -> object:
        return None if value == "" else value


class TraceInspectionPage(BaseModel):
    """Bounded closed page of operator-safe Trace summaries."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    traces: tuple[TraceInspection, ...]
    total: int = Field(ge=0)


__all__ = [
    "TraceInspection",
    "TraceInspectionPage",
    "TraceTerminalStatus",
    "validate_trace_terminal_status",
]
