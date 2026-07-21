"""Strict Conversation History domain contracts shared by Brain callers."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from typing import Literal, TypedDict
from uuid import UUID

from contextunity.core.parsing import json_dumps
from contextunity.core.types import JsonDict
from pydantic import BaseModel, ConfigDict, Field

type ConversationProjection = Literal["recent", "older_than", "session", "trace_related"]
type ConversationRole = Literal["user", "assistant", "system", "tool", "legacy"]
type ConversationKind = Literal["message", "turn_summary", "conversation_note", "legacy_import"]


def conversation_content_hash(content: str) -> str:
    """Return the canonical UTF-8 content digest."""
    return "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest()


def conversation_source_hash(source_identity: str) -> str:
    """Return the canonical digest of an immutable producer source identity."""
    return "sha256:" + hashlib.sha256(source_identity.encode("utf-8")).hexdigest()


def conversation_record_id(*, tenant_id: str, idempotency_key: str) -> UUID:
    """Derive a stable UUIDv5 record identity from tenant-scoped idempotency."""
    return uuid.uuid5(uuid.NAMESPACE_URL, f"contextunity:conversation:{tenant_id}:{idempotency_key}")


def conversation_retention_evidence_hash(*, tenant_id: str, cutoff: datetime, record_ids: list[UUID]) -> str:
    """Hash the exact retention selection so stale/mismatched requests fail closed."""
    body = json_dumps(
        {
            "tenant_id": tenant_id,
            "cutoff": cutoff.isoformat(),
            "record_ids": sorted(str(record_id) for record_id in record_ids),
        },
        sort_keys=True,
    )
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


class ConversationRecord(BaseModel):
    """One immutable Brain-owned Conversation History record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    record_id: UUID
    tenant_id: str = Field(min_length=1, max_length=128)
    user_id: str = Field(min_length=1, max_length=256)
    session_id: str | None = Field(default=None, max_length=256)
    role: ConversationRole
    kind: ConversationKind
    content: str = Field(min_length=1, max_length=65536)
    content_hash: str = Field(pattern=r"sha256:[0-9a-f]{64}")
    source_hash: str = Field(pattern=r"sha256:[0-9a-f]{64}")
    graph_run_id: UUID | None = None
    created_at: datetime
    metadata_version: Literal[1]
    idempotency_key: str = Field(min_length=1, max_length=256)
    metadata: JsonDict = Field(default_factory=dict)


def conversation_record_matches_append(
    existing: ConversationRecord,
    *,
    record_id: UUID,
    tenant_id: str,
    user_id: str,
    session_id: str | None,
    role: ConversationRole,
    kind: ConversationKind,
    content: str,
    content_hash: str,
    source_hash: str,
    graph_run_id: UUID | None,
    metadata_version: int,
    idempotency_key: str,
    metadata: JsonDict,
    created_at: datetime | None,
) -> bool:
    """Return whether a retry exactly matches the durable immutable record.

    ``created_at`` is compared only when the caller supplied it. When omitted,
    the owner generates the timestamp and a retry cannot reproduce that value.
    """
    return (
        existing.record_id == record_id
        and existing.tenant_id == tenant_id
        and existing.user_id == user_id
        and existing.session_id == session_id
        and existing.role == role
        and existing.kind == kind
        and existing.content == content
        and existing.content_hash == content_hash
        and existing.source_hash == source_hash
        and existing.graph_run_id == graph_run_id
        and existing.metadata_version == metadata_version
        and existing.idempotency_key == idempotency_key
        and existing.metadata == metadata
        and (created_at is None or existing.created_at == created_at)
    )


class ConversationRecordRef(BaseModel):
    """Immutable content-free provenance reference to one owner record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    record_id: UUID
    tenant_id: str = Field(min_length=1, max_length=128)
    source_hash: str = Field(pattern=r"sha256:[0-9a-f]{64}")
    graph_run_id: UUID | None = None
    idempotency_key: str = Field(min_length=1, max_length=256)


class ConversationRecordWire(TypedDict):
    """JSON-safe L3 projection of ``ConversationRecord``."""

    record_id: str
    tenant_id: str
    user_id: str
    session_id: str | None
    role: ConversationRole
    kind: ConversationKind
    content: str
    content_hash: str
    source_hash: str
    graph_run_id: str | None
    created_at: str
    metadata_version: int
    idempotency_key: str
    metadata: JsonDict


class ConversationRecordRefWire(TypedDict):
    """JSON-safe projection of ``ConversationRecordRef``."""

    record_id: str
    tenant_id: str
    source_hash: str
    graph_run_id: str | None
    idempotency_key: str


def conversation_record_to_wire(record: ConversationRecord) -> ConversationRecordWire:
    """Project a strict domain record into a JSON-safe wire mapping."""
    return {
        "record_id": str(record.record_id),
        "tenant_id": record.tenant_id,
        "user_id": record.user_id,
        "session_id": record.session_id,
        "role": record.role,
        "kind": record.kind,
        "content": record.content,
        "content_hash": record.content_hash,
        "source_hash": record.source_hash,
        "graph_run_id": str(record.graph_run_id) if record.graph_run_id else None,
        "created_at": record.created_at.isoformat(),
        "metadata_version": record.metadata_version,
        "idempotency_key": record.idempotency_key,
        "metadata": record.metadata,
    }


def conversation_record_ref_to_wire(ref: ConversationRecordRef) -> ConversationRecordRefWire:
    """Project a content-free provenance reference into a JSON-safe mapping."""
    return {
        "record_id": str(ref.record_id),
        "tenant_id": ref.tenant_id,
        "source_hash": ref.source_hash,
        "graph_run_id": str(ref.graph_run_id) if ref.graph_run_id else None,
        "idempotency_key": ref.idempotency_key,
    }


class ConversationAppendReceipt(BaseModel):
    """Durable append result returned for created and duplicate requests."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    record_id: UUID
    outcome: Literal["created", "duplicate"]
    content_hash: str = Field(pattern=r"sha256:[0-9a-f]{64}")
    source_hash: str = Field(pattern=r"sha256:[0-9a-f]{64}")


class ConversationHistoryStats(BaseModel):
    """Content-free tenant statistics projection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(min_length=1, max_length=128)
    total: int = Field(ge=0)
    oldest: datetime | None = None
    newest: datetime | None = None


class ConversationRetentionReceipt(BaseModel):
    """Owner-issued receipt for an evidence-backed retention operation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(min_length=1, max_length=128)
    deleted_count: int = Field(ge=0)
    policy_version: Literal["contextunity.conversation-retention/v1"]
    hold_evidence_hash: str = Field(pattern=r"sha256:[0-9a-f]{64}")


__all__ = [
    "ConversationAppendReceipt",
    "ConversationHistoryStats",
    "ConversationRecord",
    "ConversationRecordRef",
    "ConversationRecordRefWire",
    "ConversationRecordWire",
    "ConversationRetentionReceipt",
    "ConversationProjection",
    "ConversationRole",
    "ConversationKind",
    "conversation_content_hash",
    "conversation_record_matches_append",
    "conversation_record_id",
    "conversation_record_ref_to_wire",
    "conversation_record_to_wire",
    "conversation_retention_evidence_hash",
    "conversation_source_hash",
]
