"""Strict Conversation History domain-contract tests."""

from __future__ import annotations

from uuid import uuid4

import pytest
from contextunity.core.sdk.conversation import (
    ConversationRecordRef,
    conversation_record_ref_to_wire,
    conversation_source_hash,
)
from pydantic import ValidationError


def test_conversation_record_ref_is_content_free_and_closed() -> None:
    ref = ConversationRecordRef(
        record_id=uuid4(),
        tenant_id="tenant-a",
        source_hash=conversation_source_hash("router:source"),
        graph_run_id=uuid4(),
        idempotency_key="router:key",
    )

    wire = conversation_record_ref_to_wire(ref)

    assert set(wire) == {
        "record_id",
        "tenant_id",
        "source_hash",
        "graph_run_id",
        "idempotency_key",
    }
    assert "content" not in wire


def test_conversation_record_ref_rejects_unknown_or_malformed_evidence() -> None:
    with pytest.raises(ValidationError):
        ConversationRecordRef.model_validate(
            {
                "record_id": str(uuid4()),
                "tenant_id": "tenant-a",
                "source_hash": "not-a-digest",
                "graph_run_id": None,
                "idempotency_key": "router:key",
                "content": "must never be copied into a ref",
            }
        )
