"""Tests for DLQ-0: DebugBus-unavailable events must be replayable, not
silently discarded."""

from __future__ import annotations

from pathlib import Path

import pytest
from contextunity.core.dlq import LocalFileDlqWriter
from contextunity.core.passbyref import ReferenceMissingError, to_debugbus_event


@pytest.mark.asyncio
async def test_write_then_replay_returns_the_same_event(tmp_path: Path):
    writer = LocalFileDlqWriter(tmp_path / "dlq0.jsonl")
    event = {"event_type": "reference.missing", "tenant_id": "contextmed"}

    await writer.write(event)
    replayed = [e async for e in writer.replay()]

    assert replayed == [event]


@pytest.mark.asyncio
async def test_replay_preserves_write_order(tmp_path: Path):
    writer = LocalFileDlqWriter(tmp_path / "dlq0.jsonl")
    for i in range(5):
        await writer.write({"seq": i})

    replayed = [e async for e in writer.replay()]

    assert [e["seq"] for e in replayed] == [0, 1, 2, 3, 4]


@pytest.mark.asyncio
async def test_replay_on_missing_file_yields_nothing(tmp_path: Path):
    writer = LocalFileDlqWriter(tmp_path / "never-written.jsonl")

    replayed = [e async for e in writer.replay()]

    assert replayed == []


@pytest.mark.asyncio
async def test_clear_removes_events(tmp_path: Path):
    writer = LocalFileDlqWriter(tmp_path / "dlq0.jsonl")
    await writer.write({"seq": 0})

    await writer.clear()
    replayed = [e async for e in writer.replay()]

    assert replayed == []


@pytest.mark.asyncio
async def test_passbyref_error_is_replayable_end_to_end(tmp_path: Path):
    """A DebugBus-unavailable failure must produce a replayable DLQ-0
    record — using a real PassByRefError, not a hand-built dict, to prove
    the two modules compose."""
    writer = LocalFileDlqWriter(tmp_path / "dlq0.jsonl")
    error = ReferenceMissingError("ref not found", ref_kind="blackboard", memory_ref="abc-123", tenant_id="contextmed")

    await writer.write(to_debugbus_event(error, service="ContextRouter", graph_run_id="run-1"))
    replayed = [e async for e in writer.replay()]

    assert len(replayed) == 1
    assert replayed[0]["event_type"] == "reference.missing"
    assert replayed[0]["memory_ref"] == "abc-123"
    assert replayed[0]["graph_run_id"] == "run-1"
