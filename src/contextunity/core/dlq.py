"""Minimal dead-letter queue primitives for replayable diagnostic events."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Protocol

from .logging import get_contextunit_logger
from .parsing import json_dumps, json_loads
from .types import JsonDict, is_json_dict

logger = get_contextunit_logger(__name__)


class DlqWriter(Protocol):
    """Minimal DLQ-0 interface: append an event, replay everything written."""

    async def write(self, event: JsonDict) -> None: ...

    def replay(self) -> AsyncIterator[JsonDict]: ...


class LocalFileDlqWriter:
    """Append-only JSONL DLQ writer; replay reads one event per line in order.

    Not durable/concurrent-writer-safe beyond what local append-mode file
    writes give you on POSIX (atomic for writes under ``PIPE_BUF``, which one
    JSON event line always is in practice).
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = asyncio.Lock()

    async def write(self, event: JsonDict) -> None:
        line = json_dumps(event) + "\n"
        async with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as f:
                f.write(line)
        logger.warning("DLQ-0 event written: event_type=%s path=%s", event.get("event_type"), self._path)

    async def replay(self) -> AsyncIterator[JsonDict]:
        if not self._path.exists():
            return
        async with self._lock:
            text = self._path.read_text(encoding="utf-8")
        for line in text.splitlines():
            if not line.strip():
                continue
            parsed = json_loads(line)
            if is_json_dict(parsed):
                yield parsed

    async def clear(self) -> None:
        """Remove all replayed/acknowledged events — call after a successful replay."""
        async with self._lock:
            if self._path.exists():
                self._path.unlink()


__all__ = ["DlqWriter", "LocalFileDlqWriter"]
