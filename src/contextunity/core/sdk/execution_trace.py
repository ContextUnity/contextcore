"""Canonical terminal Execution Trace wire finalization.

Callers own their typed domain projection. This module owns the one semantic
digest algorithm shared by Router and non-Router trace producers before Brain
validates and persists an immutable terminal trace.
"""

from __future__ import annotations

from hashlib import sha256
from json import dumps as canonical_dumps
from json import loads as canonical_loads

from contextunity.core.sdk.types import TerminalTraceContentWire, TerminalTraceWire
from contextunity.core.types import JsonDict, is_json_dict, is_object_dict, is_object_list


def _semantic_digest_content(content: TerminalTraceContentWire) -> JsonDict:
    """Normalize decimal uint64 wire strings to Brain's admitted integer shape."""
    parsed: object = canonical_loads(canonical_dumps(content))
    if not is_json_dict(parsed):
        raise ValueError("terminal trace digest content is invalid")
    steps = parsed.get("steps")
    if not is_object_list(steps):
        raise ValueError("terminal trace digest steps are invalid")
    for step in steps:
        if not is_object_dict(step):
            raise ValueError("terminal trace digest step is invalid")
        usage = step.get("usage")
        if not is_object_dict(usage):
            raise ValueError("terminal trace digest usage is invalid")
        details = usage.get("provider_details")
        if details is None:
            continue
        if not is_object_dict(details):
            raise ValueError("terminal trace provider details are invalid")
        values = details.get("values")
        if not is_object_dict(values):
            raise ValueError("terminal trace provider values are invalid")
        normalized: dict[str, int] = {}
        for key, value in values.items():
            if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
                raise ValueError("terminal trace provider counter wire is invalid")
            normalized[key] = int(value)
        details["values"] = normalized
    return parsed


def terminal_trace_with_digest(content: TerminalTraceContentWire) -> TerminalTraceWire:
    """Attach the canonical semantic SHA-256 digest to closed trace content."""
    digest = sha256(
        canonical_dumps(
            _semantic_digest_content(content),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {**content, "digest": digest}


__all__ = ["terminal_trace_with_digest"]
