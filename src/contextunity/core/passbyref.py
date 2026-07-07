"""PassByRef reference envelope helpers for large ContextUnit payloads.

ContextUnit payloads over a size threshold are written to Blackboard and
replaced with a small reference envelope instead of being duplicated at every
graph hop:

    {
        "memory_ref": "<blackboard uuid>",
        "ref_kind": "blackboard",
        "content_hash": "sha256:<hex>",
        "expires_at": "<ISO timestamp>" | None,
    }

``origin_tenant_id`` is carried alongside the four documented fields (not
part of the spec's shown JSON shape, but not excluded by it either) so
``resolve_pass_by_ref`` can reject a cross-tenant resolve attempt locally,
before ever touching Brain — RLS already blocks the read itself, but a local
check gives a distinct, fast, non-Brain-round-trip typed error instead of a
generic "missing" result indistinguishable from "never existed".

Resolution errors are typed and can be converted into a stable event payload
with ``to_debugbus_event`` for whichever diagnostic sink is active.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Protocol, TypedDict

from .exceptions import ContextUnityError
from .faults import REFERENCE_FAULT
from .parsing import json_dumps
from .sdk.contextunit import ContextUnit
from .types import ContextUnitPayload, JsonDict, is_json_dict, is_object_dict, is_object_list

DEFAULT_PASSBYREF_THRESHOLD_BYTES = 1024


class BlackboardRefClient(Protocol):
    """Structural subset of ``BrainClient`` PassByRef actually needs."""

    async def write_blackboard(
        self,
        *,
        tenant_id: str,
        scope_path: str,
        content: ContextUnitPayload,
        metadata: JsonDict | None = None,
        ttl_seconds: int | None = None,
        created_by: str | None = None,
    ) -> ContextUnitPayload: ...

    async def read_blackboard(self, *, ids: list[str], tenant_id: str) -> ContextUnitPayload: ...


class PassByRefEnvelope(TypedDict):
    memory_ref: str
    ref_kind: str
    content_hash: str
    expires_at: str | None
    origin_tenant_id: str


class PassByRefError(ContextUnityError):
    """Base class for typed PassByRef resolution failures."""

    code: str = "REFERENCE_ERROR"
    fault_class: str = REFERENCE_FAULT
    event_type: str = "reference.error"
    severity: str = "warning"
    retryable: bool = False


class ReferenceMissingError(PassByRefError):
    code: str = "REFERENCE_MISSING"
    event_type: str = "reference.missing"


class ReferenceExpiredError(PassByRefError):
    code: str = "REFERENCE_EXPIRED"
    event_type: str = "reference.expired"


class ReferenceTenantMismatchError(PassByRefError):
    code: str = "REFERENCE_TENANT_MISMATCH"
    event_type: str = "reference.tenant_mismatch"
    severity: str = "error"


class ReferenceHashMismatchError(PassByRefError):
    code: str = "REFERENCE_HASH_MISMATCH"
    event_type: str = "reference.hash_mismatch"
    severity: str = "error"


class ReferenceUnsupportedKindError(PassByRefError):
    code: str = "REFERENCE_UNSUPPORTED_KIND"
    event_type: str = "reference.unsupported_kind"
    severity: str = "error"


def _opt_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def content_hash_of(content: Mapping[str, object]) -> str:
    """Stable content hash shared by every PassByRef envelope builder and
    any caller that needs to convert a large inline field to a reference
    (e.g. RecordSynapse's ``action_data``) using the same hash convention."""
    digest = hashlib.sha256(json_dumps(content, sort_keys=True).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def is_pass_by_ref(payload: object) -> bool:
    """True if ``payload`` is a PassByRef envelope rather than inline content."""
    if not is_object_dict(payload):
        return False
    return isinstance(payload.get("memory_ref"), str) and payload.get("ref_kind") == "blackboard"


def _unsupported_ref_kind(payload: object) -> str | None:
    """Return the ``ref_kind`` of a reference-shaped payload we cannot resolve.

    A payload carrying a ``memory_ref`` with a ``ref_kind`` other than
    ``"blackboard"`` is clearly *meant* as a reference — treating it as inline
    content would silently hand a dangling pointer downstream. Resolution must
    fail closed with the typed ``reference.unsupported_kind`` fault instead
    of resolving it as inline content.
    """
    if not is_object_dict(payload):
        return None
    ref_kind = payload.get("ref_kind")
    if isinstance(payload.get("memory_ref"), str) and isinstance(ref_kind, str) and ref_kind != "blackboard":
        return ref_kind
    return None


def _check_supported_kind(payload: ContextUnitPayload, *, tenant_id: str) -> None:
    unsupported = _unsupported_ref_kind(payload)
    if unsupported is not None:
        memory_ref = payload.get("memory_ref")
        raise ReferenceUnsupportedKindError(
            f"Reference kind {unsupported!r} is not resolvable — only 'blackboard' references are currently supported",
            ref_kind=unsupported,
            memory_ref=memory_ref if isinstance(memory_ref, str) else None,
            tenant_id=tenant_id,
        )


def _envelope_provenance(payload: ContextUnitPayload) -> list[str]:
    """Provenance tags carried inside an envelope dict (Router middleware
    attaches them there because graph state holds plain dicts, not
    ContextUnits — see ``passbyref_middleware.maybe_convert_result_to_ref``)."""
    raw = payload.get("provenance")
    if not is_object_list(raw):
        return []
    return [item for item in raw if isinstance(item, str)]


def payload_size_bytes(payload: Mapping[str, object]) -> int:
    """Serialized size of a payload — the threshold check operand."""
    return len(json_dumps(payload).encode("utf-8"))


def _as_envelope(payload: ContextUnitPayload) -> PassByRefEnvelope:
    """Narrow an already ``is_pass_by_ref``-checked payload to its typed shape."""
    return {
        "memory_ref": str(payload["memory_ref"]),
        "ref_kind": "blackboard",
        "content_hash": _opt_str(payload.get("content_hash")) or "",
        "expires_at": _opt_str(payload.get("expires_at")),
        "origin_tenant_id": _opt_str(payload.get("origin_tenant_id")) or "",
    }


def _check_envelope_local(envelope: PassByRefEnvelope, *, tenant_id: str) -> None:
    """Checks resolvable without a Brain round trip: tenant + expiry."""
    origin_tenant_id = envelope["origin_tenant_id"]
    if origin_tenant_id and origin_tenant_id != tenant_id:
        raise ReferenceTenantMismatchError(
            f"Reference {envelope['memory_ref']!r} belongs to tenant {origin_tenant_id!r}, not {tenant_id!r}",
            ref_kind="blackboard",
            memory_ref=envelope["memory_ref"],
            tenant_id=tenant_id,
        )
    expires_at = envelope["expires_at"]
    if expires_at:
        try:
            expiry = datetime.fromisoformat(expires_at)
        except ValueError as exc:
            # Malformed timestamps get the typed base fault, not a bare
            # ValueError — resolution failures must always be PassByRefError.
            raise PassByRefError(
                f"Reference {envelope['memory_ref']!r} carries a malformed expires_at timestamp: {expires_at!r}",
                ref_kind="blackboard",
                memory_ref=envelope["memory_ref"],
                tenant_id=tenant_id,
            ) from exc
        if expiry.tzinfo is None:
            # Internally-minted envelopes are always tz-aware; a naive value can
            # only come from an external writer — interpret it as UTC instead of
            # letting the aware/naive comparison raise TypeError.
            expiry = expiry.replace(tzinfo=UTC)
        if datetime.now(UTC) > expiry:
            raise ReferenceExpiredError(
                f"Reference {envelope['memory_ref']!r} expired at {expires_at}",
                ref_kind="blackboard",
                memory_ref=envelope["memory_ref"],
                tenant_id=tenant_id,
            )


def _check_record(envelope: PassByRefEnvelope, record: JsonDict | None, *, tenant_id: str) -> JsonDict:
    """Validate a resolved Blackboard record against the envelope; return its content."""
    if record is None:
        raise ReferenceMissingError(
            f"Reference {envelope['memory_ref']!r} was not found (never written, "
            "already pruned, or blocked by tenant isolation)",
            ref_kind="blackboard",
            memory_ref=envelope["memory_ref"],
            tenant_id=tenant_id,
        )
    content = record.get("content")
    content = content if is_json_dict(content) else {}
    expected_hash = envelope["content_hash"]
    if expected_hash and content_hash_of(content) != expected_hash:
        raise ReferenceHashMismatchError(
            f"Reference {envelope['memory_ref']!r} content hash mismatch — expected {expected_hash!r}",
            ref_kind="blackboard",
            memory_ref=envelope["memory_ref"],
            tenant_id=tenant_id,
        )
    return content


async def maybe_pass_by_ref(
    unit: ContextUnit,
    *,
    tenant_id: str,
    scope_path: str,
    brain_client: BlackboardRefClient,
    threshold_bytes: int = DEFAULT_PASSBYREF_THRESHOLD_BYTES,
    ttl_seconds: int | None = None,
    created_by: str | None = None,
) -> ContextUnit:
    """Convert ``unit.payload`` to a PassByRef envelope if it exceeds the threshold.

    Returns the same ``unit`` unchanged (same ``trace_id``/``parent_unit_id``,
    no provenance change) when the payload is already a reference or is at or
    under ``threshold_bytes``. Otherwise returns a new ``ContextUnit`` with the
    same ``trace_id``/``parent_unit_id``, the payload replaced by the
    reference envelope, and ``"router:auto_passbyref"`` appended to provenance.
    """
    if is_pass_by_ref(unit.payload) or payload_size_bytes(unit.payload) <= threshold_bytes:
        return unit

    content_hash = content_hash_of(unit.payload)
    written = await brain_client.write_blackboard(
        tenant_id=tenant_id,
        scope_path=scope_path,
        content=unit.payload,
        ttl_seconds=ttl_seconds,
        created_by=created_by,
    )
    expires_at: str | None = None
    if ttl_seconds and ttl_seconds > 0:
        created_at = _opt_str(written.get("created_at"))
        base = datetime.fromisoformat(created_at) if created_at else datetime.now(UTC)
        expires_at = (base + timedelta(seconds=ttl_seconds)).isoformat()

    envelope: PassByRefEnvelope = {
        "memory_ref": str(written["id"]),
        "ref_kind": "blackboard",
        "content_hash": content_hash,
        "expires_at": expires_at,
        "origin_tenant_id": tenant_id,
    }
    return unit.model_copy(
        update={
            "payload": dict(envelope),
            "provenance": [*unit.provenance, "router:auto_passbyref"],
        }
    )


async def resolve_pass_by_ref(
    unit: ContextUnit,
    *,
    tenant_id: str,
    brain_client: BlackboardRefClient,
) -> ContextUnit:
    """Resolve a single PassByRef envelope back to its original payload.

    Returns the same ``unit`` unchanged if ``unit.payload`` is not a
    reference. Raises a typed :class:`PassByRefError` subclass — never
    silently falls back to the (unresolved) envelope — on any failure,
    including a reference-shaped payload with an unsupported ``ref_kind``.
    """
    _check_supported_kind(unit.payload, tenant_id=tenant_id)
    if not is_pass_by_ref(unit.payload):
        return unit

    envelope = _as_envelope(unit.payload)
    _check_envelope_local(envelope, tenant_id=tenant_id)

    result = await brain_client.read_blackboard(ids=[envelope["memory_ref"]], tenant_id=tenant_id)
    records = result.get("records")
    record: JsonDict | None = None
    if is_object_list(records) and records and is_json_dict(records[0]):
        record = records[0]
    content = _check_record(envelope, record, tenant_id=tenant_id)

    return unit.model_copy(
        update={
            "payload": content,
            "provenance": [
                *unit.provenance,
                *_envelope_provenance(unit.payload),
                "router:resolve_ref",
            ],
        }
    )


async def resolve_pass_by_ref_batch(
    units: list[ContextUnit],
    *,
    tenant_id: str,
    brain_client: BlackboardRefClient,
) -> list[ContextUnit]:
    """Resolve many PassByRef envelopes with exactly one Brain read call.

    Units whose payload is not a reference pass through unchanged in place.
    Raises on the first envelope-level failure (tenant mismatch / expired) —
    those never reach Brain. Missing/hash-mismatch failures are only
    detectable after the batched read, so those are raised per-unit after it.
    """
    to_resolve: list[tuple[int, PassByRefEnvelope]] = []
    for index, unit in enumerate(units):
        _check_supported_kind(unit.payload, tenant_id=tenant_id)
        if not is_pass_by_ref(unit.payload):
            continue
        envelope = _as_envelope(unit.payload)
        _check_envelope_local(envelope, tenant_id=tenant_id)
        to_resolve.append((index, envelope))

    if not to_resolve:
        return units

    ids = [envelope["memory_ref"] for _, envelope in to_resolve]
    result = await brain_client.read_blackboard(ids=ids, tenant_id=tenant_id)
    records = result.get("records")
    by_id: dict[str, JsonDict] = {}
    if is_object_list(records):
        for candidate in records:
            if not is_json_dict(candidate):
                continue
            record_id = candidate.get("id")
            if isinstance(record_id, str):
                by_id[record_id] = candidate

    resolved = list(units)
    for index, envelope in to_resolve:
        content = _check_record(envelope, by_id.get(envelope["memory_ref"]), tenant_id=tenant_id)
        unit = units[index]
        resolved[index] = unit.model_copy(
            update={
                "payload": content,
                "provenance": [
                    *unit.provenance,
                    *_envelope_provenance(unit.payload),
                    "router:resolve_ref",
                ],
            }
        )
    return resolved


def to_debugbus_event(
    error: PassByRefError,
    *,
    service: str,
    component: str = "passbyref",
    trace_id: str | None = None,
    graph_run_id: str | None = None,
) -> JsonDict:
    """Shape a :class:`PassByRefError` as a DebugBus-ready event, used as
    the DLQ-0 record body when DebugBus storage itself is unavailable.
    Pass ``trace_id``/``graph_run_id`` whenever the caller has them, so
    the event can be correlated back to the run that produced it."""
    event: JsonDict = {
        "event_type": error.event_type,
        "fault_class": error.fault_class,
        "phase": 1,
        "service": service,
        "component": component,
        "tenant_id": _opt_str(error.details.get("tenant_id")),
        "trace_id": trace_id,
        "graph_run_id": graph_run_id,
        "ref_kind": _opt_str(error.details.get("ref_kind")),
        "memory_ref": _opt_str(error.details.get("memory_ref")),
        "severity": error.severity,
        "retryable": error.retryable,
        "metadata": {"message": error.message},
    }
    return event


__all__ = [
    "DEFAULT_PASSBYREF_THRESHOLD_BYTES",
    "BlackboardRefClient",
    "PassByRefEnvelope",
    "PassByRefError",
    "ReferenceMissingError",
    "ReferenceExpiredError",
    "ReferenceTenantMismatchError",
    "ReferenceHashMismatchError",
    "ReferenceUnsupportedKindError",
    "content_hash_of",
    "is_pass_by_ref",
    "payload_size_bytes",
    "maybe_pass_by_ref",
    "resolve_pass_by_ref",
    "resolve_pass_by_ref_batch",
    "to_debugbus_event",
]
