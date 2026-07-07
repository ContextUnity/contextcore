"""Tests for the PassByRef convention.

Uses an in-memory fake satisfying the structural ``BlackboardRefClient``
protocol — no real Brain/gRPC needed, since PassByRef itself is
storage-agnostic (it only calls ``write_blackboard``/``read_blackboard``).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from contextunity.core.passbyref import (
    DEFAULT_PASSBYREF_THRESHOLD_BYTES,
    PassByRefError,
    ReferenceExpiredError,
    ReferenceHashMismatchError,
    ReferenceMissingError,
    ReferenceTenantMismatchError,
    ReferenceUnsupportedKindError,
    is_pass_by_ref,
    maybe_pass_by_ref,
    resolve_pass_by_ref,
    resolve_pass_by_ref_batch,
    to_debugbus_event,
)
from contextunity.core.sdk.contextunit import ContextUnit
from contextunity.core.types import ContextUnitPayload, JsonDict


class FakeBlackboardClient:
    """In-memory stand-in for BrainClient's write_blackboard/read_blackboard."""

    def __init__(self) -> None:
        self.store: dict[str, dict[str, object]] = {}
        self.write_calls = 0
        self.read_calls = 0
        self.last_ttl_seconds: int | None = None

    async def write_blackboard(
        self,
        *,
        tenant_id: str,
        scope_path: str,
        content: ContextUnitPayload,
        metadata: JsonDict | None = None,
        ttl_seconds: int | None = None,
        created_by: str | None = None,
    ) -> ContextUnitPayload:
        self.write_calls += 1
        self.last_ttl_seconds = ttl_seconds
        record_id = str(uuid.uuid4())
        created_at = datetime.now(UTC).isoformat()
        self.store[record_id] = {"tenant_id": tenant_id, "content": dict(content)}
        return {"id": record_id, "scope_path": scope_path, "created_at": created_at}

    async def read_blackboard(self, *, ids: list[str], tenant_id: str) -> ContextUnitPayload:
        self.read_calls += 1
        records: list[JsonDict] = []
        for record_id in ids:
            record = self.store.get(record_id)
            if record is not None and record["tenant_id"] == tenant_id:
                records.append({"id": record_id, "content": record["content"]})
        return {"records": records}


TENANT = "contextmed"


@pytest.mark.asyncio
async def test_payload_below_threshold_remains_inline():
    client = FakeBlackboardClient()
    unit = ContextUnit(payload={"key": "small"})

    result = await maybe_pass_by_ref(unit, tenant_id=TENANT, scope_path=f"{TENANT}.step1", brain_client=client)

    assert result is unit
    assert not is_pass_by_ref(result.payload)
    assert client.write_calls == 0


@pytest.mark.asyncio
async def test_payload_above_threshold_becomes_ref():
    client = FakeBlackboardClient()
    large_content = {"data": "x" * (DEFAULT_PASSBYREF_THRESHOLD_BYTES + 100)}
    unit = ContextUnit(payload=large_content)

    result = await maybe_pass_by_ref(unit, tenant_id=TENANT, scope_path=f"{TENANT}.step1", brain_client=client)

    assert result is not unit
    assert result.trace_id == unit.trace_id
    assert result.parent_unit_id == unit.parent_unit_id
    assert is_pass_by_ref(result.payload)
    assert result.payload["ref_kind"] == "blackboard"
    assert result.payload["memory_ref"]
    assert "router:auto_passbyref" in result.provenance
    assert client.write_calls == 1


@pytest.mark.asyncio
async def test_payload_above_threshold_uses_configured_ttl():
    client = FakeBlackboardClient()
    large_content = {"data": "x" * (DEFAULT_PASSBYREF_THRESHOLD_BYTES + 100)}
    unit = ContextUnit(payload=large_content)

    result = await maybe_pass_by_ref(
        unit,
        tenant_id=TENANT,
        scope_path=f"{TENANT}.step1",
        brain_client=client,
        ttl_seconds=60,
    )

    assert client.last_ttl_seconds == 60
    assert result.payload["expires_at"] is not None


@pytest.mark.asyncio
async def test_resolve_valid_ref_restores_payload_and_provenance():
    client = FakeBlackboardClient()
    original = {"data": "x" * (DEFAULT_PASSBYREF_THRESHOLD_BYTES + 100)}
    unit = ContextUnit(payload=original)
    ref_unit = await maybe_pass_by_ref(unit, tenant_id=TENANT, scope_path=f"{TENANT}.step1", brain_client=client)

    resolved = await resolve_pass_by_ref(ref_unit, tenant_id=TENANT, brain_client=client)

    assert resolved.payload == original
    assert resolved.trace_id == unit.trace_id
    assert "router:resolve_ref" in resolved.provenance


@pytest.mark.asyncio
async def test_resolve_expired_ref_raises_typed_error_without_brain_call():
    client = FakeBlackboardClient()
    envelope = {
        "memory_ref": str(uuid.uuid4()),
        "ref_kind": "blackboard",
        "content_hash": "sha256:deadbeef",
        "expires_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
        "origin_tenant_id": TENANT,
    }
    unit = ContextUnit(payload=envelope)

    with pytest.raises(ReferenceExpiredError) as exc:
        await resolve_pass_by_ref(unit, tenant_id=TENANT, brain_client=client)

    assert exc.value.details["ref_kind"] == "blackboard"
    assert client.read_calls == 0  # envelope-level check short-circuits before any Brain call


@pytest.mark.asyncio
async def test_resolve_missing_ref_raises_typed_error():
    client = FakeBlackboardClient()
    envelope = {
        "memory_ref": str(uuid.uuid4()),
        "ref_kind": "blackboard",
        "content_hash": "sha256:deadbeef",
        "expires_at": None,
        "origin_tenant_id": TENANT,
    }
    unit = ContextUnit(payload=envelope)

    with pytest.raises(ReferenceMissingError):
        await resolve_pass_by_ref(unit, tenant_id=TENANT, brain_client=client)
    assert client.read_calls == 1


@pytest.mark.asyncio
async def test_resolve_tenant_mismatch_raises_without_brain_call():
    client = FakeBlackboardClient()
    unit = ContextUnit(payload={"data": "x" * (DEFAULT_PASSBYREF_THRESHOLD_BYTES + 100)})
    ref_unit = await maybe_pass_by_ref(unit, tenant_id=TENANT, scope_path=f"{TENANT}.step1", brain_client=client)

    with pytest.raises(ReferenceTenantMismatchError):
        await resolve_pass_by_ref(ref_unit, tenant_id="commerce-pim", brain_client=client)
    assert client.read_calls == 0


@pytest.mark.asyncio
async def test_resolve_hash_mismatch_raises_typed_error():
    client = FakeBlackboardClient()
    unit = ContextUnit(payload={"data": "x" * (DEFAULT_PASSBYREF_THRESHOLD_BYTES + 100)})
    ref_unit = await maybe_pass_by_ref(unit, tenant_id=TENANT, scope_path=f"{TENANT}.step1", brain_client=client)
    # Corrupt the stored content after the fact — simulates data tampering.
    memory_ref = ref_unit.payload["memory_ref"]
    client.store[memory_ref]["content"] = {"data": "tampered"}

    with pytest.raises(ReferenceHashMismatchError):
        await resolve_pass_by_ref(ref_unit, tenant_id=TENANT, brain_client=client)


@pytest.mark.asyncio
async def test_batch_resolve_uses_one_brain_read_call():
    client = FakeBlackboardClient()
    units = [ContextUnit(payload={"data": f"{'y' * DEFAULT_PASSBYREF_THRESHOLD_BYTES}{i}"}) for i in range(3)]
    ref_units = [
        await maybe_pass_by_ref(unit, tenant_id=TENANT, scope_path=f"{TENANT}.step{i}", brain_client=client)
        for i, unit in enumerate(units)
    ]
    assert client.write_calls == 3

    resolved = await resolve_pass_by_ref_batch(ref_units, tenant_id=TENANT, brain_client=client)

    assert client.read_calls == 1
    for original, result in zip(units, resolved, strict=True):
        assert result.payload == original.payload
        assert "router:resolve_ref" in result.provenance


@pytest.mark.asyncio
async def test_batch_resolve_passes_through_non_ref_units_unchanged():
    client = FakeBlackboardClient()
    units = [ContextUnit(payload={"small": "inline"})]

    resolved = await resolve_pass_by_ref_batch(units, tenant_id=TENANT, brain_client=client)

    assert resolved == units
    assert client.read_calls == 0


def test_to_debugbus_event_shape():
    error = ReferenceExpiredError("ref expired", ref_kind="blackboard", memory_ref="abc-123", tenant_id=TENANT)
    event = to_debugbus_event(error, service="ContextRouter", trace_id="trace-1", graph_run_id="run-1")

    assert event["event_type"] == "reference.expired"
    assert event["fault_class"] == "reference_fault"
    assert event["phase"] == 1
    assert event["service"] == "ContextRouter"
    assert event["component"] == "passbyref"
    assert event["tenant_id"] == TENANT
    assert event["ref_kind"] == "blackboard"
    assert event["memory_ref"] == "abc-123"
    assert event["severity"] == "warning"
    assert event["retryable"] is False
    assert event["trace_id"] == "trace-1"
    assert event["graph_run_id"] == "run-1"


@pytest.mark.asyncio
async def test_resolve_unsupported_ref_kind_raises_typed_error():
    """A reference-shaped payload we cannot resolve must fail closed with a
    typed reference.unsupported_kind fault, not be silently treated as
    inline content (a dangling pointer downstream)."""
    client = FakeBlackboardClient()
    unit = ContextUnit(payload={"memory_ref": str(uuid.uuid4()), "ref_kind": "s3"})

    with pytest.raises(ReferenceUnsupportedKindError) as exc:
        await resolve_pass_by_ref(unit, tenant_id=TENANT, brain_client=client)

    assert exc.value.event_type == "reference.unsupported_kind"
    assert exc.value.details["ref_kind"] == "s3"
    assert client.read_calls == 0

    with pytest.raises(ReferenceUnsupportedKindError):
        await resolve_pass_by_ref_batch([unit], tenant_id=TENANT, brain_client=client)
    assert client.read_calls == 0


@pytest.mark.asyncio
async def test_resolve_malformed_expires_at_raises_typed_error():
    """A malformed expires_at must surface as a PassByRefError, never a bare
    ValueError/TypeError from datetime parsing."""
    client = FakeBlackboardClient()
    unit = ContextUnit(
        payload={
            "memory_ref": str(uuid.uuid4()),
            "ref_kind": "blackboard",
            "expires_at": "not-a-timestamp",
            "origin_tenant_id": TENANT,
        }
    )

    with pytest.raises(PassByRefError, match="malformed"):
        await resolve_pass_by_ref(unit, tenant_id=TENANT, brain_client=client)
    assert client.read_calls == 0


@pytest.mark.asyncio
async def test_resolve_naive_expires_at_is_treated_as_utc():
    """Externally-written envelopes may carry tz-naive timestamps — those are
    interpreted as UTC instead of raising an aware/naive comparison TypeError."""
    client = FakeBlackboardClient()
    naive_past = (datetime.now(UTC) - timedelta(seconds=5)).replace(tzinfo=None).isoformat()
    unit = ContextUnit(
        payload={
            "memory_ref": str(uuid.uuid4()),
            "ref_kind": "blackboard",
            "expires_at": naive_past,
            "origin_tenant_id": TENANT,
        }
    )

    with pytest.raises(ReferenceExpiredError):
        await resolve_pass_by_ref(unit, tenant_id=TENANT, brain_client=client)


@pytest.mark.asyncio
async def test_resolve_carries_envelope_provenance_into_resolved_unit():
    """Router middleware stores provenance inside the envelope dict (graph
    state holds plain dicts, not ContextUnits) — resolution must merge it
    back into the resolved unit's provenance rather than dropping it."""
    client = FakeBlackboardClient()
    original = {"data": "x" * (DEFAULT_PASSBYREF_THRESHOLD_BYTES + 100)}
    ref_unit = await maybe_pass_by_ref(
        ContextUnit(payload=original),
        tenant_id=TENANT,
        scope_path=f"{TENANT}.step1",
        brain_client=client,
    )
    envelope_dict = {**ref_unit.payload, "provenance": ["router:auto_passbyref"]}

    resolved = await resolve_pass_by_ref(ContextUnit(payload=envelope_dict), tenant_id=TENANT, brain_client=client)

    assert resolved.payload == original
    assert resolved.provenance == ["router:auto_passbyref", "router:resolve_ref"]

    resolved_batch = await resolve_pass_by_ref_batch(
        [ContextUnit(payload=envelope_dict)], tenant_id=TENANT, brain_client=client
    )
    assert resolved_batch[0].provenance == ["router:auto_passbyref", "router:resolve_ref"]
