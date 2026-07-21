"""Project-side closed delivery protocol and idempotency tests."""

from __future__ import annotations

import queue
import time
from hashlib import sha256
from uuid import uuid4

import pytest
from contextunity.core.parsing import json_dumps
from contextunity.core.sdk.streaming.bidi import (
    FederatedToolCallContext,
    _DeliveryCache,
    _handle_delivery_request,
    _status_receipt,
)
from contextunity.core.sdk.streaming.delivery import (
    AcceptedAck,
    DeliveryRequest,
    DeliveryStatusRequest,
    FinalDeliveryReceipt,
    parse_delivery_message,
)
from google.protobuf.json_format import MessageToDict


def _request(instance_project: str = "project-1") -> DeliveryRequest:
    args = {"value": 1}
    return DeliveryRequest(
        delivery_id=uuid4(),
        operation_id=uuid4(),
        idempotency_key=uuid4(),
        attempt_id=uuid4(),
        project_id=instance_project,
        caller_tenant="tenant-1",
        user_id="user-1",
        tool="write",
        deadline_unix_ms=int((time.time() + 30) * 1000),
        input_digest=sha256(json_dumps(args, sort_keys=True).encode("utf-8")).hexdigest(),
        args=args,
    )


def _messages(outgoing: queue.Queue[object]) -> list[AcceptedAck | FinalDeliveryReceipt]:
    result: list[AcceptedAck | FinalDeliveryReceipt] = []
    while not outgoing.empty():
        wire = outgoing.get_nowait()
        payload = MessageToDict(wire.payload)
        parsed = parse_delivery_message(payload)
        assert isinstance(parsed, (AcceptedAck, FinalDeliveryReceipt))
        result.append(parsed)
    return result


def test_delivery_ack_precedes_final_and_forwards_verified_identity() -> None:
    request = _request()
    instance = uuid4()
    cache = _DeliveryCache(10)
    outgoing: queue.Queue = queue.Queue()
    seen: list[FederatedToolCallContext] = []

    def handler(_tool: str, _args: dict[str, object], ctx: FederatedToolCallContext) -> dict:
        seen.append(ctx)
        return {"status": "stored"}

    _handle_delivery_request(
        request,
        tool_handler=handler,
        project_id="project-1",
        allowed_tools=frozenset({"write"}),
        allowed_tenants=("tenant-1",),
        executor_instance_id=instance,
        cache=cache,
        response_queue=outgoing,
    )
    messages = _messages(outgoing)
    assert isinstance(messages[0], AcceptedAck)
    assert isinstance(messages[1], FinalDeliveryReceipt)
    assert messages[1].effect_state == "committed"
    assert seen[0].caller_tenant == "tenant-1"
    assert seen[0].operation_id == str(request.operation_id)
    assert seen[0].idempotency_key == str(request.idempotency_key)


def test_duplicate_delivery_returns_cached_receipt_without_second_effect() -> None:
    request = _request()
    instance = uuid4()
    cache = _DeliveryCache(10)
    outgoing: queue.Queue = queue.Queue()
    calls = 0

    def handler(_tool: str, _args: dict[str, object], _ctx: FederatedToolCallContext) -> dict:
        nonlocal calls
        calls += 1
        return {"status": "stored"}

    for _ in range(2):
        _handle_delivery_request(
            request,
            tool_handler=handler,
            project_id="project-1",
            allowed_tools=frozenset({"write"}),
            allowed_tenants=("tenant-1",),
            executor_instance_id=instance,
            cache=cache,
            response_queue=outgoing,
        )
    messages = _messages(outgoing)
    assert calls == 1
    assert isinstance(messages[-1], FinalDeliveryReceipt)
    assert messages[-1].delivery_id == request.delivery_id


@pytest.mark.parametrize(
    ("allowed_tools", "allowed_tenants", "error"),
    [
        (frozenset({"read"}), ("tenant-1",), "tool is not registered"),
        (frozenset({"write"}), ("tenant-2",), "outside executor scope"),
    ],
)
def test_delivery_rejects_unregistered_tool_and_cross_tenant_scope(
    allowed_tools: frozenset[str], allowed_tenants: tuple[str, ...], error: str
) -> None:
    request = _request()
    with pytest.raises(ValueError, match=error):
        _handle_delivery_request(
            request,
            tool_handler=lambda _tool, _args, _ctx: {"status": "unexpected"},
            project_id="project-1",
            allowed_tools=allowed_tools,
            allowed_tenants=allowed_tenants,
            executor_instance_id=uuid4(),
            cache=_DeliveryCache(10),
            response_queue=queue.Queue(),
        )


def test_idempotency_capacity_never_evicts_committed_receipt_or_starts_new_effect() -> None:
    cache = _DeliveryCache(1)
    instance = uuid4()
    outgoing: queue.Queue = queue.Queue()
    calls = 0

    def handler(_tool: str, _args: dict[str, object], _ctx: FederatedToolCallContext) -> dict:
        nonlocal calls
        calls += 1
        return {"status": "stored"}

    first = _request()
    second = _request()
    for request in (first, second):
        _handle_delivery_request(
            request,
            tool_handler=handler,
            project_id="project-1",
            allowed_tools=frozenset({"write"}),
            allowed_tenants=("tenant-1",),
            executor_instance_id=instance,
            cache=cache,
            response_queue=outgoing,
        )

    assert calls == 1
    assert isinstance(cache.get(first.delivery_id), FinalDeliveryReceipt)
    messages = _messages(outgoing)
    capacity = messages[-1]
    assert isinstance(capacity, FinalDeliveryReceipt)
    assert capacity.delivery_id == second.delivery_id
    assert capacity.effect_state == "unknown"
    assert capacity.error_code == "idempotency_capacity"


def test_same_idempotency_key_with_new_delivery_reuses_receipt_without_effect() -> None:
    first = _request()
    duplicate = first.model_copy(update={"delivery_id": uuid4(), "attempt_id": uuid4()})
    cache = _DeliveryCache(10)
    outgoing: queue.Queue = queue.Queue()
    calls = 0

    def handler(_tool: str, _args: dict[str, object], _ctx: FederatedToolCallContext) -> dict:
        nonlocal calls
        calls += 1
        return {"status": "stored"}

    for request in (first, duplicate):
        _handle_delivery_request(
            request,
            tool_handler=handler,
            project_id="project-1",
            allowed_tools=frozenset({"write"}),
            allowed_tenants=("tenant-1",),
            executor_instance_id=uuid4(),
            cache=cache,
            response_queue=outgoing,
        )
    assert calls == 1
    messages = _messages(outgoing)
    duplicate_receipt = messages[-1]
    assert isinstance(duplicate_receipt, FinalDeliveryReceipt)
    assert duplicate_receipt.delivery_id == duplicate.delivery_id


def test_conflicting_delivery_identity_rejects_before_effect() -> None:
    first = _request()
    cache = _DeliveryCache(10)
    outgoing: queue.Queue = queue.Queue()
    calls = 0

    def handler(_tool: str, _args: dict[str, object], _ctx: FederatedToolCallContext) -> dict:
        nonlocal calls
        calls += 1
        return {"status": "stored"}

    _handle_delivery_request(
        first,
        tool_handler=handler,
        project_id="project-1",
        allowed_tools=frozenset({"write"}),
        allowed_tenants=("tenant-1",),
        executor_instance_id=uuid4(),
        cache=cache,
        response_queue=outgoing,
    )
    conflicting = first.model_copy(update={"caller_tenant": "tenant-2"})
    with pytest.raises(ValueError, match="outside executor scope|conflicting"):
        _handle_delivery_request(
            conflicting,
            tool_handler=handler,
            project_id="project-1",
            allowed_tools=frozenset({"write"}),
            allowed_tenants=("tenant-1", "tenant-2"),
            executor_instance_id=uuid4(),
            cache=cache,
            response_queue=outgoing,
        )
    assert calls == 1


def test_input_digest_mismatch_rejects_before_ack_or_effect() -> None:
    request = _request().model_copy(update={"input_digest": "0" * 64})
    outgoing: queue.Queue = queue.Queue()
    with pytest.raises(ValueError, match="digest mismatch"):
        _handle_delivery_request(
            request,
            tool_handler=lambda _tool, _args, _ctx: {"status": "unexpected"},
            project_id="project-1",
            allowed_tools=frozenset({"write"}),
            allowed_tenants=("tenant-1",),
            executor_instance_id=uuid4(),
            cache=_DeliveryCache(10),
            response_queue=outgoing,
        )
    assert outgoing.empty()


def test_status_missing_same_process_is_replay_safe_not_started() -> None:
    request = _request()
    instance = uuid4()
    status = DeliveryStatusRequest(
        delivery_id=request.delivery_id,
        operation_id=request.operation_id,
        idempotency_key=request.idempotency_key,
        previous_executor_instance_id=instance,
    )
    receipt = _status_receipt(status, instance, _DeliveryCache(10))
    assert receipt.effect_state == "not_started"
    assert receipt.replay_safe is True


def test_status_missing_after_restart_is_unknown() -> None:
    request = _request()
    status = DeliveryStatusRequest(
        delivery_id=request.delivery_id,
        operation_id=request.operation_id,
        idempotency_key=request.idempotency_key,
        previous_executor_instance_id=uuid4(),
    )
    receipt = _status_receipt(status, uuid4(), _DeliveryCache(10))
    assert receipt.effect_state == "unknown"
    assert receipt.replay_safe is False


def test_receipt_rejects_result_without_committed_effect_state() -> None:
    request = _request()
    with pytest.raises(ValueError, match="committed"):
        FinalDeliveryReceipt(
            delivery_id=request.delivery_id,
            operation_id=request.operation_id,
            idempotency_key=request.idempotency_key,
            executor_instance_id=uuid4(),
            effect_state="unknown",
            replay_safe=False,
            result_digest="b" * 64,
            outcome="result",
            result={"status": "ambiguous"},
        )


def test_unknown_version_and_legacy_action_map_reject() -> None:
    with pytest.raises(ValueError):
        parse_delivery_message({"action": "execute"})
    payload = _request().to_payload()
    payload["schema_version"] = "contextunity.tool-delivery/v2"
    with pytest.raises(ValueError):
        parse_delivery_message(payload)


def test_oversized_result_becomes_bounded_committed_receipt() -> None:
    request = _request()
    outgoing: queue.Queue = queue.Queue()
    _handle_delivery_request(
        request,
        tool_handler=lambda _tool, _args, _ctx: {"secret": "x" * 10_000},
        project_id="project-1",
        allowed_tools=frozenset({"write"}),
        allowed_tenants=("tenant-1",),
        executor_instance_id=uuid4(),
        cache=_DeliveryCache(10),
        response_queue=outgoing,
        max_message_bytes=1024,
    )
    messages = _messages(outgoing)
    receipt = messages[-1]
    assert isinstance(receipt, FinalDeliveryReceipt)
    assert receipt.effect_state == "committed"
    assert receipt.outcome == "error"
    assert receipt.error_code == "result_too_large"
    assert "secret" not in repr(receipt)


def test_handler_failure_is_unknown_and_redacts_exception_text() -> None:
    request = _request()
    outgoing: queue.Queue = queue.Queue()

    def handler(_tool: str, _args: dict[str, object], _ctx: FederatedToolCallContext) -> dict:
        raise RuntimeError("secret database text")

    _handle_delivery_request(
        request,
        tool_handler=handler,
        project_id="project-1",
        allowed_tools=frozenset({"write"}),
        allowed_tenants=("tenant-1",),
        executor_instance_id=uuid4(),
        cache=_DeliveryCache(10),
        response_queue=outgoing,
    )
    serialized = [MessageToDict(item.payload) for item in list(outgoing.queue)]
    assert all("secret database text" not in str(item) for item in serialized)
    receipt = parse_delivery_message(serialized[-1])
    assert isinstance(receipt, FinalDeliveryReceipt)
    assert receipt.effect_state == "unknown"
