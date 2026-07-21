"""Project-side client for the closed federated tool delivery protocol."""

from __future__ import annotations

import queue
import random
import threading
import time
from collections import OrderedDict
from collections.abc import Iterator
from dataclasses import dataclass
from hashlib import sha256
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import grpc
from contextunity.core.logging import get_contextunit_logger
from contextunity.core.parsing import json_dumps
from contextunity.core.sdk.streaming.delivery import (
    AcceptedAck,
    DeliveryProtocolError,
    DeliveryRequest,
    DeliveryStatusRequest,
    ExecutorHeartbeat,
    ExecutorReady,
    ExecutorRegistered,
    FinalDeliveryReceipt,
    RouterKeepalive,
    parse_delivery_message,
)
from contextunity.core.sdk.types import ManifestRegistrationCallback, ToolHandler, ToolResult
from contextunity.core.types import ContextUnitPayload, JsonDict, is_json_dict

if TYPE_CHECKING:
    from contextunity.core import contextunit_pb2
    from contextunity.core.sdk.types import GrpcMetadata
    from contextunity.core.signing import AuthBackend
    from contextunity.core.tokens import ContextToken

logger = get_contextunit_logger(__name__)
RECONNECT_DELAY_MIN = 5
RECONNECT_DELAY_MAX = 30
RECONNECT_GRACEFUL_MIN = 1.0
RECONNECT_GRACEFUL_JITTER = 2.0
HEARTBEAT_INTERVAL = 30
TOKEN_TTL_STREAM = 3600
_session_counter = 0
_session_lock = threading.Lock()


@dataclass(frozen=True)
class FederatedToolCallContext:
    """Verified Router-derived identity delivered to a project-owned tool."""

    project_id: str
    tool_name: str
    request_id: str
    caller_tenant: str
    user_id: str | None = None
    operation_id: str = ""
    idempotency_key: str = ""


class _DeliveryCacheCapacityError(RuntimeError):
    """The executor cannot safely remember another accepted delivery."""


@dataclass(frozen=True)
class _DeliveryIdentity:
    operation_id: UUID
    idempotency_key: UUID
    project_id: str
    caller_tenant: str
    user_id: str | None
    tool: str
    input_digest: str

    @classmethod
    def from_request(cls, request: DeliveryRequest) -> _DeliveryIdentity:
        return cls(
            operation_id=request.operation_id,
            idempotency_key=request.idempotency_key,
            project_id=request.project_id,
            caller_tenant=request.caller_tenant,
            user_id=request.user_id,
            tool=request.tool,
            input_digest=request.input_digest,
        )


class _DeliveryCache:
    """Bounded process-local cache keyed by delivery and logical operation identity.

    Entries are never evicted while this executor instance is alive. Capacity
    therefore fails before acknowledgement, and a committed receipt cannot turn
    into a false cache miss. Reusing either identity with conflicting immutable
    fields is rejected before tool execution.
    """

    def __init__(self, max_entries: int) -> None:
        self._max_entries = max_entries
        self._items: OrderedDict[UUID, AcceptedAck | FinalDeliveryReceipt] = OrderedDict()
        self._identities: dict[UUID, _DeliveryIdentity] = {}
        self._delivery_by_key: dict[UUID, UUID] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _with_delivery_id(
        value: AcceptedAck | FinalDeliveryReceipt, delivery_id: UUID
    ) -> AcceptedAck | FinalDeliveryReceipt:
        return value.model_copy(update={"delivery_id": delivery_id})

    def get(self, delivery_id: UUID) -> AcceptedAck | FinalDeliveryReceipt | None:
        with self._lock:
            return self._items.get(delivery_id)

    def lookup_request(self, request: DeliveryRequest) -> AcceptedAck | FinalDeliveryReceipt | None:
        identity = _DeliveryIdentity.from_request(request)
        with self._lock:
            existing_identity = self._identities.get(request.delivery_id)
            if existing_identity is not None:
                if existing_identity != identity:
                    raise ValueError("conflicting delivery identity")
                return self._items[request.delivery_id]
            prior_delivery = self._delivery_by_key.get(request.idempotency_key)
            if prior_delivery is None:
                return None
            if self._identities[prior_delivery] != identity:
                raise ValueError("conflicting idempotency identity")
            return self._with_delivery_id(self._items[prior_delivery], request.delivery_id)

    def lookup_status(self, request: DeliveryStatusRequest) -> AcceptedAck | FinalDeliveryReceipt | None:
        with self._lock:
            delivery_id = request.delivery_id
            value = self._items.get(delivery_id)
            if value is None:
                delivery_id = self._delivery_by_key.get(request.idempotency_key, request.delivery_id)
                value = self._items.get(delivery_id)
            if value is None:
                return None
            identity = self._identities[delivery_id]
            if identity.operation_id != request.operation_id or identity.idempotency_key != request.idempotency_key:
                raise ValueError("conflicting delivery status identity")
            return self._with_delivery_id(value, request.delivery_id)

    def put_request(
        self,
        request: DeliveryRequest,
        value: AcceptedAck | FinalDeliveryReceipt,
    ) -> None:
        identity = _DeliveryIdentity.from_request(request)
        with self._lock:
            prior_delivery = self._delivery_by_key.get(request.idempotency_key)
            if prior_delivery is not None and prior_delivery != request.delivery_id:
                if self._identities[prior_delivery] != identity:
                    raise ValueError("conflicting idempotency identity")
                raise ValueError("duplicate idempotency key must use cached receipt")
            existing_identity = self._identities.get(request.delivery_id)
            if existing_identity is not None and existing_identity != identity:
                raise ValueError("conflicting delivery identity")
            if existing_identity is None and len(self._delivery_by_key) >= self._max_entries:
                raise _DeliveryCacheCapacityError("delivery idempotency cache capacity exhausted")
            self._identities[request.delivery_id] = identity
            self._delivery_by_key[request.idempotency_key] = request.delivery_id
            self._items[request.delivery_id] = value


def _next_session() -> int:
    global _session_counter
    with _session_lock:
        _session_counter += 1
        return _session_counter


def format_grpc_error(exc: Exception) -> str:
    try:
        if isinstance(exc, grpc.RpcError):
            code_fn = getattr(exc, "code", None)
            details_fn = getattr(exc, "details", None)
            code = code_fn() if callable(code_fn) else grpc.StatusCode.UNKNOWN
            details = details_fn() if callable(details_fn) else "no details"
            return f"gRPC {getattr(code, 'name', code)}: {details or 'no details'}"
    except ImportError:
        pass
    return str(exc)[:120]


def _create_stream_metadata(token: ContextToken, backend: AuthBackend | None) -> GrpcMetadata:
    from contextunity.core.token_utils import create_grpc_metadata_with_token

    return create_grpc_metadata_with_token(token, backend=backend)


def run_stream_loop(
    router_url: str,
    project_id: str,
    tool_names: list[str],
    tool_handler: ToolHandler,
    register_fn: ManifestRegistrationCallback | None = None,
    backend: AuthBackend | None = None,
    *,
    allowed_tenants: tuple[str, ...] = (),
    resume_window_seconds: int = 300,
    max_cache_entries: int = 1024,
    max_message_bytes: int = 256 * 1024,
) -> None:
    """Reconnect transport while retaining one process-local idempotency cache."""

    delay = RECONNECT_DELAY_MIN
    executor_instance_id = uuid4()
    cache = _DeliveryCache(max_cache_entries)
    while True:
        session = _next_session()
        if session > 1 and register_fn is not None:
            try:
                _ = register_fn()
            except Exception as exc:
                logger.warning("Re-registration failed: %s", format_grpc_error(exc))
                time.sleep(delay)
                delay = min(delay * 2, RECONNECT_DELAY_MAX)
                continue
        try:
            _run_stream(
                router_url,
                project_id,
                tool_names,
                tool_handler,
                session,
                backend,
                allowed_tenants=allowed_tenants,
                executor_instance_id=executor_instance_id,
                cache=cache,
                resume_window_seconds=resume_window_seconds,
                max_message_bytes=max_message_bytes,
            )
            delay = RECONNECT_DELAY_MIN
            time.sleep(RECONNECT_GRACEFUL_MIN + random.random() * RECONNECT_GRACEFUL_JITTER)
        except Exception as exc:
            logger.warning("Delivery stream disconnected: %s", format_grpc_error(exc))
            time.sleep(delay)
            delay = min(delay * 2, RECONNECT_DELAY_MAX)


def _run_stream(
    router_url: str,
    project_id: str,
    tool_names: list[str],
    tool_handler: ToolHandler,
    session: int,
    backend: AuthBackend | None,
    *,
    allowed_tenants: tuple[str, ...],
    executor_instance_id: UUID,
    cache: _DeliveryCache,
    resume_window_seconds: int,
    max_message_bytes: int,
) -> None:
    from contextunity.core import ContextUnit, contextunit_pb2, router_pb2_grpc
    from contextunity.core.grpc_utils import create_channel_sync
    from contextunity.core.tokens import ContextToken, ProjectBound

    token = ContextToken(
        token_id=f"{project_id}-executor",
        project_binding=ProjectBound(project_id),
        permissions=("stream:executor", f"stream:executor:{project_id}"),
        allowed_tenants=allowed_tenants or (project_id,),
        exp_unix=time.time() + TOKEN_TTL_STREAM,
    )
    effective_tenants = allowed_tenants or (project_id,)
    allowed_tools = frozenset(tool_names)
    metadata = _create_stream_metadata(token, backend)
    channel = create_channel_sync(router_url)
    response_queue: queue.Queue[contextunit_pb2.ContextUnit | None] = queue.Queue()

    def request_generator() -> Iterator[contextunit_pb2.ContextUnit]:
        ready = ExecutorReady(
            project_id=project_id,
            executor_instance_id=executor_instance_id,
            tools=tuple(tool_names),
            resume_window_seconds=resume_window_seconds,
        )
        yield ContextUnit(payload=ready.to_payload(), provenance=[f"{project_id}:tool_delivery:v1"]).to_protobuf(
            contextunit_pb2
        )
        while True:
            try:
                outgoing = response_queue.get(timeout=HEARTBEAT_INTERVAL)
            except queue.Empty:
                heartbeat = ExecutorHeartbeat(executor_instance_id=executor_instance_id)
                yield ContextUnit(payload=heartbeat.to_payload()).to_protobuf(contextunit_pb2)
                continue
            if outgoing is None:
                return
            yield outgoing

    try:
        stub = router_pb2_grpc.RouterServiceStub(channel)
        responses = stub.ToolExecutorStream(request_generator(), metadata=metadata, wait_for_ready=True)
        for wire in responses:
            from contextunity.core.sdk.payload import wire_payload_from_field

            raw = wire_payload_from_field(wire.payload)
            if len(json_dumps(raw).encode("utf-8")) > max_message_bytes:
                raise ValueError("delivery message exceeds project C0 byte budget")
            message = parse_delivery_message(raw)
            if isinstance(message, DeliveryRequest):
                _handle_delivery_request(
                    message,
                    tool_handler=tool_handler,
                    project_id=project_id,
                    allowed_tools=allowed_tools,
                    allowed_tenants=effective_tenants,
                    executor_instance_id=executor_instance_id,
                    cache=cache,
                    response_queue=response_queue,
                    max_message_bytes=max_message_bytes,
                )
            elif isinstance(message, DeliveryStatusRequest):
                receipt = _status_receipt(message, executor_instance_id, cache)
                _queue_message(
                    receipt,
                    project_id,
                    response_queue,
                    max_message_bytes=max_message_bytes,
                )
            elif isinstance(message, (RouterKeepalive, ExecutorRegistered)):
                continue
            elif isinstance(message, DeliveryProtocolError):
                raise RuntimeError(f"Router rejected delivery protocol: {message.error_code}")
            else:
                raise ValueError("message direction is not accepted from Router")
    finally:
        response_queue.put(None)
        channel.close()
        logger.info("Delivery stream session %d closed", session)


def _to_tool_payload(payload: JsonDict) -> ContextUnitPayload:
    """Cross the validated delivery JSON boundary into the open SDK tool contract."""

    return {key: value for key, value in payload.items()}


def _handle_delivery_request(
    request: DeliveryRequest,
    *,
    tool_handler: ToolHandler,
    project_id: str,
    allowed_tools: frozenset[str],
    allowed_tenants: tuple[str, ...],
    executor_instance_id: UUID,
    cache: _DeliveryCache,
    response_queue: queue.Queue[contextunit_pb2.ContextUnit | None],
    max_message_bytes: int = 256 * 1024,
) -> None:
    if request.project_id != project_id:
        raise ValueError("delivery project mismatch")
    if request.tool not in allowed_tools:
        raise ValueError("delivery tool is not registered by this executor")
    if request.caller_tenant not in allowed_tenants:
        raise ValueError("delivery caller tenant is outside executor scope")
    actual_digest = sha256(json_dumps(request.args, sort_keys=True).encode("utf-8")).hexdigest()
    if actual_digest != request.input_digest:
        raise ValueError("delivery input digest mismatch")
    existing = cache.lookup_request(request)
    if isinstance(existing, FinalDeliveryReceipt):
        _queue_message(existing, project_id, response_queue, max_message_bytes=max_message_bytes)
        return
    if isinstance(existing, AcceptedAck):
        _queue_message(existing, project_id, response_queue, max_message_bytes=max_message_bytes)
        return
    if request.deadline_unix_ms <= int(time.time() * 1000):
        receipt = _unknown_receipt(request, executor_instance_id, "deadline_expired")
        try:
            cache.put_request(request, receipt)
        except _DeliveryCacheCapacityError:
            pass
        _queue_message(receipt, project_id, response_queue, max_message_bytes=max_message_bytes)
        return

    ack = AcceptedAck(
        delivery_id=request.delivery_id,
        operation_id=request.operation_id,
        idempotency_key=request.idempotency_key,
        executor_instance_id=executor_instance_id,
    )
    try:
        cache.put_request(request, ack)
    except _DeliveryCacheCapacityError:
        receipt = _unknown_receipt(request, executor_instance_id, "idempotency_capacity")
        _queue_message(receipt, project_id, response_queue, max_message_bytes=max_message_bytes)
        return
    _queue_message(ack, project_id, response_queue, max_message_bytes=max_message_bytes)
    auth_context = FederatedToolCallContext(
        project_id=project_id,
        tool_name=request.tool,
        request_id=str(request.delivery_id),
        caller_tenant=request.caller_tenant,
        user_id=request.user_id,
        operation_id=str(request.operation_id),
        idempotency_key=str(request.idempotency_key),
    )
    try:
        result: ToolResult = tool_handler(
            request.tool,
            _to_tool_payload(request.args),
            auth_context,
        )
        if not is_json_dict(result):
            raise ValueError("federated tool result must be a JSON object")
        validated = result
        digest = sha256(json_dumps(validated, sort_keys=True).encode("utf-8")).hexdigest()
        receipt = FinalDeliveryReceipt(
            delivery_id=request.delivery_id,
            operation_id=request.operation_id,
            idempotency_key=request.idempotency_key,
            executor_instance_id=executor_instance_id,
            effect_state="committed",
            replay_safe=False,
            result_digest=digest,
            outcome="result",
            result=validated,
        )
    except Exception as exc:
        error_type = type(exc)
        code = f"{error_type.__module__}.{error_type.__qualname__}"[:128].replace(" ", "_")
        digest = sha256(code.encode("utf-8")).hexdigest()
        receipt = FinalDeliveryReceipt(
            delivery_id=request.delivery_id,
            operation_id=request.operation_id,
            idempotency_key=request.idempotency_key,
            executor_instance_id=executor_instance_id,
            effect_state="unknown",
            replay_safe=False,
            result_digest=digest,
            outcome="error",
            error_code=code,
        )
    if len(json_dumps(receipt.to_payload()).encode("utf-8")) > max_message_bytes:
        receipt = FinalDeliveryReceipt(
            delivery_id=request.delivery_id,
            operation_id=request.operation_id,
            idempotency_key=request.idempotency_key,
            executor_instance_id=executor_instance_id,
            effect_state="committed",
            replay_safe=False,
            result_digest=receipt.result_digest,
            outcome="error",
            error_code="result_too_large",
        )
    cache.put_request(request, receipt)
    _queue_message(
        receipt,
        project_id,
        response_queue,
        max_message_bytes=max_message_bytes,
    )


def _status_receipt(
    request: DeliveryStatusRequest,
    executor_instance_id: UUID,
    cache: _DeliveryCache,
) -> FinalDeliveryReceipt:
    cached = cache.lookup_status(request)
    if isinstance(cached, FinalDeliveryReceipt):
        return cached
    if isinstance(cached, AcceptedAck):
        return FinalDeliveryReceipt(
            delivery_id=request.delivery_id,
            operation_id=request.operation_id,
            idempotency_key=request.idempotency_key,
            executor_instance_id=executor_instance_id,
            effect_state="unknown",
            replay_safe=False,
            result_digest=sha256(b"accepted-without-final").hexdigest(),
            outcome="status",
        )
    if request.previous_executor_instance_id == executor_instance_id:
        return FinalDeliveryReceipt(
            delivery_id=request.delivery_id,
            operation_id=request.operation_id,
            idempotency_key=request.idempotency_key,
            executor_instance_id=executor_instance_id,
            effect_state="not_started",
            replay_safe=True,
            result_digest=sha256(b"not-started").hexdigest(),
            outcome="status",
        )
    return _unknown_status(request, executor_instance_id)


def _unknown_status(request: DeliveryStatusRequest, executor_instance_id: UUID) -> FinalDeliveryReceipt:
    return FinalDeliveryReceipt(
        delivery_id=request.delivery_id,
        operation_id=request.operation_id,
        idempotency_key=request.idempotency_key,
        executor_instance_id=executor_instance_id,
        effect_state="unknown",
        replay_safe=False,
        result_digest=sha256(b"unknown-after-restart").hexdigest(),
        outcome="status",
    )


def _unknown_receipt(request: DeliveryRequest, executor_instance_id: UUID, reason: str) -> FinalDeliveryReceipt:
    return FinalDeliveryReceipt(
        delivery_id=request.delivery_id,
        operation_id=request.operation_id,
        idempotency_key=request.idempotency_key,
        executor_instance_id=executor_instance_id,
        effect_state="unknown",
        replay_safe=False,
        result_digest=sha256(reason.encode("utf-8")).hexdigest(),
        outcome="error",
        error_code=reason,
    )


def _queue_message(
    message: AcceptedAck | FinalDeliveryReceipt,
    project_id: str,
    response_queue: queue.Queue[contextunit_pb2.ContextUnit | None],
    *,
    max_message_bytes: int = 256 * 1024,
) -> None:
    from contextunity.core import ContextUnit, contextunit_pb2

    payload = message.to_payload()
    if len(json_dumps(payload).encode("utf-8")) > max_message_bytes:
        raise ValueError("delivery message exceeds project C0 byte budget")
    response_queue.put(
        ContextUnit(payload=payload, provenance=[f"{project_id}:tool_delivery:v1"]).to_protobuf(contextunit_pb2)
    )


__all__ = ["FederatedToolCallContext", "format_grpc_error", "run_stream_loop"]
