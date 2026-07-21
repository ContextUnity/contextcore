"""Closed v1 protocol for Router-to-project federated tool delivery.

The protobuf stream remains the transport, while every ``ContextUnit.payload``
is validated as exactly one versioned message here.  No caller may construct or
parse ad-hoc ``action`` dictionaries.
"""

from __future__ import annotations

from typing import Annotated, ClassVar, Literal, TypeAlias
from uuid import UUID

from contextunity.core.types import ContextUnitPayload, JsonDict, is_json_dict, is_object_dict
from pydantic import BaseModel, ConfigDict, Field, model_validator

DELIVERY_SCHEMA_V1 = "contextunity.tool-delivery/v1"
Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"[A-Za-z0-9][A-Za-z0-9._:@/-]*")]
Digest = Annotated[str, Field(pattern=r"[0-9a-f]{64}")]


class DeliveryMessage(BaseModel):
    """Strict base for one delivery-stream message."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["contextunity.tool-delivery/v1"] = DELIVERY_SCHEMA_V1

    def to_payload(self) -> ContextUnitPayload:
        """Serialize once at the typed protocol-to-ContextUnit boundary."""

        payload: object = self.model_dump(mode="json", exclude_none=True)
        if not is_json_dict(payload):
            raise ValueError("delivery model produced a non-JSON payload")
        return {key: value for key, value in payload.items()}


class ExecutorReady(DeliveryMessage):
    message_type: Literal["executor_ready"] = "executor_ready"
    project_id: Identifier
    executor_instance_id: UUID
    tools: tuple[Identifier, ...] = Field(min_length=1, max_length=256)
    resume_window_seconds: int = Field(ge=1, le=86_400)

    @model_validator(mode="after")
    def _unique_tools(self) -> "ExecutorReady":
        if len(self.tools) != len(set(self.tools)):
            raise ValueError("executor_ready tools must be unique")
        return self


class ExecutorRegistered(DeliveryMessage):
    message_type: Literal["executor_registered"] = "executor_registered"
    project_id: Identifier
    executor_instance_id: UUID


class DeliveryRequest(DeliveryMessage):
    message_type: Literal["delivery_request"] = "delivery_request"
    delivery_id: UUID
    operation_id: UUID
    idempotency_key: UUID
    attempt_id: UUID
    project_id: Identifier
    caller_tenant: Identifier
    user_id: Identifier | None = None
    tool: Identifier
    deadline_unix_ms: int = Field(gt=0)
    input_digest: Digest
    args: JsonDict


class AcceptedAck(DeliveryMessage):
    message_type: Literal["accepted_ack"] = "accepted_ack"
    delivery_id: UUID
    operation_id: UUID
    idempotency_key: UUID
    executor_instance_id: UUID


class DeliveryStatusRequest(DeliveryMessage):
    message_type: Literal["delivery_status_request"] = "delivery_status_request"
    delivery_id: UUID
    operation_id: UUID
    idempotency_key: UUID
    previous_executor_instance_id: UUID


class FinalDeliveryReceipt(DeliveryMessage):
    message_type: Literal["final_delivery_receipt"] = "final_delivery_receipt"
    delivery_id: UUID
    operation_id: UUID
    idempotency_key: UUID
    executor_instance_id: UUID
    effect_state: Literal["not_started", "committed", "unknown", "compensated"]
    replay_safe: bool
    result_digest: Digest
    outcome: Literal["result", "error", "status"]
    result: JsonDict | None = None
    error_code: Identifier | None = None

    @model_validator(mode="after")
    def _closed_outcome(self) -> "FinalDeliveryReceipt":
        if self.replay_safe and self.effect_state != "not_started":
            raise ValueError("only not_started delivery may be replay-safe")
        if self.outcome == "result" and self.result is None:
            raise ValueError("result receipt requires result")
        if self.outcome == "result" and self.effect_state != "committed":
            raise ValueError("result receipt requires committed effect state")
        if self.effect_state == "not_started" and self.outcome != "status":
            raise ValueError("not_started receipt must be a status response")
        if self.outcome == "error" and self.error_code is None:
            raise ValueError("error receipt requires error_code")
        if self.outcome != "result" and self.result is not None:
            raise ValueError("non-result receipt cannot carry result")
        return self


class ExecutorHeartbeat(DeliveryMessage):
    message_type: Literal["executor_heartbeat"] = "executor_heartbeat"
    executor_instance_id: UUID


class RouterKeepalive(DeliveryMessage):
    message_type: Literal["router_keepalive"] = "router_keepalive"


class DeliveryProtocolError(DeliveryMessage):
    message_type: Literal["protocol_error"] = "protocol_error"
    error_code: Identifier


ToolDeliveryEnvelope: TypeAlias = (
    ExecutorReady
    | ExecutorRegistered
    | DeliveryRequest
    | AcceptedAck
    | DeliveryStatusRequest
    | FinalDeliveryReceipt
    | ExecutorHeartbeat
    | RouterKeepalive
    | DeliveryProtocolError
)
_MESSAGE_TYPES: dict[str, type[DeliveryMessage]] = {
    "executor_ready": ExecutorReady,
    "executor_registered": ExecutorRegistered,
    "delivery_request": DeliveryRequest,
    "accepted_ack": AcceptedAck,
    "delivery_status_request": DeliveryStatusRequest,
    "final_delivery_receipt": FinalDeliveryReceipt,
    "executor_heartbeat": ExecutorHeartbeat,
    "router_keepalive": RouterKeepalive,
    "protocol_error": DeliveryProtocolError,
}


def parse_delivery_message(payload: object) -> ToolDeliveryEnvelope:
    """Validate one closed message and reject unknown/legacy wire shapes."""

    if not is_object_dict(payload):
        raise ValueError("delivery message must be an object")
    message_type = payload.get("message_type")
    if not isinstance(message_type, str) or message_type not in _MESSAGE_TYPES:
        raise ValueError("unknown delivery message type")
    model = _MESSAGE_TYPES[message_type].model_validate(payload)
    if not isinstance(
        model,
        (
            ExecutorReady,
            ExecutorRegistered,
            DeliveryRequest,
            AcceptedAck,
            DeliveryStatusRequest,
            FinalDeliveryReceipt,
            ExecutorHeartbeat,
            RouterKeepalive,
            DeliveryProtocolError,
        ),
    ):
        raise ValueError("unsupported delivery message")
    return model


__all__ = [
    "DELIVERY_SCHEMA_V1",
    "AcceptedAck",
    "DeliveryMessage",
    "DeliveryProtocolError",
    "DeliveryRequest",
    "DeliveryStatusRequest",
    "ExecutorHeartbeat",
    "ExecutorReady",
    "ExecutorRegistered",
    "FinalDeliveryReceipt",
    "RouterKeepalive",
    "ToolDeliveryEnvelope",
    "parse_delivery_message",
]
