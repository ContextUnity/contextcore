"""Typed accessors for ``ContextUnit.payload`` values.

The ContextUnit payload is an open ``ContextUnitPayload`` because it carries
arbitrary domain data deserialized from the wire (a protobuf ``Struct``).
These helpers narrow individual payload entries to concrete Python types
without resorting to ``Any`` or ``cast``, so SDK client methods can map
gRPC responses onto strongly-typed result models.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TypedDict

from contextunity.core import contextunit_pb2
from contextunity.core.sdk.types import ToolResult
from contextunity.core.types import (
    ContextUnitPayload,
    JsonDict,
    JsonValue,
    is_json_dict,
    is_json_value,
    is_object_dict,
    is_object_list,
    is_object_mapping,
)
from google.protobuf.message import Message

__all__ = [
    "FederatedExecuteRequest",
    "get_str",
    "get_optional_str",
    "get_required_str",
    "get_int",
    "get_float",
    "get_bool",
    "get_str_list",
    "get_dict",
    "get_dict_list",
    "get_object_list",
    "get_json_dict",
    "get_json_dict_list",
    "get_json_value",
    "normalize_tool_result",
    "copy_wire_payload",
    "parse_federated_execute",
    "wire_payload_from_field",
    "wire_payload_from_message",
    "wire_payload_from_proto_unit",
]


class FederatedExecuteRequest(TypedDict):
    """Router → project federated tool execute wire (BiDi stream)."""

    request_id: str
    tool: str
    args: ContextUnitPayload
    caller_tenant: str
    user_id: str | None


def get_str(payload: Mapping[str, object], key: str, default: str = "") -> str:
    """Return ``payload[key]`` as ``str``, or ``default`` if missing/wrong type."""
    value = payload.get(key, default)
    return value if isinstance(value, str) else default


def get_optional_str(payload: Mapping[str, object], key: str) -> str | None:
    """Return ``payload[key]`` as ``str`` when present and typed, else ``None``."""
    value = payload.get(key)
    return value if isinstance(value, str) else None


def get_required_str(payload: Mapping[str, object], key: str, *, label: str | None = None) -> str:
    """Return a required non-empty string from the payload or raise ``ValueError``."""
    value = get_optional_str(payload, key)
    if value:
        return value
    field = label or key
    raise ValueError(f"{field} is required")


def get_int(payload: Mapping[str, object], key: str, default: int = 0) -> int:
    """Return ``payload[key]`` as ``int``, or ``default`` if missing/wrong type."""
    value = payload.get(key, default)
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    return default


def get_float(payload: Mapping[str, object], key: str, default: float = 0.0) -> float:
    """Return ``payload[key]`` as ``float``, or ``default`` if missing/wrong type."""
    value = payload.get(key, default)
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    return default


def get_bool(payload: Mapping[str, object], key: str, default: bool = False) -> bool:
    """Return ``payload[key]`` as ``bool``, or ``default`` if missing/wrong type."""
    value = payload.get(key, default)
    return value if isinstance(value, bool) else default


def _coerce_dict(value: object) -> ContextUnitPayload:
    """Coerce a value to ``ContextUnitPayload`` when it is a mapping, else ``{}``."""
    if not is_object_mapping(value):
        return {}
    result: ContextUnitPayload = {}
    for key, entry in value.items():
        result[str(key)] = entry
    return result


def get_str_list(payload: Mapping[str, object], key: str) -> list[str]:
    """Return ``payload[key]`` as ``list[str]`` (string elements only)."""
    value = payload.get(key)
    if not is_object_list(value):
        return []
    result: list[str] = []
    for item in value:
        if isinstance(item, str):
            result.append(item)
    return result


def get_dict(payload: ContextUnitPayload, key: str) -> ContextUnitPayload:
    """Return ``payload[key]`` as nested ``ContextUnitPayload`` with string keys."""
    return _coerce_dict(payload.get(key))


def get_json_dict(payload: Mapping[str, object], key: str) -> JsonDict:
    """Return ``payload[key]`` as ``JsonDict`` when it passes L2 validation."""
    value = payload.get(key)
    if is_json_dict(value):
        return value
    return {}


def get_json_value(payload: Mapping[str, object], key: str, default: JsonValue = "") -> JsonValue:
    """Return ``payload[key]`` when it passes L2 validation, else ``default``."""
    value = payload.get(key, default)
    return value if is_json_value(value) else default


def get_dict_list(payload: ContextUnitPayload, key: str) -> list[ContextUnitPayload]:
    """Return ``payload[key]`` as ``list[ContextUnitPayload]`` (mapping elements only)."""
    value = payload.get(key)
    if not is_object_list(value):
        return []
    return [_coerce_dict(item) for item in value if is_object_mapping(item)]


def get_object_list(payload: Mapping[str, object], key: str) -> list[object]:
    """Return ``payload[key]`` as ``list[object]`` when the value is a list."""
    value = payload.get(key, [])
    if is_object_list(value):
        return list(value)
    return []


def normalize_tool_result(result: object) -> ToolResult:
    """Normalize a tool or activity return value to ``ToolResult`` (L3 payload)."""
    if not is_object_dict(result):
        return {"result": result}
    normalized: ToolResult = {}
    for key, val in result.items():
        normalized[str(key)] = val
    return normalized


def get_json_dict_list(payload: Mapping[str, object], key: str) -> list[JsonDict]:
    """Return ``payload[key]`` as ``list[JsonDict]`` (L2-valid mapping elements only)."""
    value = payload.get(key)
    if not is_object_list(value):
        return []
    return [item for item in value if is_json_dict(item)]


def wire_payload_from_message(message: Message) -> ContextUnitPayload:
    """Convert a protobuf ``Struct`` (or other message) to ``ContextUnitPayload``."""
    from google.protobuf.json_format import MessageToDict

    raw = MessageToDict(message)
    if not is_json_dict(raw):
        return {}
    result: ContextUnitPayload = {}
    for key, value in raw.items():
        result[str(key)] = value
    return result


def wire_payload_from_field(payload_field: object) -> ContextUnitPayload:
    """Convert an already-decoded wire dict or protobuf Struct to ``ContextUnitPayload``."""
    if is_json_dict(payload_field):
        result: ContextUnitPayload = {}
        for key, value in payload_field.items():
            result[str(key)] = value
        return result
    if isinstance(payload_field, Message):
        return wire_payload_from_message(payload_field)
    return {}


def wire_payload_from_proto_unit(unit: contextunit_pb2.ContextUnit) -> ContextUnitPayload:
    """Extract ``ContextUnit.payload`` as ``ContextUnitPayload`` without Pydantic."""
    if unit.HasField("payload"):
        return wire_payload_from_field(unit.payload)
    return {}


def copy_wire_payload(payload: Mapping[str, object]) -> ContextUnitPayload:
    """Return a shallow copy of a unary RPC wire payload.

    SDK clients use this to preserve the full server response (including
    ``error`` / ``message`` envelope fields) instead of projecting through
    getters that inject false defaults for missing keys.
    """
    return dict(payload)


def parse_federated_execute(payload: ContextUnitPayload) -> FederatedExecuteRequest:
    """Parse a federated ``execute`` payload from the Router BiDi stream."""
    user_id = get_optional_str(payload, "user_id") or get_optional_str(payload, "caller_user")
    return FederatedExecuteRequest(
        request_id=get_str(payload, "request_id"),
        tool=get_str(payload, "tool"),
        args=get_dict(payload, "args"),
        caller_tenant=get_str(payload, "caller_tenant"),
        user_id=user_id,
    )
