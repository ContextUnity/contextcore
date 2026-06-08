"""Value-level narrowing helpers (L1 → L2) for arbitrary ``object`` values.

Use ``contextunity.core.sdk.payload.get_*`` when reading keyed fields from
``ContextUnit`` wire payloads (L3). Use this module when narrowing a bare
``object`` after ``json_loads``, ORM rows, third-party API responses, or
``getattr`` results.
"""

from __future__ import annotations

from collections.abc import Awaitable
from typing import TypeGuard

from contextunity.core.types import JsonDict, JsonValue, is_json_dict, is_object_list

__all__ = [
    "await_object",
    "as_float",
    "as_int",
    "as_json_dict",
    "as_json_dict_list",
    "as_json_dict_map",
    "as_str",
    "as_str_list",
    "is_heterogeneous_tuple",
    "json_dict_list_as_json",
    "object_attr",
    "optional_str_field",
    "related_name",
    "str_list_as_json",
    "tuple_item_at",
    "tuple_len",
]


async def await_object(value: object) -> object:
    """Await when *value* is awaitable; otherwise return it unchanged."""
    if isinstance(value, Awaitable):
        from pydantic import TypeAdapter

        return TypeAdapter(object).validate_python(await value)
    return value


def is_heterogeneous_tuple(value: object) -> TypeGuard[tuple[object, ...]]:
    return isinstance(value, tuple)


def object_attr(obj: object, name: str) -> object:
    """Read an attribute without propagating ``getattr``'s ``Any``."""
    from pydantic import TypeAdapter

    bound: object = TypeAdapter(object).validate_python(getattr(obj, name))
    return bound


def related_name(parent: object, field: str) -> str:
    """Read ``parent.field.name`` for optional Django FK/M2O relations."""
    related = object_attr(parent, field)
    if related is None:
        return ""
    return as_str(object_attr(related, "name"))


def tuple_len(value: object) -> int:
    """Return tuple length for heterogeneous tuple objects at service boundaries."""
    if not is_heterogeneous_tuple(value):
        return 0
    return len(value)


def tuple_item_at(value: object, index: int, *, default: object = "") -> object:
    """Read a tuple index without propagating ``Unknown`` from heterogeneous tuples."""
    if not is_heterogeneous_tuple(value):
        return default
    try:
        from pydantic import TypeAdapter

        return TypeAdapter(object).validate_python(value[index])
    except IndexError:
        return default


def as_str(value: object, *, default: str = "") -> str:
    return value if isinstance(value, str) else default


def as_float(value: object, *, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return default
    return default


def as_int(value: object, *, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def as_str_list(value: object) -> list[str]:
    if not is_object_list(value):
        return []
    return [item if isinstance(item, str) else str(item) for item in value]


def as_json_dict(value: object) -> JsonDict:
    return value if is_json_dict(value) else {}


def as_json_dict_list(value: object) -> list[JsonDict]:
    if not is_object_list(value):
        return []
    out: list[JsonDict] = []
    for item in value:
        if is_json_dict(item):
            out.append(item)
    return out


def as_json_dict_map(value: object) -> dict[str, JsonDict]:
    root = as_json_dict(value)
    out: dict[str, JsonDict] = {}
    for key, item in root.items():
        if is_json_dict(item):
            out[key] = item
    return out


def optional_str_field(value: object, key: str) -> str | None:
    """Return ``value[key]`` as ``str`` when ``value`` is a JSON dict."""
    if not is_json_dict(value):
        return None
    field = value.get(key)
    return field if isinstance(field, str) else None


def str_list_as_json(values: list[str]) -> list[JsonValue]:
    return list(values)


def json_dict_list_as_json(values: list[JsonDict]) -> list[JsonValue]:
    packed: list[JsonValue] = []
    for item in values:
        packed.append(item)
    return packed
