"""JSON/YAML external boundary for ContextUnity core.

Parse untrusted wire/config data through ``TypeAdapter(object)`` so pyright
never sees stdlib/PyYAML ``Any`` in application code. Serialize through
``pydantic_core.to_json`` (or stdlib ``json.dumps`` when canonical options
are required) so call sites stay on the boundary module.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import lru_cache
from typing import TextIO

from contextunity.core.types import WireValue


@lru_cache(maxsize=1)
def _object_adapter():
    from pydantic import TypeAdapter

    return TypeAdapter(object)


def json_loads(raw: bytes | str) -> WireValue:
    """Parse JSON text into an untyped wire value tree."""
    return _object_adapter().validate_json(raw)


def yaml_load(stream: TextIO) -> WireValue:
    """Parse YAML stream into an untyped wire value tree."""
    import yaml

    return _object_adapter().validate_python(yaml.safe_load(stream))


def json_dumps(
    value: object,
    *,
    sort_keys: bool = False,
    ensure_ascii: bool = True,
    indent: int | None = None,
    default: Callable[[object], object] | None = None,
) -> str:
    """Serialize a Python object to a JSON string."""
    if default is not None or sort_keys or indent is not None:
        import json

        if default is not None:
            return json.dumps(
                value,
                sort_keys=sort_keys,
                ensure_ascii=ensure_ascii,
                indent=indent,
                default=default,
            )
        return json.dumps(
            value,
            sort_keys=sort_keys,
            ensure_ascii=ensure_ascii,
            indent=indent,
        )

    from pydantic_core import to_json

    return to_json(value, ensure_ascii=ensure_ascii).decode()


__all__ = ["json_dumps", "json_loads", "yaml_load"]
