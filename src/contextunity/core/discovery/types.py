"""Typed project registry records for discovery stores."""

from __future__ import annotations

from typing import Required, TypedDict

from contextunity.core.parsing import json_loads
from contextunity.core.types import JsonDict, is_json_dict


def parse_json_object(raw: str) -> JsonDict:
    """Parse JSON text into a ``JsonDict`` or return an empty mapping."""
    decoded = json_loads(raw)
    if is_json_dict(decoded):
        return decoded
    return {}


class ProjectRecord(TypedDict, total=False):
    """Shape of a project registry entry."""

    project_id: Required[str]
    owner_project: str
    tools: list[str]
    project_secret: str
    stream_secret: str
    stream_secret_expires_at: float
    public_key_b64: str
    public_key_kid: str
    api_keys: str | dict[str, str]


class ProjectKeyInfo(TypedDict, total=False):
    """Decrypted key material returned by ``get_project_key``."""

    project_secret: str
    public_key_b64: str
    public_key_kid: str
    api_keys: dict[str, str]
