"""HTTP and token-payload contracts for REST/webhook boundaries."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol, TypedDict, TypeGuard, runtime_checkable

from contextunity.core.types import JsonDict, is_json_dict, is_object_dict


class TokenPayloadDict(TypedDict, total=False):
    """JSON payload embedded in a signed ContextToken."""

    token_id: str
    project_binding: JsonDict
    permissions: list[str]
    allowed_tenants: list[str]
    exp_unix: float
    iat: float
    revocation_id: str
    user_id: str
    agent_id: str
    user_namespace: str
    provenance: list[str]
    trail: list[str]
    delegation_chain: list[str]


def is_token_payload_dict(value: object) -> TypeGuard[TokenPayloadDict]:
    """Narrow decoded JSON to a token payload mapping."""
    if not is_object_dict(value):
        return False
    token_id = value.get("token_id")
    return isinstance(token_id, str)


class TokenSessionDict(TypedDict, total=False):
    """Session-stored token payload (Django/Flask)."""

    token_id: str
    project_binding: JsonDict
    permissions: list[str]
    allowed_tenants: list[str]
    exp_unix: float
    iat: float
    user_id: str
    user_namespace: str
    agent_id: str
    provenance: list[str]


def is_token_session_dict(value: object) -> TypeGuard[TokenSessionDict]:
    """Narrow session token data to a structured mapping."""
    if not is_json_dict(value):
        return False
    token_id = value.get("token_id")
    return isinstance(token_id, str)


@runtime_checkable
class HttpLikeRequest(Protocol):
    """Minimal HTTP request surface (Django WSGI/ASGI, Flask, Starlette)."""

    @property
    def META(self) -> Mapping[str, object]: ...

    @property
    def headers(self) -> Mapping[str, object]: ...

    @property
    def session(self) -> Mapping[str, object]: ...

    @property
    def context_token(self) -> object: ...


def request_meta(request: object) -> Mapping[str, object] | None:
    """Return request META mapping when present."""
    meta = getattr(request, "META", None)
    if is_object_dict(meta):
        return meta
    return None


def request_headers(request: object) -> Mapping[str, object] | None:
    """Return request headers mapping when present."""
    headers = getattr(request, "headers", None)
    if is_object_dict(headers):
        return headers
    return None


def request_session(request: object) -> Mapping[str, object] | None:
    """Return request session mapping when present."""
    session = getattr(request, "session", None)
    if is_object_dict(session):
        return session
    return None


def header_value(headers: Mapping[str, object], key: str) -> str:
    """Read a header value as string."""
    raw = headers.get(key, "")
    if isinstance(raw, bytes):
        return raw.decode(errors="ignore")
    if isinstance(raw, str):
        return raw
    return str(raw) if raw is not None else ""


__all__ = [
    "TokenPayloadDict",
    "is_token_payload_dict",
    "TokenSessionDict",
    "is_token_session_dict",
    "HttpLikeRequest",
    "request_meta",
    "request_headers",
    "request_session",
    "header_value",
]
