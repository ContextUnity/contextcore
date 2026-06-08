"""Token parsing and verification utilities."""

from __future__ import annotations

import base64
from json import JSONDecodeError
from typing import Protocol, runtime_checkable

from contextunity.core.parsing import json_dumps, json_loads
from contextunity.core.types import JsonValue, is_json_value
from pydantic import ValidationError

from ..logging import get_contextunit_logger
from ..tokens import ContextToken
from .contracts import TokenPayloadDict, TokenSessionDict, is_token_payload_dict

logger = get_contextunit_logger(__name__)


@runtime_checkable
class _SerializedToken(Protocol):
    """Represent and manage Serialized Token logic within the system."""

    def serialize(self) -> str: ...


@runtime_checkable
class LocalSigningBackend(Protocol):
    """Protocol for components capable of locally signing cryptographic payloads."""

    def sign(self, payload: bytes) -> _SerializedToken: ...


@runtime_checkable
class TokenVerifier(Protocol):
    """Protocol for components capable of verifying cryptographic token signatures."""

    def verify(self, token_str: str) -> bytes | None: ...


def _string_tuple(values: list[str] | None) -> tuple[str, ...]:
    return tuple(values) if values is not None else ()


def _parse_json(raw: bytes | str) -> JsonValue:
    """Parse verified token bytes through the L1/L2 JSON boundary."""
    loaded = json_loads(raw)
    if is_json_value(loaded):
        return loaded
    return repr(loaded)


def token_from_payload_dict(data: TokenPayloadDict) -> ContextToken:
    """Build a ContextToken from a decoded payload mapping."""
    token_id = data.get("token_id")
    if not isinstance(token_id, str):
        raise ValueError("token payload missing token_id")

    provenance_raw = data.get("provenance")
    if provenance_raw is None:
        provenance_raw = data.get("trail")
    if provenance_raw is None:
        provenance_raw = data.get("delegation_chain")

    return ContextToken(
        token_id=token_id,
        permissions=_string_tuple(data.get("permissions")),
        allowed_tenants=_string_tuple(data.get("allowed_tenants")),
        exp_unix=data.get("exp_unix"),
        revocation_id=data.get("revocation_id"),
        user_id=data.get("user_id"),
        agent_id=data.get("agent_id"),
        user_namespace=data.get("user_namespace", "default"),
        provenance=_string_tuple(provenance_raw),
    )


def token_from_session_dict(data: TokenSessionDict) -> ContextToken:
    """Build a ContextToken from session-stored token data."""
    return ContextToken(
        token_id=data.get("token_id", ""),
        permissions=_string_tuple(data.get("permissions")),
        allowed_tenants=_string_tuple(data.get("allowed_tenants")),
        exp_unix=data.get("exp_unix"),
        user_id=data.get("user_id"),
        user_namespace=data.get("user_namespace") or "default",
        agent_id=data.get("agent_id", ""),
        provenance=_string_tuple(data.get("provenance")),
    )


def serialize_token(
    token: ContextToken,
    *,
    backend: LocalSigningBackend,
) -> str:
    """Serialize ContextToken to string for network transmission."""
    data: dict[str, str | list[str] | float | None] = {
        "token_id": token.token_id,
        "permissions": list(token.permissions),
        "provenance": list(token.provenance),
    }
    if token.allowed_tenants:
        data["allowed_tenants"] = list(token.allowed_tenants)
    if token.exp_unix is not None:
        data["exp_unix"] = token.exp_unix
    if token.revocation_id:
        data["revocation_id"] = token.revocation_id
    if token.user_id:
        data["user_id"] = token.user_id
    if token.agent_id:
        data["agent_id"] = token.agent_id
    if token.user_namespace != "default":
        data["user_namespace"] = token.user_namespace

    payload = json_dumps(data, sort_keys=True).encode()
    signed = backend.sign(payload)
    return signed.serialize()


def verify_token_string(
    token_str: str,
    verifier_backend: TokenVerifier,
) -> ContextToken | None:
    """Securely verify token string and parse it."""
    if not token_str or not token_str.strip():
        return None

    token_str = token_str.strip()
    if token_str.startswith("Bearer "):
        token_str = token_str[7:].strip()

    verified_payload = verifier_backend.verify(token_str)
    if verified_payload is None:
        token_preview = None
        try:
            parsed = parse_token_string(token_str)
            if parsed:
                token_preview = f"tenant={parsed.allowed_tenants}, id={parsed.token_id}"
        except Exception:
            pass
        logger.warning(f"Token signature verification failed. Rejecting token. [Preview: {token_preview}]")
        return None

    try:
        decoded = _parse_json(verified_payload)
        if not is_token_payload_dict(decoded):
            logger.warning("Failed to decode token payload after verification")
            return None
        return token_from_payload_dict(decoded)
    except (JSONDecodeError, UnicodeDecodeError, ValidationError):
        logger.warning("Failed to decode token payload after verification")
        return None


def parse_token_string(token_str: str) -> ContextToken | None:
    """UNSAFE: Parse serialized token string back to ContextToken WITHOUT VERIFICATION."""
    if not token_str or not token_str.strip():
        return None

    token_str = token_str.strip()
    if token_str.startswith("Bearer "):
        token_str = token_str[7:].strip()

    parts = token_str.rsplit(".", 2)
    if len(parts) >= 2:
        try:
            payload_idx = 1 if len(parts) == 3 else 0
            decoded = base64.b64decode(parts[payload_idx])
            data_obj = _parse_json(decoded)
            if is_token_payload_dict(data_obj):
                return token_from_payload_dict(data_obj)
        except Exception:
            pass

    return None
