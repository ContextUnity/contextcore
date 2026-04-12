"""Token parsing and verification utilities."""

from __future__ import annotations

import base64
import json
from typing import Optional

from ..logging import get_contextunit_logger
from ..signing import AuthBackend
from ..tokens import ContextToken

logger = get_contextunit_logger(__name__)


def serialize_token(
    token: ContextToken,
    *,
    backend: AuthBackend,
) -> str:
    """Serialize ContextToken to string for network transmission."""
    data = {
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

    payload = json.dumps(data, sort_keys=True).encode()
    if not hasattr(backend, "sign"):
        raise RuntimeError(f"Backend {backend.__class__.__name__} does not support local signing")
    signed = backend.sign(payload)
    return signed.serialize()


def verify_token_string(
    token_str: str,
    verifier_backend: AuthBackend,
) -> Optional[ContextToken]:
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
            from .serialization import parse_token_string  # local import to avoid issues, though we are in it

            parsed = parse_token_string(token_str)
            if parsed:
                token_preview = f"tenant={parsed.allowed_tenants}, id={parsed.token_id}"
        except Exception:
            pass
        logger.warning(f"Token signature verification failed. Rejecting token. [Preview: {token_preview}]")
        return None

    try:
        data = json.loads(verified_payload)
        return ContextToken(
            token_id=data["token_id"],
            permissions=tuple(data.get("permissions", [])),
            allowed_tenants=tuple(data.get("allowed_tenants", [])),
            exp_unix=data.get("exp_unix"),
            revocation_id=data.get("revocation_id"),
            user_id=data.get("user_id"),
            agent_id=data.get("agent_id"),
            user_namespace=data.get("user_namespace", "default"),
            provenance=tuple(data.get("provenance", data.get("trail", data.get("delegation_chain", [])))),
        )
    except (json.JSONDecodeError, KeyError, UnicodeDecodeError):
        logger.warning("Failed to decode token payload after verification")
        return None


def parse_token_string(token_str: str) -> Optional[ContextToken]:
    """UNSAFE: Parse serialized token string back to ContextToken WITHOUT VERIFICATION.

    FOR LOGGING ONLY.
    """
    if not token_str or not token_str.strip():
        return None

    token_str = token_str.strip()
    if token_str.startswith("Bearer "):
        token_str = token_str[7:].strip()

    parts = token_str.rsplit(".", 2)
    # if it's new signed format: kid.payload.signature
    if len(parts) >= 2:
        try:
            payload_idx = 1 if len(parts) == 3 else 0
            decoded = base64.b64decode(parts[payload_idx])
            data = json.loads(decoded)
            return ContextToken(
                token_id=data["token_id"],
                permissions=tuple(data.get("permissions", [])),
                allowed_tenants=tuple(data.get("allowed_tenants", [])),
                exp_unix=data.get("exp_unix"),
                revocation_id=data.get("revocation_id"),
                user_id=data.get("user_id"),
                agent_id=data.get("agent_id"),
                user_namespace=data.get("user_namespace", "default"),
                provenance=tuple(data.get("provenance", data.get("trail", data.get("delegation_chain", [])))),
            )
        except Exception:
            pass

    # Fallback: plain token_id
    return ContextToken(token_id=token_str, permissions=())
