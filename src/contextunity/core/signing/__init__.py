"""Signing backend interface for ContextUnity.

Public surface:
- ``AuthBackend`` / ``VerifierBackend`` protocols
- ``SignedPayload`` wire format
- ``HmacBackend`` (OpenSource symmetric mode)
- ``SessionTokenBackend`` (Enterprise Shield mode)
- ``get_signing_backend`` / ``set_signing_backend`` factory + singleton
"""

from __future__ import annotations

from .hmac import HmacBackend
from .protocols import AuthBackend, SignedPayload, VerifierBackend
from .registry import get_signing_backend, reset_signing_backend, set_signing_backend
from .service_auth import configure_service_signing_backend
from .session import SessionTokenBackend
from .shield_client import request_session_token as _request_session_token

__all__ = [
    "SignedPayload",
    "AuthBackend",
    "VerifierBackend",
    "SessionTokenBackend",
    "configure_service_signing_backend",
    "HmacBackend",
    "get_signing_backend",
    "set_signing_backend",
    "reset_signing_backend",
    "_request_session_token",
]
