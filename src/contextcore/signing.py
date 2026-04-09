"""Signing backend interface for ContextUnity.

Provides the AuthBackend protocol — the interface that signing implementations
must satisfy. Actual implementations live in contextshield (Pro) and here.

contextcore (public) provides:
- AuthBackend Protocol (interface)
- SignedPayload dataclass (wire format)
- HmacBackend (OpenSource symmetric mode)
- SessionTokenBackend (Enterprise mode via Shield)
- get_signing_backend() factory

Security is ALWAYS enabled. The legacy UnsignedBackend is removed.

Wire format for HMAC: kid.payload_b64.signature_b64
Wire format for Ed25519: kid.payload_b64.signature_b64
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from .tokens import ContextToken

from .exceptions import ConfigurationError, SecurityError
from .logging import get_context_unit_logger

logger = get_context_unit_logger(__name__)


# =========================================
# Data types
# =========================================


@dataclass(frozen=True)
class SignedPayload:
    """Result of a signing operation."""

    payload: str
    signature: str
    kid: str
    algorithm: str

    def serialize(self) -> str:
        """Serialize to wire format: kid.payload.signature (always 3 parts)."""
        return f"{self.kid}.{self.payload}.{self.signature}"


# =========================================
# Protocol
# =========================================


@runtime_checkable
class AuthBackend(Protocol):
    """Protocol for all authentication/signing backends.

    Implementations must provide:
    - algorithm: string identifier (e.g. "hmac", "ed25519", "kms")
    - active_kid: current key identifier for rotation
    - project_id: the project this backend belongs to
    - get_auth_metadata(): generating token and metadata for gRPC/HTTP
    - verify(): verify and return payload, or None if invalid
    """

    @property
    def algorithm(self) -> str: ...

    @property
    def active_kid(self) -> str: ...

    @property
    def project_id(self) -> str: ...

    def get_auth_metadata(self) -> list[tuple[str, str]]:
        """Return gRPC metadata containing the serialized token."""
        ...

    def create_grpc_metadata(self, token: "ContextToken" | str) -> list[tuple[str, str]]:
        """Create gRPC metadata for a specific token, applying backend-specific logic."""
        ...

    def verify(self, token_str: str) -> bytes | None:
        """Verify token and return raw payload bytes.

        Args:
            token_str: serialized token string (kid.payload.signature)

        Returns:
            Raw payload bytes if valid, None if verification fails.
        """
        ...


# =========================================
# Enterprise Session Token Backend
# =========================================


class SessionTokenBackend:
    """Enterprise mode backend using Shield-issued session tokens.

    Does not sign locally. Relies on Shield to issue short-lived
    session tokens signed dynamically via PKI (Ed25519).
    """

    def __init__(
        self,
        project_id: str,
        session_token: str,
        kid: str,
        expires_at: float,
        shield_url: str,
        hmac_backend: HmacBackend,
    ):
        self._project_id = project_id
        self._token = session_token
        self._kid = kid
        self._expires_at = expires_at
        self._shield_url = shield_url
        self._hmac_backend = hmac_backend

    @property
    def algorithm(self) -> str:
        return "session_token"

    @property
    def project_id(self) -> str:
        return self._project_id

    @property
    def active_kid(self) -> str:
        return self._kid

    def get_auth_metadata(self) -> list[tuple[str, str]]:
        """Return metadata with token, lazily refreshing if close to expiry."""
        # Refresh if less than 5 minutes remaining
        if time.time() > self._expires_at - 300:
            try:
                new_token, new_kid, new_exp = _request_session_token(
                    self._project_id, self._shield_url, self._hmac_backend
                )
                self.update_token(new_token, new_kid, new_exp)
                logger.debug("Successfully refreshed session token for %s", self._project_id)
            except Exception as e:
                logger.error("Failed to refresh session token: %s", e)
                # Keep using old token and hope it hasn't hard-expired yet

        return [("authorization", f"Bearer {self._token}")]

    def create_grpc_metadata(self, token: "ContextToken" | str) -> list[tuple[str, str]]:
        """Create gRPC metadata with dual headers for Enterprise mode.

        - ``authorization``: Ed25519 SessionToken (project-level authn)
        - ``x-context-token``: HMAC-signed per-request ContextToken (user identity)

        The interceptor verifies ``authorization`` for project auth, then
        parses ``x-context-token`` for user identity — eliminating the need
        for unsigned metadata fallbacks.
        """
        if isinstance(token, str):
            if not token.startswith("Bearer "):
                return [("authorization", f"Bearer {token}")]
            return [("authorization", token)]

        # Project-level SessionToken in authorization header
        metadata = self.get_auth_metadata()

        # Per-request ContextToken (carries user_id) signed via HMAC
        from contextcore.token_utils.serialization import serialize_token

        user_token_str = serialize_token(token, backend=self._hmac_backend)
        metadata.append(("x-context-token", user_token_str))

        return metadata

    def update_token(self, new_token: str, new_kid: str, expires_at: float) -> None:
        self._token = new_token
        self._kid = new_kid
        self._expires_at = expires_at

    def verify(self, token_str: str) -> bytes | None:
        # SDK clients typically do not verify, they only send.
        # Router/Brain uses Ed25519Backend directly to verify.
        raise NotImplementedError("SessionTokenBackend only issues metadata, for verification use Ed25519Backend.")


# =========================================
# HMAC mode (basic open source security)
# =========================================


class HmacBackend:
    """Symmetric HMAC-SHA256 signing backend for ContextUnity Basic (OpenSource).

    Requires a project secret known to both the project and the Router.
    """

    def __init__(self, project_id: str, project_secret: str, kid: str = "hmac-001"):
        if not project_secret:
            raise ValueError("HmacBackend requires a project_secret")
        self._project_id = project_id
        self._secret = project_secret.encode()
        self._kid = f"{project_id}:{kid}"

    @property
    def algorithm(self) -> str:
        return "hmac"

    @property
    def project_id(self) -> str:
        return self._project_id

    @property
    def secret(self) -> str:
        """Raw project secret (used only during SDK bootstrap)."""
        return self._secret.decode()

    @property
    def active_kid(self) -> str:
        return self._kid

    def sign(self, payload: bytes) -> SignedPayload:
        payload_b64 = base64.b64encode(payload).decode()
        sig = hmac.new(self._secret, payload_b64.encode(), hashlib.sha256).digest()
        sig_b64 = base64.b64encode(sig).decode()
        return SignedPayload(
            payload=payload_b64,
            signature=sig_b64,
            kid=self._kid,
            algorithm=self.algorithm,
        )

    def verify(self, token_str: str) -> bytes | None:
        if not token_str or not token_str.strip():
            return None

        parts = token_str.strip().split(".")

        if len(parts) != 3:
            return None

        token_kid, payload_b64, sig_b64 = parts
        if token_kid != self._kid:
            logger.warning("Rejecting HMAC token with unexpected kid: %s", token_kid)
            return None

        if not sig_b64:
            return None

        try:
            expected_sig = hmac.new(self._secret, payload_b64.encode(), hashlib.sha256).digest()
            actual_sig = base64.b64decode(sig_b64)
            if not hmac.compare_digest(expected_sig, actual_sig):
                logger.warning("HMAC signature verification failed")
                return None
            return base64.b64decode(payload_b64)
        except Exception:
            logger.warning("HMAC payload base64 decode failed")
            return None

    def get_auth_metadata(self) -> list[tuple[str, str]]:
        from .permissions import Permissions
        from .tokens import TokenBuilder

        token = TokenBuilder().mint_root(
            user_ctx={},
            permissions=[
                Permissions.SHIELD_SESSION_TOKEN_ISSUE,
                Permissions.SHIELD_PROJECT_KEY_ROTATE,
            ],
            ttl_s=3600,
            allowed_tenants=(self._project_id,),
            user_id="system",
            agent_id=f"project:{self._project_id}",
        )

        # Serialize logic (inline to avoid loop)
        import json

        data = {
            "token_id": token.token_id,
            "permissions": list(token.permissions),
            "allowed_tenants": list(token.allowed_tenants),
            "user_id": token.user_id,
            "agent_id": token.agent_id,
            "user_namespace": token.user_namespace,
        }
        if token.exp_unix is not None:
            data["exp_unix"] = token.exp_unix
        if token.revocation_id:
            data["revocation_id"] = token.revocation_id

        payload = json.dumps(data, sort_keys=True).encode()
        signed = self.sign(payload)
        return [("authorization", f"Bearer {signed.serialize()}")]

    def create_grpc_metadata(self, token: "ContextToken" | str) -> list[tuple[str, str]]:
        if isinstance(token, str):
            if not token.startswith("Bearer "):
                return [("authorization", f"Bearer {token}")]
            return [("authorization", token)]

        from contextcore.token_utils.serialization import serialize_token

        token_str = serialize_token(token, backend=self)
        return [("authorization", f"Bearer {token_str}")]


# =========================================
# Internal Helpers
# =========================================


def _request_session_token(project_id: str, shield_url: str, hmac_backend: HmacBackend) -> tuple[str, str, float]:
    """Request a signed session token from Shield via gRPC.

    Returns:
        tuple of (session_token_str, kid, expires_at_unix)
    """
    from . import shield_pb2_grpc
    from .grpc_utils import create_channel_sync

    channel = create_channel_sync(shield_url)
    try:
        stub = shield_pb2_grpc.ShieldServiceStub(channel)
        metadata = hmac_backend.get_auth_metadata()

        from google.protobuf.json_format import MessageToDict

        from . import context_unit_pb2
        from .sdk.context_unit import ContextUnit as PydanticUnit

        unit = PydanticUnit(
            payload={"project_id": project_id},
            provenance=["core:issue_session_token"],
        )
        req = unit.to_protobuf(context_unit_pb2)

        resp = stub.IssueSessionToken(req, metadata=metadata, timeout=10.0)
        resp_dict = MessageToDict(resp.payload)
        session_token = resp_dict.get("session_token", "")
        kid = resp_dict.get("kid", "")
        expires_at = resp_dict.get("expires_at", 0.0)
        if not session_token or not kid or not expires_at:
            error_response = resp_dict.get("error")
            error_message = resp_dict.get("message")
            if error_response:
                raise SecurityError(
                    message=f"Shield denied IssueSessionToken: [{error_response}] {error_message}",
                    code="SHIELD_DENIED_ERROR",
                )

            raise SecurityError(
                message=f"Shield returned incomplete IssueSessionToken response for project '{project_id}'",
                code="SHIELD_INVALID_RESPONSE",
            )
        return session_token, kid, expires_at
    except Exception as e:
        import grpc

        if isinstance(e, grpc.RpcError):
            status_code = getattr(e, "code", lambda: None)()
            details = getattr(e, "details", lambda: "")()
            raise SecurityError(
                message=f"Shield RPC failed [{status_code.name if hasattr(status_code, 'name') else status_code}]: {details}",
                code="SHIELD_RPC_ERROR",
            ) from e
        raise
    finally:
        channel.close()


# =========================================
# Factory — global singleton
# =========================================

# The active backend is set once during bootstrap (from manifest project_id
# + CU_PROJECT_SECRET) and reused by all SDK clients.
_active_backend: AuthBackend | None = None


def set_signing_backend(backend: AuthBackend) -> None:
    """Set the global signing backend.

    Called by SDK bootstrap after reading the manifest project_id.
    All subsequent get_signing_backend() calls return this instance.
    """
    global _active_backend
    _active_backend = backend
    logger.info(
        "Signing backend set: %s (project=%s)",
        type(backend).__name__,
        getattr(backend, "project_id", "?"),
    )


def get_signing_backend(
    project_id: str | None = None,
    project_secret: str | None = None,
    shield_url: str | None = None,
) -> AuthBackend:
    """Get the signing backend for token operations.

    Resolution order:
    1. Return cached _active_backend (set by bootstrap / set_signing_backend)
    2. If explicit project_id + project_secret provided → create new backend
    3. Fallback: CU_PROJECT_SECRET env var (for service-side interceptors
       and dev environments without full bootstrap)

    project_id comes from the manifest (contextunity.project.yaml), NOT from
    a separate env var. Services that verify tokens get project_id from the
    token's composite kid.

    Args:
        project_id: Explicit project identifier (from manifest).
        project_secret: Explicit HMAC secret. Falls back to CU_PROJECT_SECRET env var.
        shield_url: Optional Shield gRPC URL. Falls back to CONTEXTSHIELD_GRPC_URL env var.

    Returns:
        AuthBackend instance.
    """
    # 1. Return cached backend if available and no explicit args
    if _active_backend is not None and project_id is None:
        return _active_backend

    if project_secret is None or shield_url is None:
        from contextcore.config import get_core_config

        config = get_core_config()
        if project_secret is None:
            project_secret = config.security.project_secret
        if shield_url is None:
            shield_url = config.shield_url

    if not project_id:
        raise ConfigurationError(
            message="No signing backend configured. Either:\n  1. Call set_signing_backend() during bootstrap, or\n  2. Pass project_id= and set CU_PROJECT_SECRET env var.",
            code="CONFIGURATION_ERROR",
        )
    if not project_secret:
        raise ConfigurationError(
            message="CU_PROJECT_SECRET is required. Set it via env var or pass project_secret= to get_signing_backend().",
            code="CONFIGURATION_ERROR",
        )

    # 2. Enterprise Mode (Shield-issued Session Tokens)
    if shield_url:
        hmac_backend = HmacBackend(project_id, project_secret)
        token, kid, expires_at = _request_session_token(project_id, shield_url, hmac_backend)
        backend = SessionTokenBackend(
            project_id=project_id,
            session_token=token,
            kid=kid,
            expires_at=expires_at,
            shield_url=shield_url,
            hmac_backend=hmac_backend,
        )
    else:
        # 3. Open Source Mode (Local HMAC Signing)
        backend = HmacBackend(project_id=project_id, project_secret=project_secret)

    # Cache for future calls
    set_signing_backend(backend)
    return backend


def reset_signing_backend() -> None:
    """Reset the global backend (for testing only)."""
    global _active_backend
    _active_backend = None


__all__ = [
    "SignedPayload",
    "AuthBackend",
    "SessionTokenBackend",
    "HmacBackend",
    "get_signing_backend",
    "set_signing_backend",
    "reset_signing_backend",
]
