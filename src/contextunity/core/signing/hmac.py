"""Symmetric HMAC-SHA256 signing backend."""

from __future__ import annotations

import base64
import hashlib
import hmac
from typing import TYPE_CHECKING

from contextunity.core.exceptions import ConfigurationError
from contextunity.core.logging import get_contextunit_logger
from contextunity.core.sdk.types import GrpcMetadata

from .protocols import SignedPayload

if TYPE_CHECKING:
    from contextunity.core.tokens import ContextToken

logger = get_contextunit_logger(__name__)


class HmacBackend:
    """Symmetric HMAC-SHA256 signing backend for ContextUnity Basic (OpenSource)."""

    _project_id: str
    _secret: bytes
    _kid: str

    def __init__(self, project_id: str, project_secret: str, kid: str = "hmac-001"):
        if not project_secret:
            raise ConfigurationError("HmacBackend requires a project_secret")
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

        parts = token_str.strip().rsplit(".", 2)
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

    def get_auth_metadata(self) -> GrpcMetadata:
        from contextunity.core.permissions import Permissions
        from contextunity.core.token_utils.serialization import serialize_token
        from contextunity.core.tokens import ProjectBound, TokenBuilder

        token = TokenBuilder().mint_root(
            user_ctx={},
            permissions=[
                Permissions.SHIELD_SESSION_TOKEN_ISSUE,
                Permissions.SHIELD_PROJECT_KEY_ROTATE,
            ],
            ttl_s=3600,
            project_binding=ProjectBound(self._project_id),
            allowed_tenants=(self._project_id,),
            user_id="system",
            agent_id=f"project:{self._project_id}",
        )

        return (("authorization", f"Bearer {serialize_token(token, backend=self)}"),)

    def create_grpc_metadata(self, token: ContextToken | str) -> GrpcMetadata:
        if isinstance(token, str):
            if not token.startswith("Bearer "):
                return (("authorization", f"Bearer {token}"),)
            return (("authorization", token),)

        from contextunity.core.token_utils.serialization import serialize_token

        token_str = serialize_token(token, backend=self)
        return (("authorization", f"Bearer {token_str}"),)
