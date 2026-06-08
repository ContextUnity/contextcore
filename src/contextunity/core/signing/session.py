"""Enterprise Shield session token backend."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from contextunity.core.logging import get_contextunit_logger
from contextunity.core.sdk.types import GrpcMetadata

from .hmac import HmacBackend

if TYPE_CHECKING:
    from contextunity.core.tokens import ContextToken

logger = get_contextunit_logger(__name__)


class SessionTokenBackend:
    """Enterprise mode backend using Shield-issued session tokens."""

    _project_id: str
    _token: str
    _kid: str
    _expires_at: float
    _shield_url: str
    _hmac_backend: HmacBackend

    def __init__(
        self,
        project_id: str,
        session_token: str,
        kid: str,
        expires_at: float,
        shield_url: str,
        hmac_backend: HmacBackend,
    ) -> None:
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

    def get_auth_metadata(self) -> GrpcMetadata:
        if time.time() > self._expires_at - 300:
            try:
                from contextunity.core.signing import _request_session_token

                new_token, new_kid, new_exp = _request_session_token(
                    self._project_id, self._shield_url, self._hmac_backend
                )
                self.update_token(new_token, new_kid, new_exp)
                logger.debug("Successfully refreshed session token for %s", self._project_id)
            except Exception as e:
                logger.error("Failed to refresh session token: %s", e)

        return (("authorization", f"Bearer {self._token}"),)

    def create_grpc_metadata(self, token: ContextToken | str) -> GrpcMetadata:
        if isinstance(token, str):
            if not token.startswith("Bearer "):
                return (("authorization", f"Bearer {token}"),)
            return (("authorization", token),)

        from contextunity.core.signing import _request_session_token

        new_token, _, _ = _request_session_token(
            self._project_id,
            self._shield_url,
            self._hmac_backend,
            requested_token=token,
        )
        return (("authorization", f"Bearer {new_token}"),)

    def update_token(self, new_token: str, new_kid: str, expires_at: float) -> None:
        self._token = new_token
        self._kid = new_kid
        self._expires_at = expires_at

    def verify(self, token_str: str) -> bytes | None:
        _ = token_str
        raise NotImplementedError("SessionTokenBackend only issues metadata, for verification use Ed25519Backend.")
