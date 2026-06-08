"""HTTP token utilities — serialize, parse, and verify ContextTokens for REST/webhook flows.

Bridges the gRPC-native token model to HTTP ``Authorization`` headers
for Django views and external webhook endpoints.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..exceptions import ConfigurationError
from ..logging import get_contextunit_logger
from ..signing import AuthBackend
from ..tokens import ContextToken
from .contracts import (
    header_value,
    is_token_session_dict,
    request_headers,
    request_meta,
    request_session,
)
from .public_key import fetch_project_public_key_sync
from .serialization import (
    LocalSigningBackend,
    TokenVerifier,
    parse_token_string,
    serialize_token,
    token_from_session_dict,
    verify_token_string,
)

if TYPE_CHECKING:
    from ..config import SharedConfig

logger = get_contextunit_logger(__name__)

HTTP_AUTH_HEADER = "HTTP_AUTHORIZATION"
HTTP_TOKEN_HEADER = "X-Context-Token"  # nosec B105
HTTP_TOKEN_META_KEY = f"HTTP_{HTTP_TOKEN_HEADER.upper().replace('-', '_')}"


def _extract_bearer_from_auth_header(auth_header: str) -> str:
    if auth_header.startswith("Bearer "):
        token_str = auth_header[7:].strip()
        if token_str:
            return token_str
    return ""


def extract_token_string_from_http_request(request: object) -> str:
    """Extract serialized token string from HTTP request headers/session."""
    meta = request_meta(request)
    if meta is not None:
        auth_header = header_value(meta, HTTP_AUTH_HEADER)
        bearer = _extract_bearer_from_auth_header(auth_header)
        if bearer:
            return bearer

        token_str = header_value(meta, HTTP_TOKEN_META_KEY).strip()
        if token_str:
            return token_str

    headers = request_headers(request)
    if headers is not None:
        auth_header = header_value(headers, "authorization")
        bearer = _extract_bearer_from_auth_header(auth_header)
        if bearer:
            return bearer

        token_str = header_value(headers, HTTP_TOKEN_HEADER.lower()).strip()
        if token_str:
            return token_str

    session = request_session(request)
    if session is not None:
        token_data = session.get("context_token")
        if isinstance(token_data, str) and token_data.strip():
            return token_data.strip()

    return ""


def extract_token_from_http_request(request: object) -> ContextToken | None:
    """UNSAFE: Extract ContextToken from HTTP request without verification."""
    try:
        token_str = extract_token_string_from_http_request(request)
        if token_str:
            return parse_token_string(token_str)

        session = request_session(request)
        if session is not None:
            token_data = session.get("context_token")
            if token_data is not None:
                if is_token_session_dict(token_data):
                    return token_from_session_dict(token_data)
                if isinstance(token_data, ContextToken):
                    return token_data

        token = getattr(request, "context_token", None)
        if isinstance(token, ContextToken):
            return token

    except Exception as e:
        logger.warning("Failed to extract token from HTTP request: %s", e)

    return None


def build_verifier_backend_from_token_string(
    token_str: str,
    *,
    shield_url: str = "",
    service_name: str = "service",
    config: SharedConfig | None = None,
) -> TokenVerifier | None:
    """Build a verifier backend from a serialized token string."""
    parts = token_str.strip().rsplit(".", 2)
    if len(parts) != 3:
        return None

    kid = parts[0]
    if ":" not in kid:
        logger.warning("Rejecting token with legacy non-composite kid: %s", kid)
        return None

    project_id, key_version = kid.split(":", 1)

    from ..discovery import get_project_key

    key_data = get_project_key(project_id) or {}

    if "session" in key_version:
        public_key_b64 = key_data.get("public_key_b64")
        if not public_key_b64 and shield_url:
            try:
                public_key_b64, returned_kid = fetch_project_public_key_sync(
                    project_id,
                    kid,
                    shield_url,
                    provenance=f"{service_name.lower()}:http:fetch_public_key",
                    config=config,
                )
                from ..discovery import update_project_public_key

                _ = update_project_public_key(project_id, public_key_b64, returned_kid)
            except Exception as e:
                logger.warning("Failed to fetch public key from Shield for %s: %s", kid, e)
                return None

        if public_key_b64:
            try:
                from contextunity.core.ed25519 import Ed25519Backend

                return Ed25519Backend(public_key_b64=public_key_b64, kid=kid)
            except ImportError:
                logger.error("contextunity.shield not installed, cannot verify Ed25519 tokens")
                return None
        return None

    secret = key_data.get("project_secret")
    if not secret:
        return None

    from ..signing import HmacBackend

    return HmacBackend(project_id, project_secret=secret)


def extract_and_verify_token_from_http_request(
    request: object,
    verifier_backend: AuthBackend | None = None,
    *,
    shield_url: str = "",
    service_name: str = "service",
    config: SharedConfig | None = None,
) -> ContextToken | None:
    """Extract and securely verify ContextToken from HTTP request."""
    try:
        token_str = extract_token_string_from_http_request(request)
        if not token_str:
            context_token = getattr(request, "context_token", None)
            if isinstance(context_token, ContextToken):
                return context_token
            return None

        backend = verifier_backend or build_verifier_backend_from_token_string(
            token_str,
            shield_url=shield_url,
            service_name=service_name,
            config=config,
        )
        if backend is None:
            logger.warning("No verifier backend available for HTTP token")
            return None
        return verify_token_string(token_str, backend)
    except Exception as e:
        logger.warning("Failed to verify token from HTTP request: %s", e)
        return None


def create_http_headers_with_token(
    token: ContextToken | None = None,
    additional_headers: dict[str, str] | None = None,
    backend: AuthBackend | None = None,
) -> dict[str, str]:
    """Create HTTP headers dict with token metadata."""
    headers: dict[str, str] = {}

    if backend is not None:
        if token is not None:
            if not isinstance(backend, LocalSigningBackend):
                raise ConfigurationError("create_http_headers_with_token backend does not support local signing")
            headers["Authorization"] = f"Bearer {serialize_token(token, backend=backend)}"
        else:
            for k, v in backend.get_auth_metadata():
                headers[k.title()] = v if isinstance(v, str) else v.decode(errors="ignore")
    elif token:
        raise ConfigurationError("create_http_headers_with_token requires a backend")

    if additional_headers:
        headers.update(additional_headers)

    return headers
