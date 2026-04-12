"""HTTP Token Utilities."""

from __future__ import annotations

from typing import Optional

from ..logging import get_contextunit_logger
from ..signing import AuthBackend
from ..tokens import ContextToken
from .public_key import fetch_project_public_key_sync
from .serialization import parse_token_string, serialize_token, verify_token_string

logger = get_contextunit_logger(__name__)

# HTTP header keys
HTTP_AUTH_HEADER = "HTTP_AUTHORIZATION"
HTTP_TOKEN_HEADER = "X-Context-Token"  # nosec B105


def extract_token_string_from_http_request(request) -> str:
    """Extract serialized token string from HTTP request headers/session."""
    if hasattr(request, "META"):
        auth_header = request.META.get(HTTP_AUTH_HEADER, "")
        if auth_header.startswith("Bearer "):
            token_str = auth_header[7:].strip()
            if token_str:
                return token_str

        token_str = request.META.get(f"HTTP_{HTTP_TOKEN_HEADER.upper().replace('-', '_')}", "")
        if token_str:
            return str(token_str).strip()

    if hasattr(request, "headers"):
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token_str = auth_header[7:].strip()
            if token_str:
                return token_str

        token_str = request.headers.get(HTTP_TOKEN_HEADER.lower(), "")
        if token_str:
            return str(token_str).strip()

    if hasattr(request, "session"):
        token_data = request.session.get("context_token")
        if isinstance(token_data, str) and token_data.strip():
            return token_data.strip()

    return ""


def extract_token_from_http_request(request) -> Optional[ContextToken]:
    """UNSAFE: Extract ContextToken from HTTP request without verification."""
    try:
        token_str = extract_token_string_from_http_request(request)
        if token_str:
            return parse_token_string(token_str)

        if hasattr(request, "session"):
            token_data = request.session.get("context_token")
            if token_data:
                if isinstance(token_data, dict):
                    return ContextToken(
                        token_id=token_data.get("token_id", ""),
                        permissions=tuple(token_data.get("permissions", [])),
                        allowed_tenants=tuple(token_data.get("allowed_tenants", [])),
                        exp_unix=token_data.get("exp_unix"),
                        user_id=token_data.get("user_id"),
                        user_namespace=token_data.get("user_namespace"),
                        agent_id=token_data.get("agent_id", ""),
                        provenance=tuple(token_data.get("provenance", [])),
                    )
                elif isinstance(token_data, ContextToken):
                    return token_data

        if hasattr(request, "context_token"):
            token = request.context_token
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
):
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
                )
                from ..discovery import update_project_public_key

                update_project_public_key(project_id, public_key_b64, returned_kid)
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
    request,
    verifier_backend: AuthBackend | None = None,
    *,
    shield_url: str = "",
    service_name: str = "service",
) -> Optional[ContextToken]:
    """Extract and securely verify ContextToken from HTTP request."""
    try:
        token_str = extract_token_string_from_http_request(request)
        if not token_str:
            if hasattr(request, "context_token") and isinstance(request.context_token, ContextToken):
                return request.context_token
            return None

        backend = verifier_backend or build_verifier_backend_from_token_string(
            token_str,
            shield_url=shield_url,
            service_name=service_name,
        )
        if backend is None:
            logger.warning("No verifier backend available for HTTP token")
            return None
        return verify_token_string(token_str, backend)
    except Exception as e:
        logger.warning("Failed to verify token from HTTP request: %s", e)
        return None


def create_http_headers_with_token(
    token: Optional[ContextToken] = None,
    additional_headers: Optional[dict[str, str]] = None,
    backend: Optional[AuthBackend] = None,
) -> dict[str, str]:
    """Create HTTP headers dict with token metadata."""
    headers = {}

    if backend is not None:
        if token is not None:
            headers["Authorization"] = f"Bearer {serialize_token(token, backend=backend)}"
        else:
            for k, v in backend.get_auth_metadata():
                headers[k.title()] = v
    elif token:
        raise ValueError("create_http_headers_with_token requires a backend")

    if additional_headers:
        headers.update(additional_headers)

    return headers
