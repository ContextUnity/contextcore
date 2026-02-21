"""Centralized token handling utilities for ContextUnity services.

This module provides unified token extraction and forwarding for:
- gRPC services (metadata)
- HTTP services (headers)
- SDK clients (metadata injection)

Token signing/verification delegates to SigningBackend (see signing.py).
Security is DISABLED by default. Install contextshield for production signing.
"""

from __future__ import annotations

import logging
from typing import Optional

import grpc

from .signing import SigningBackend, UnsignedBackend, get_signing_backend
from .tokens import ContextToken

logger = logging.getLogger(__name__)

# gRPC metadata keys
GRPC_AUTH_HEADER = "authorization"
GRPC_TOKEN_HEADER = "x-context-token"  # nosec B105

# HTTP header keys
HTTP_AUTH_HEADER = "HTTP_AUTHORIZATION"
HTTP_TOKEN_HEADER = "X-Context-Token"  # nosec B105


# =========================================
# gRPC Token Utilities
# =========================================


def extract_token_from_grpc_metadata(
    context: grpc.ServicerContext,
) -> Optional[ContextToken]:
    """Extract ContextToken from gRPC invocation metadata.

    Parses serialized token (JSON base64) to restore full ContextToken with permissions.

    Looks for token in:
    1. metadata['authorization'] (Bearer token)
    2. metadata['x-context-token'] (direct token)

    Args:
        context: gRPC servicer context with invocation_metadata()

    Returns:
        ContextToken if found, None otherwise

    Example:
        async def MyMethod(self, request, context):
            token = extract_token_from_grpc_metadata(context)
            if not token:
                context.abort(grpc.StatusCode.UNAUTHENTICATED, "Missing token")
    """
    try:
        metadata = dict(context.invocation_metadata())

        # Check Authorization header (Bearer token)
        auth_header = metadata.get(GRPC_AUTH_HEADER, "")
        if auth_header.startswith("Bearer "):
            token_str = auth_header[7:].strip()
            if token_str:
                # Parse serialized token (JSON base64) to restore full ContextToken
                return parse_token_string(token_str)

        # Check x-context-token header (direct token)
        token_str = metadata.get(GRPC_TOKEN_HEADER, "").strip()
        if token_str:
            # Parse serialized token (JSON base64) to restore full ContextToken
            return parse_token_string(token_str)

    except Exception as e:
        logger.warning("Failed to extract token from gRPC metadata: %s", e)

    return None


def create_grpc_metadata_with_token(
    token: Optional[ContextToken],
    additional_metadata: Optional[list[tuple[str, str]]] = None,
) -> list[tuple[str, str]]:
    """Create gRPC metadata list with ContextToken.

    Serializes full ContextToken (with permissions) for transmission.

    Args:
        token: ContextToken to include (None = no token)
        additional_metadata: Optional additional metadata tuples

    Returns:
        List of (key, value) tuples for gRPC metadata

    Example:
        token = ContextToken(token_id="abc", permissions=("read", "write"))
        metadata = create_grpc_metadata_with_token(token)
        response = await stub.Method(request, metadata=metadata)
    """
    metadata = []

    if token:
        # Serialize full token (with permissions) for transmission
        token_str = serialize_token(token)
        # Add token as Bearer token in authorization header
        metadata.append((GRPC_AUTH_HEADER, f"Bearer {token_str}"))
        # Also add as x-context-token for compatibility
        metadata.append((GRPC_TOKEN_HEADER, token_str))

    if additional_metadata:
        metadata.extend(additional_metadata)

    return metadata


# =========================================
# HTTP Token Utilities
# =========================================


def extract_token_from_http_request(request) -> Optional[ContextToken]:
    """Extract ContextToken from HTTP request (Django/FastAPI).

    Looks for token in:
    1. request.META['HTTP_AUTHORIZATION'] (Bearer token)
    2. request.META['HTTP_X_CONTEXT_TOKEN'] (direct token)
    3. request.headers.get('Authorization') (FastAPI)
    4. request.headers.get('X-Context-Token') (FastAPI)
    5. request.session.get('context_token') (Django session)
    6. request.context_token (if set by middleware)

    Args:
        request: Django HttpRequest or FastAPI Request object

    Returns:
        ContextToken if found, None otherwise

    Example:
        def my_view(request):
            token = extract_token_from_http_request(request)
            if not token:
                return HttpResponse("Unauthorized", status=401)
    """
    try:
        # Try Django-style META
        if hasattr(request, "META"):
            # Check Authorization header
            auth_header = request.META.get(HTTP_AUTH_HEADER, "")
            if auth_header.startswith("Bearer "):
                token_str = auth_header[7:].strip()
                if token_str:
                    return ContextToken(token_id=token_str, permissions=())

            # Check X-Context-Token header
            token_str = request.META.get(f"HTTP_{HTTP_TOKEN_HEADER.upper().replace('-', '_')}", "")
            if token_str:
                return ContextToken(token_id=token_str, permissions=())

        # Try FastAPI-style headers
        if hasattr(request, "headers"):
            auth_header = request.headers.get("authorization", "")
            if auth_header.startswith("Bearer "):
                token_str = auth_header[7:].strip()
                if token_str:
                    return ContextToken(token_id=token_str, permissions=())

            token_str = request.headers.get(HTTP_TOKEN_HEADER.lower(), "")
            if token_str:
                return ContextToken(token_id=token_str, permissions=())

        # Check Django session
        if hasattr(request, "session"):
            token_data = request.session.get("context_token")
            if token_data:
                if isinstance(token_data, dict):
                    return ContextToken(
                        token_id=token_data.get("token_id", ""),
                        permissions=tuple(token_data.get("permissions", [])),
                        exp_unix=token_data.get("exp_unix"),
                    )
                elif isinstance(token_data, ContextToken):
                    return token_data

        # Check request attribute (set by middleware)
        if hasattr(request, "context_token"):
            token = request.context_token
            if isinstance(token, ContextToken):
                return token

    except Exception as e:
        logger.warning("Failed to extract token from HTTP request: %s", e)

    return None


def create_http_headers_with_token(
    token: Optional[ContextToken],
    additional_headers: Optional[dict[str, str]] = None,
) -> dict[str, str]:
    """Create HTTP headers dict with ContextToken.

    Args:
        token: ContextToken to include (None = no token)
        additional_headers: Optional additional headers

    Returns:
        Dict of headers for HTTP requests

    Example:
        headers = create_http_headers_with_token(token)
        response = requests.get(url, headers=headers)
    """
    headers = {}

    if token:
        headers["Authorization"] = f"Bearer {token.token_id}"
        headers[HTTP_TOKEN_HEADER] = token.token_id

    if additional_headers:
        headers.update(additional_headers)

    return headers


# =========================================
# SDK Client Utilities
# =========================================


class TokenMetadataInterceptor(grpc.aio.UnaryUnaryClientInterceptor):
    """gRPC interceptor to automatically inject token into metadata.

    Usage:
        channel = create_channel("localhost:50051")  # TLS-aware
        interceptor = TokenMetadataInterceptor(token)
        intercepted_channel = grpc.aio.intercept_channel(channel, interceptor)
        stub = ServiceStub(intercepted_channel)
    """

    def __init__(self, token: Optional[ContextToken]):
        self.token = token

    async def intercept_unary_unary(self, continuation, client_call_details, request):
        """Intercept unary-unary calls to add token metadata."""
        if self.token:
            metadata = create_grpc_metadata_with_token(self.token)
            if client_call_details.metadata:
                metadata.extend(client_call_details.metadata)
            client_call_details = client_call_details._replace(metadata=metadata)
        return await continuation(client_call_details, request)


# =========================================
# Token Serialization
# =========================================


# Module-level backend cache (lazy, created on first use)
_default_backend: SigningBackend | None = None


def _get_default_backend() -> SigningBackend:
    """Get or create the default signing backend.

    Uses get_signing_backend() which auto-discovers contextshield
    if installed. Falls back to UnsignedBackend (dev mode).
    """
    global _default_backend
    if _default_backend is None:
        _default_backend = get_signing_backend()
    return _default_backend


def reset_default_backend() -> None:
    """Reset the cached default backend (for testing)."""
    global _default_backend
    _default_backend = None


def serialize_token(
    token: ContextToken,
    *,
    backend: SigningBackend | None = None,
) -> str:
    """Serialize ContextToken to string for network transmission.

    Uses the signing backend for Ed25519/KMS signing.
    When backend is not provided, uses auto-discovered backend
    (contextshield if installed, otherwise unsigned).

    Args:
        token: ContextToken to serialize
        backend: Explicit SigningBackend instance (preferred)

    Returns:
        Serialized token string (signed if backend supports it)
    """
    import json

    data = {
        "token_id": token.token_id,
        "permissions": list(token.permissions),
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

    signing = backend if backend is not None else _get_default_backend()
    signed = signing.sign(payload)
    return signed.serialize()


def parse_token_string(
    token_str: str,
    *,
    backend: SigningBackend | None = None,
) -> Optional[ContextToken]:
    """Parse serialized token string back to ContextToken.

    Supports:
    - Signed format: `kid.payload.signature` (Ed25519/KMS verified)
    - Unsigned format: `unsigned.payload.` (dev mode)
    - Plain token_id (legacy fallback) — no permissions, no tenants

    When a cryptographic backend is configured, tokens with invalid
    signatures are REJECTED (returns None).

    Args:
        token_str: Serialized token string
        backend: Explicit SigningBackend instance (preferred)

    Returns:
        ContextToken if valid, None otherwise
    """
    import base64
    import json

    if not token_str or not token_str.strip():
        return None

    token_str = token_str.strip()

    # Remove "Bearer " prefix if present
    if token_str.startswith("Bearer "):
        token_str = token_str[7:].strip()

    signing = backend if backend is not None else _get_default_backend()

    # Determine if we have a real (non-unsigned) signing backend
    is_secure = not isinstance(signing, UnsignedBackend)

    # Try verification through backend
    if "." in token_str:
        verified_payload = signing.verify(token_str)
        if verified_payload is not None:
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
                )
            except (json.JSONDecodeError, KeyError, UnicodeDecodeError):
                pass

        # If secure backend is configured and verification failed, reject.
        # Do NOT fall through to unsigned fallback — that would allow
        # tampered or wrong-key tokens to bypass verification.
        if is_secure:
            logger.warning("Token signature verification failed with secure backend. Rejecting token.")
            return None

    # If secure backend is configured, we MUST reject all legacy/unsigned tokens.
    if is_secure:
        logger.warning("Unsigned or legacy token rejected in secure mode.")
        return None

    # Try bare base64 JSON (legacy unsigned)
    raw_token = token_str.rstrip(".")
    try:
        decoded = base64.b64decode(raw_token)
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
        )
    except Exception:
        pass

    # Fallback: plain token_id (legacy behavior for backward compatibility)
    return ContextToken(token_id=token_str, permissions=())


__all__ = [
    # gRPC utilities
    "extract_token_from_grpc_metadata",
    "create_grpc_metadata_with_token",
    # HTTP utilities
    "extract_token_from_http_request",
    "create_http_headers_with_token",
    # SDK utilities
    "TokenMetadataInterceptor",
    # Serialization
    "serialize_token",
    "parse_token_string",
    # Backend management
    "reset_default_backend",
    # Constants
    "GRPC_AUTH_HEADER",
    "GRPC_TOKEN_HEADER",
    "HTTP_AUTH_HEADER",
    "HTTP_TOKEN_HEADER",
]
