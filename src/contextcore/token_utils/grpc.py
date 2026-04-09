"""gRPC Token Utilities."""

from __future__ import annotations

from typing import Optional

import grpc

from ..logging import get_context_unit_logger
from ..signing import AuthBackend
from ..tokens import ContextToken
from .serialization import parse_token_string, verify_token_string

logger = get_context_unit_logger(__name__)

# gRPC metadata keys
GRPC_AUTH_HEADER = "authorization"
GRPC_TOKEN_HEADER = "x-context-token"  # nosec B105


def extract_token_from_grpc_metadata(
    context: grpc.ServicerContext,
) -> Optional[ContextToken]:
    """UNSAFE: Extract ContextToken from gRPC without verification.

    FOR LOGGING ONLY. Security guards MUST use extract_and_verify_token_from_grpc_metadata().
    """
    try:
        metadata = dict(context.invocation_metadata())

        auth_header = metadata.get(GRPC_AUTH_HEADER, "")
        if auth_header.startswith("Bearer "):
            token_str = auth_header[7:].strip()
            if token_str:
                return parse_token_string(token_str)

        token_str = metadata.get(GRPC_TOKEN_HEADER, "").strip()
        if token_str:
            return parse_token_string(token_str)
    except Exception as e:
        logger.warning("Failed to extract token from gRPC metadata: %s", e)

    return None


def extract_and_verify_token_from_grpc_metadata(
    context: grpc.ServicerContext,
    verifier_backend: AuthBackend,
) -> Optional[ContextToken]:
    """Extract and securely verify ContextToken from gRPC metadata."""
    try:
        metadata = dict(context.invocation_metadata())

        auth_header = metadata.get(GRPC_AUTH_HEADER, "")
        if auth_header.startswith("Bearer "):
            token_str = auth_header[7:].strip()
            if token_str:
                return verify_token_string(token_str, verifier_backend)

        token_str = metadata.get(GRPC_TOKEN_HEADER, "").strip()
        if token_str:
            return verify_token_string(token_str, verifier_backend)
    except Exception as e:
        logger.warning("Failed to verify token from gRPC metadata: %s", e)

    return None


def create_grpc_metadata_with_token(
    token: Optional[ContextToken | str] = None,
    additional_metadata: Optional[list[tuple[str, str]]] = None,
    backend: Optional[AuthBackend] = None,
) -> list[tuple[str, str]]:
    """Create gRPC metadata list with token.

    Delegates completely to the provided AuthBackend which handles
    the specifics of local signing (HMAC) vs propagating pre-issued tokens (Shield).
    """
    if backend is None:
        raise ValueError("create_grpc_metadata_with_token requires a backend")

    if token is not None:
        metadata = backend.create_grpc_metadata(token)
    else:
        metadata = backend.get_auth_metadata()

    if additional_metadata:
        metadata.extend(additional_metadata)

    return metadata


def resolve_client_metadata(token_provider) -> list[tuple[str, str]]:
    """Resolve a token provider into a gRPC metadata list.

    Delegates to the active AuthBackend. Compatible with:
    - Pre-serialized token strings (SPOT wrapper)
    - Callable providers
    - ContextToken objects
    """
    actual_token = token_provider() if callable(token_provider) else token_provider

    from ..signing import get_signing_backend

    backend = get_signing_backend()

    return backend.create_grpc_metadata(actual_token)
