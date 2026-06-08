"""gRPC token utilities — extract, verify, and inject ContextTokens in gRPC metadata.

Used by service interceptors to deserialize ``authorization`` metadata into
validated ``ContextToken`` instances.
"""

from __future__ import annotations

import grpc
from contextunity.core.grpc_metadata import (
    GRPC_AUTH_HEADER,
    extract_bearer_token,
    invocation_metadata_from_context,
)

from ..exceptions import ConfigurationError
from ..logging import get_contextunit_logger
from ..sdk.types import GrpcMetadata, GrpcMetadataEntry, TokenStringProvider
from ..signing import AuthBackend
from ..tokens import ContextToken
from .serialization import parse_token_string, verify_token_string

logger = get_contextunit_logger(__name__)

TokenProvider = ContextToken | str | TokenStringProvider


def extract_token_from_grpc_metadata(
    context: grpc.ServicerContext,
) -> ContextToken | None:
    """UNSAFE: Extract ContextToken from gRPC without verification."""
    try:
        token_str = extract_bearer_token(context)
        if token_str:
            return parse_token_string(token_str)
    except Exception as e:
        logger.warning("Failed to extract token from gRPC metadata: %s", e)
    return None


def extract_and_verify_token_from_grpc_metadata(
    context: grpc.ServicerContext,
    verifier_backend: AuthBackend,
) -> ContextToken | None:
    """Extract and securely verify ContextToken from gRPC metadata."""
    try:
        token_str = extract_bearer_token(context)
        if token_str:
            return verify_token_string(token_str, verifier_backend)
    except Exception as e:
        logger.warning("Failed to verify token from gRPC metadata: %s", e)
    return None


def create_grpc_metadata_with_token(
    token: ContextToken | str | None = None,
    additional_metadata: list[tuple[str, str]] | None = None,
    backend: AuthBackend | None = None,
) -> GrpcMetadata:
    """Create gRPC metadata list with token."""
    if backend is None:
        raise ConfigurationError("create_grpc_metadata_with_token requires an AuthBackend")

    if token is not None:
        metadata: list[GrpcMetadataEntry] = list(backend.create_grpc_metadata(token))
    else:
        metadata = list(backend.get_auth_metadata())

    if additional_metadata:
        metadata.extend(additional_metadata)

    return tuple(metadata)


def resolve_client_metadata(token_provider: TokenProvider) -> GrpcMetadata:
    """Resolve a token provider into a gRPC metadata list."""
    actual_token: ContextToken | str
    if isinstance(token_provider, ContextToken | str):
        actual_token = token_provider
    else:
        actual_token = token_provider()

    from ..signing import get_signing_backend

    backend = get_signing_backend()

    return tuple(backend.create_grpc_metadata(actual_token))


__all__ = [
    "GRPC_AUTH_HEADER",
    "extract_and_verify_token_from_grpc_metadata",
    "extract_bearer_token",
    "extract_token_from_grpc_metadata",
    "create_grpc_metadata_with_token",
    "invocation_metadata_from_context",
    "resolve_client_metadata",
]
