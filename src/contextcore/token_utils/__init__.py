"""Centralized token handling utilities for ContextUnity services.

This module provides unified token extraction and forwarding for:
- gRPC services (metadata)
- HTTP services (headers)
- SDK clients (metadata injection)

Tokens must be explicitly verified using `verify_token_string` or
`extract_and_verify_token_from_grpc_metadata`. Using `parse_token_string`
for security decisions is FORBIDDEN.
"""

from .grpc import (
    GRPC_AUTH_HEADER,
    GRPC_TOKEN_HEADER,
    create_grpc_metadata_with_token,
    extract_and_verify_token_from_grpc_metadata,
    extract_token_from_grpc_metadata,
)
from .http import (
    HTTP_AUTH_HEADER,
    HTTP_TOKEN_HEADER,
    build_verifier_backend_from_token_string,
    create_http_headers_with_token,
    extract_and_verify_token_from_http_request,
    extract_token_from_http_request,
    extract_token_string_from_http_request,
)
from .public_key import (
    fetch_project_public_key_async,
    fetch_project_public_key_sync,
)
from .sdk import TokenMetadataInterceptor
from .serialization import (
    parse_token_string,
    serialize_token,
    verify_token_string,
)

__all__ = [
    # gRPC utilities
    "extract_token_from_grpc_metadata",
    "extract_and_verify_token_from_grpc_metadata",
    "create_grpc_metadata_with_token",
    # HTTP utilities
    "extract_token_string_from_http_request",
    "extract_token_from_http_request",
    "extract_and_verify_token_from_http_request",
    "build_verifier_backend_from_token_string",
    "create_http_headers_with_token",
    # Public Key fetching
    "fetch_project_public_key_sync",
    "fetch_project_public_key_async",
    # SDK utilities
    "TokenMetadataInterceptor",
    # Serialization and Verification
    "serialize_token",
    "parse_token_string",
    "verify_token_string",
    # Constants
    "GRPC_AUTH_HEADER",
    "GRPC_TOKEN_HEADER",
    "HTTP_AUTH_HEADER",
    "HTTP_TOKEN_HEADER",
]
