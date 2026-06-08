"""SDK Client Utilities.

Provides a client-side gRPC interceptor to inject security and identity tokens
automatically into outgoing calls.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TypeGuard, TypeVar, override

import grpc

from ..sdk.types import GrpcUnaryUnaryClientContinuation
from ..signing import AuthBackend
from ..tokens import ContextToken
from .grpc import create_grpc_metadata_with_token

_RequestT = TypeVar("_RequestT")
_ResponseT = TypeVar("_ResponseT")


def _is_metadata_iterable(value: object) -> TypeGuard[Iterable[object]]:
    """Narrow raw gRPC metadata to an iterable of key/value pairs."""
    return value is not None and isinstance(value, Iterable)


def _is_metadata_pair(value: object) -> TypeGuard[tuple[object, object]]:
    if not isinstance(value, tuple):
        return False
    return value[0:1] != () and value[1:2] != () and value[2:3] == ()


class TokenMetadataInterceptor(grpc.aio.UnaryUnaryClientInterceptor):
    """Client-side gRPC interceptor that automatically attaches identity credentials.

    Injects the authorization token (ContextToken) or signature headers via the
    specified AuthBackend into the call metadata of all outgoing unary-unary RPCs.
    """

    token: ContextToken | None
    backend: AuthBackend | None

    def __init__(self, token: ContextToken | None = None, backend: AuthBackend | None = None):
        """Initialize the token metadata injector.

        Args:
            token: ContextToken containing identity and signature parameters.
            backend: Optional AuthBackend utilized for dynamic signature generation.
        """
        self.token = token
        self.backend = backend

    @staticmethod
    def _normalize_metadata(raw_metadata: object) -> list[tuple[str, str]]:
        """Normalize gRPC metadata structure into a list of string key-value tuples.

        Converts raw metadata iterables to a strict list of 2-tuples of string types.

        Args:
            raw_metadata: Raw iterable of metadata items.

        Returns:
            A list of (key, value) string tuples.
        """
        if not _is_metadata_iterable(raw_metadata):
            return []
        normalized: list[tuple[str, str]] = []
        metadata_items: Iterable[object] = raw_metadata
        for item in metadata_items:
            if _is_metadata_pair(item):
                key, value = item
                normalized.append((str(key), str(value)))
        return normalized

    @override
    async def intercept_unary_unary(
        self,
        continuation: GrpcUnaryUnaryClientContinuation[_RequestT, _ResponseT],
        client_call_details: grpc.aio.ClientCallDetails,
        request: _RequestT,
    ) -> grpc.aio.UnaryUnaryCall[_RequestT, _ResponseT]:
        """Intercept outgoing unary-unary calls to inject the security token.

        Modifies the client call details, attaching the authentication headers
        prefixed or resolved by the local ContextToken or AuthBackend.

        Args:
            continuation: The next handler or RPC endpoint runner in the pipeline.
            client_call_details: Object containing destination method, timeout, and metadata.
            request: The outgoing request protobuf message.

        Returns:
            The continuation call result.
        """
        if self.token or self.backend:
            metadata_entries = list(create_grpc_metadata_with_token(token=self.token, backend=self.backend))
            metadata_entries.extend(self._normalize_metadata(client_call_details.metadata))
            metadata = tuple(metadata_entries)
            replace_fn = getattr(client_call_details, "_replace", None)
            if callable(replace_fn):
                replaced_details = replace_fn(metadata=metadata)
                if isinstance(replaced_details, grpc.aio.ClientCallDetails):
                    client_call_details = replaced_details
        return await continuation(client_call_details, request)
