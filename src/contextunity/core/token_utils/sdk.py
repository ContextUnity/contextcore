"""SDK Client Utilities."""

from __future__ import annotations

from typing import Optional

import grpc

from ..signing import AuthBackend
from ..tokens import ContextToken
from .grpc import create_grpc_metadata_with_token


class TokenMetadataInterceptor(grpc.aio.UnaryUnaryClientInterceptor):
    """gRPC interceptor to automatically inject token into metadata."""

    def __init__(self, token: Optional[ContextToken] = None, backend: Optional[AuthBackend] = None):
        self.token = token
        self.backend = backend

    async def intercept_unary_unary(self, continuation, client_call_details, request):
        if self.token or self.backend:
            metadata = create_grpc_metadata_with_token(token=self.token, backend=self.backend)
            if client_call_details.metadata:
                metadata.extend(client_call_details.metadata)
            client_call_details = client_call_details._replace(metadata=metadata)
        return await continuation(client_call_details, request)
