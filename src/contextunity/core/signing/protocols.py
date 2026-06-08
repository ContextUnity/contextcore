"""Signing protocols and wire-format types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from contextunity.core.sdk.types import GrpcMetadata

if TYPE_CHECKING:
    from contextunity.core.tokens import ContextToken


@dataclass(frozen=True)
class SignedPayload:
    """Result of a signing operation."""

    payload: str
    signature: str
    kid: str
    algorithm: str

    def serialize(self) -> str:
        """Serialize the signed payload to the standard 3-part wire format."""
        return f"{self.kid}.{self.payload}.{self.signature}"


@runtime_checkable
class VerifierBackend(Protocol):
    """Protocol for backends that can verify tokens."""

    def verify(self, token_str: str) -> bytes | None:
        """Verify a serialized token string and extract its raw payload."""
        ...


@runtime_checkable
class AuthBackend(Protocol):
    """Protocol for all authentication/signing backends."""

    @property
    def algorithm(self) -> str:
        """Get the signing algorithm identifier (e.g., 'hmac', 'session_token')."""
        ...

    @property
    def active_kid(self) -> str:
        """Get the key identifier used for the active signing key."""
        ...

    @property
    def project_id(self) -> str:
        """Get the identifier of the project associated with this backend."""
        ...

    def get_auth_metadata(self) -> GrpcMetadata:
        """Generate gRPC authentication metadata containing a serialized authorization token."""
        ...

    def create_grpc_metadata(self, token: ContextToken | str) -> GrpcMetadata:
        """Serialize a specific token or raw token string into gRPC metadata."""
        ...

    def verify(self, token_str: str) -> bytes | None:
        """Verify token and return raw payload bytes."""
        ...
