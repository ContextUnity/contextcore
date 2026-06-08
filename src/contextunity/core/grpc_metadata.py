"""gRPC invocation metadata normalization (L0 wire boundary).

gRPC delivers ``invocation_metadata`` as a tuple of pairs, ``grpc.aio.Metadata``,
or occasionally a mapping — never reliably as ``dict(...)``. Use these helpers
at every read site instead of ``dict(context.invocation_metadata())``.
"""

from __future__ import annotations

from typing import Protocol

from contextunity.core.types import is_object_dict, is_object_iterable, is_object_pair


class GrpcInvocationContext(Protocol):
    """Minimal gRPC context surface for reading ``invocation_metadata``."""

    def invocation_metadata(self) -> object: ...


GRPC_AUTH_HEADER = "authorization"


def _normalize_auth_header(value: str | bytes | object) -> str:
    """Normalize a metadata header value to ``str``."""
    if isinstance(value, bytes):
        return value.decode(errors="ignore")
    if isinstance(value, str):
        return value
    return ""


def invocation_metadata_as_dict(raw_metadata: object) -> dict[str, str | bytes]:
    """Normalize gRPC invocation metadata to a string-keyed mapping."""
    if raw_metadata is None:
        return {}
    if is_object_dict(raw_metadata):
        metadata: dict[str, str | bytes] = {}
        for key, value in raw_metadata.items():
            if isinstance(value, (str, bytes)):
                metadata[str(key)] = value
        return metadata
    if isinstance(raw_metadata, (str, bytes)):
        return {}
    if is_object_iterable(raw_metadata):
        metadata = {}
        for entry_obj in raw_metadata:
            if not is_object_pair(entry_obj):
                continue
            key_raw, value_raw = entry_obj
            if isinstance(value_raw, (str, bytes)):
                metadata[str(key_raw)] = value_raw
        return metadata
    return {}


def invocation_metadata_from_context(context: GrpcInvocationContext) -> dict[str, str | bytes]:
    """Read and normalize ``context.invocation_metadata()``."""
    return invocation_metadata_as_dict(context.invocation_metadata())


def extract_bearer_token(context: GrpcInvocationContext) -> str:
    """Return the Bearer token string from ``authorization`` metadata, or ``\"\"``."""
    metadata = invocation_metadata_from_context(context)
    auth_header = _normalize_auth_header(metadata.get(GRPC_AUTH_HEADER, ""))
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    return ""


__all__ = [
    "GRPC_AUTH_HEADER",
    "GrpcInvocationContext",
    "extract_bearer_token",
    "invocation_metadata_as_dict",
    "invocation_metadata_from_context",
]
