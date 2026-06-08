"""Client-side gRPC error humanization for SDK callers.

Used by Router client, Brain client, and other outbound gRPC stubs so
``PlatformServiceError`` carries a single-line message instead of raw
``AioRpcError`` repr dumps.
"""

from __future__ import annotations

import contextlib
from collections.abc import Generator


def humanize_grpc_client_error(exc: Exception, *, service: str, rpc_name: str) -> str:
    """Extract a clean, one-line error message from a gRPC client exception.

    Attempts to extract the error details and gRPC status code, parsing out nested
    `AioRpcError` representations when present to present a user-friendly message.

    Args:
        exc: The gRPC client exception to parse.
        service: The name of the remote service (e.g., "Router").
        rpc_name: The name of the RPC method called.

    Returns:
        str: A formatted, human-readable error message.
    """
    details_fn = getattr(exc, "details", None)
    raw_details = details_fn() if callable(details_fn) else None
    details = raw_details if isinstance(raw_details, str) else None
    code_fn = getattr(exc, "code", None)
    code_obj = code_fn() if callable(code_fn) else None
    code_name = getattr(code_obj, "name", None) if code_obj is not None else None
    if not isinstance(code_name, str) or not code_name:
        code_name = "UNKNOWN"

    if details:
        clean: str = details
        for prefix in ("Unexpected RuntimeError: ", "Unexpected Exception: "):
            if clean.startswith(prefix):
                clean = clean[len(prefix) :]
                break
        if "<AioRpcError" in clean:
            idx = clean.find("<AioRpcError")
            cause = clean[:idx].rstrip(": ")
            nested_details_marker = 'details = "'
            nd_start = clean.find(nested_details_marker, idx)
            if nd_start != -1:
                nd_start += len(nested_details_marker)
                nd_end = clean.find('"', nd_start)
                nested_msg = clean[nd_start:nd_end] if nd_end != -1 else clean[nd_start : nd_start + 120]
                clean = f"{cause}: {nested_msg}" if cause else nested_msg
            elif cause:
                clean = cause
        return f"{service} {rpc_name} failed ({code_name}): {clean}"

    return f"{service} {rpc_name} failed ({code_name}): {exc}"


def wrap_client_error(service: str, rpc_name: str) -> contextlib.AbstractContextManager[None]:
    """Context manager to intercept gRPC client errors and raise a humanized PlatformServiceError.

    Args:
        service: The name of the remote service being called.
        rpc_name: The name of the RPC method being called.

    Returns:
        ContextManager: A context manager wrapping the gRPC call.

    Raises:
        PlatformServiceError: If a gRPC RpcError occurs, wrapping it with a clean message.
    """

    @contextlib.contextmanager
    def _wrapper() -> Generator[None]:
        try:
            yield
        except Exception as exc:
            import grpc
            from contextunity.core.exceptions import PlatformServiceError

            if isinstance(exc, grpc.RpcError):
                msg = humanize_grpc_client_error(exc, service=service, rpc_name=rpc_name)
                raise PlatformServiceError(msg) from exc
            raise

    return _wrapper()


__all__ = ["humanize_grpc_client_error", "wrap_client_error"]
