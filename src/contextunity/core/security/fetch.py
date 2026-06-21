"""SSRF-safe HTTP fetch helper.

Builds on :func:`validate_safe_url` so that any service can fetch a
caller-supplied URL (model media parts, RAG sources, connectors) without
exposing the platform to server-side request forgery. This is the single
shared entry point for "fetch an untrusted URL" across ContextUnity.

Guarantees on every fetch:

- The URL is SSRF-validated (scheme allowlist + metadata/loopback/private/
  link-local block via DNS resolution) **before** any socket is opened.
- Redirects are disabled — a ``3xx`` to an internal host cannot bypass the
  upfront validation.
- Connect + read time is bounded by an explicit timeout.
- The response body is streamed and capped at ``max_bytes``.

Note on DNS rebinding: the hostname is resolved once for validation and again
by the HTTP client when it connects, so an attacker controlling an
authoritative resolver could in principle answer the two lookups differently.
Pinning the validated address into the connection is left as a follow-up; the
scheme + redirect + private-IP + size controls already block the common SSRF
vectors. Callers needing strict guarantees should fetch through an egress proxy.
"""

from __future__ import annotations

from collections.abc import Mapping

from contextunity.core.exceptions import ResourceFetchError, SecurityError
from contextunity.core.security.utils import validate_safe_url

__all__ = [
    "fetch_safe_url",
    "fetch_safe_url_sync",
    "DEFAULT_FETCH_TIMEOUT_S",
    "DEFAULT_MAX_FETCH_BYTES",
]

DEFAULT_FETCH_TIMEOUT_S: float = 15.0
DEFAULT_MAX_FETCH_BYTES: int = 25 * 1024 * 1024  # 25 MiB


async def fetch_safe_url(
    url: object,
    *,
    allow_local: bool = False,
    timeout_s: float = DEFAULT_FETCH_TIMEOUT_S,
    max_bytes: int = DEFAULT_MAX_FETCH_BYTES,
    headers: Mapping[str, str] | None = None,
) -> bytes:
    """Validate *url* against the SSRF policy, then fetch it with bounds.

    Args:
        url: Caller-supplied URL string (untrusted).
        allow_local: Permit loopback/private/metadata targets. Dev-only;
            defaults to ``False`` (fail closed).
        timeout_s: Total connect + read timeout in seconds.
        max_bytes: Hard cap on the response body size.
        headers: Optional request headers, for example a service User-Agent.

    Returns:
        The response body as raw bytes.

    Raises:
        SecurityError: The URL fails SSRF validation, the server answers with a
            redirect, or the body exceeds ``max_bytes``.
        ResourceFetchError: Transport failure, timeout, or non-2xx status. The
            message is safe to surface — it never echoes the resolved address.
    """
    safe_url = validate_safe_url(url, allow_local=allow_local)

    import httpx

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout_s), follow_redirects=False) as client:
            async with client.stream("GET", safe_url, headers=headers) as response:
                if response.is_redirect:
                    raise SecurityError("Refusing to follow a redirect while fetching a caller-supplied URL")
                if response.status_code >= 400:
                    raise ResourceFetchError(f"Upstream returned HTTP {response.status_code}")

                chunks: list[bytes] = []
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        raise SecurityError(f"Response body exceeded the {max_bytes}-byte limit")
                    chunks.append(chunk)
                return b"".join(chunks)
    except httpx.HTTPError as exc:
        # Transport/timeout failure — wrap without leaking internal details.
        raise ResourceFetchError(f"Failed to fetch remote resource: {type(exc).__name__}") from exc


def fetch_safe_url_sync(
    url: object,
    *,
    allow_local: bool = False,
    timeout_s: float = DEFAULT_FETCH_TIMEOUT_S,
    max_bytes: int = DEFAULT_MAX_FETCH_BYTES,
    headers: Mapping[str, str] | None = None,
) -> bytes:
    """Synchronous variant of :func:`fetch_safe_url` for sync ingestion paths."""
    safe_url = validate_safe_url(url, allow_local=allow_local)

    import httpx

    try:
        with httpx.Client(timeout=httpx.Timeout(timeout_s), follow_redirects=False) as client:
            with client.stream("GET", safe_url, headers=headers) as response:
                if response.is_redirect:
                    raise SecurityError("Refusing to follow a redirect while fetching a caller-supplied URL")
                if response.status_code >= 400:
                    raise ResourceFetchError(f"Upstream returned HTTP {response.status_code}")

                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        raise SecurityError(f"Response body exceeded the {max_bytes}-byte limit")
                    chunks.append(chunk)
                return b"".join(chunks)
    except httpx.HTTPError as exc:
        raise ResourceFetchError(f"Failed to fetch remote resource: {type(exc).__name__}") from exc
