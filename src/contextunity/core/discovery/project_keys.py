"""Project key material API — public-key cache update and lookup.
Wraps ``ProjectStore`` for Ed25519/HMAC key material exchange between
consumer projects and the platform (Shield ↔ Router registration).
"""

from __future__ import annotations

import secrets

from .store import get_project_store
from .types import ProjectKeyInfo


def update_project_public_key(
    project_id: str,
    public_key_b64: str,
    public_key_kid: str,
    *,
    redis_url: str | None = None,
) -> bool:
    """Update (or create) the cached public key material for a project.

    Args:
        project_id: The unique identifier of the project.
        public_key_b64: The base64-encoded Ed25519 public key.
        public_key_kid: The key identifier (KID) for the public key.
        redis_url: Optional explicit Redis connection URL.

    Returns:
        bool: True if the update was successful, False otherwise.
    """

    return get_project_store(redis_url).update_public_key(project_id, public_key_b64, public_key_kid)


def update_project_stream_secret(
    project_id: str,
    stream_secret: str,
    *,
    redis_url: str | None = None,
) -> bool:
    """Update the cached stream secret for a project-owned ToolExecutorStream.

    Args:
        project_id: The unique identifier of the project.
        stream_secret: The new stream secret.
        redis_url: Optional explicit Redis connection URL.

    Returns:
        bool: True if the update was successful, False otherwise.
    """

    return get_project_store(redis_url).update_stream_secret(project_id, stream_secret)


def get_project_stream_secret(
    project_id: str,
    *,
    redis_url: str | None = None,
) -> str | None:
    """Retrieve the cached stream secret for a project-owned ToolExecutorStream.

    Args:
        project_id: The unique identifier of the project.
        redis_url: Optional explicit Redis connection URL.

    Returns:
        str | None: The stream secret if it exists and is valid, otherwise None.
    """

    return get_project_store(redis_url).get_stream_secret(project_id)


def get_project_key(
    project_id: str,
    *,
    redis_url: str | None = None,
) -> ProjectKeyInfo | None:
    """Retrieve decrypted key material for a project.

    Args:
        project_id: The unique identifier of the project.
        redis_url: Optional explicit Redis connection URL.

    Returns:
        ProjectKeyInfo | None: The key information if found, otherwise None.
    """

    return get_project_store(redis_url).get_key_material(project_id)


def get_or_create_project_stream_secret(
    project_id: str,
    *,
    redis_url: str | None = None,
) -> str:
    """Return the existing stream secret, or generate and persist a new one.

    Idempotent registration paths (hash-match re-registration, project
    recovery after restart) reuse the existing secret so active
    ToolExecutorStream sessions reconnect with the same key. New
    projects get a fresh 256-bit URL-safe token on first registration.
    """

    existing = get_project_stream_secret(project_id, redis_url=redis_url)
    if existing:
        return existing
    new_secret = secrets.token_urlsafe(32)
    _ = update_project_stream_secret(project_id, new_secret, redis_url=redis_url)
    return new_secret


__all__ = [
    "ProjectKeyInfo",
    "get_project_key",
    "get_project_stream_secret",
    "get_or_create_project_stream_secret",
    "update_project_public_key",
    "update_project_stream_secret",
]
