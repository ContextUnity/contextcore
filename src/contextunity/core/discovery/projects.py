"""Project registry API — register, lookup, and deregister consumer projects.

Facade over ``ProjectStore``. **Legacy path:** ``contextunity:projects:*`` in Redis
stores key material and stream secrets written by Router during RegisterManifest.

Registration manifest state (graphs, tools, bundle hash) lives in
``router:registrations:*`` — see ``docs/architecture/project-tenant-registration.md``.
"""

from __future__ import annotations

from contextunity.core.types import JsonDict

from .store import get_project_store
from .types import ProjectKeyInfo, ProjectRecord


def register_project(
    project_id: str,
    *,
    tools: list[str] | None = None,
    redis_url: str | None = None,
    project_secret: str | None = None,
    public_key_b64: str | None = None,
    public_key_kid: str | None = None,
    api_keys: dict[str, str] | None = None,
) -> bool:
    """Register or update legacy project key material in the discovery store.

    Owner is always ``project_id``. Prefer persisting registration state under
    ``router:registrations:{project_id}``; this store remains for HMAC/stream
    material until the migration in the v1alpha7 tenant-scope plan completes.

    Args:
        project_id: The unique identifier of the project.
        tools: Optional list of enabled tool names for this project.
        redis_url: Optional explicit Redis connection URL.
        project_secret: Optional project HMAC secret.
        public_key_b64: Optional Ed25519 public key base64 string.
        public_key_kid: Optional Key ID (KID) of the public key.
        api_keys: Optional mapping of service API keys.

    Returns:
        bool: True if the registration or update succeeded, False otherwise.
    """

    return get_project_store(redis_url).register(
        project_id,
        owner_project=project_id,
        tools=tools,
        project_secret=project_secret,
        public_key_b64=public_key_b64,
        public_key_kid=public_key_kid,
        api_keys=api_keys,
    )


def verify_project_owner(
    project_id: str,
    *,
    redis_url: str | None = None,
) -> bool:
    """Verify that ``project_id`` owns itself in the legacy discovery store.

    Args:
        project_id: The unique identifier of the project.

    Returns:
        bool: True if unregistered or owner matches ``project_id``.
    """

    return get_project_store(redis_url).verify_owner(project_id, project_id)


def get_registered_projects(
    redis_url: str | None = None,
) -> list[JsonDict]:
    """List all registered projects for admin or dashboard introspection."""
    return get_project_store(redis_url).list_projects()


__all__ = [
    "ProjectKeyInfo",
    "ProjectRecord",
    "get_registered_projects",
    "register_project",
    "verify_project_owner",
]
