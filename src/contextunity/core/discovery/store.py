"""ProjectStore contract and local fallback implementation."""

from __future__ import annotations

import time
from threading import RLock
from typing import TYPE_CHECKING, ClassVar, override

from contextunity.core.types import JsonDict

from ..logging import get_contextunit_logger
from .client import RedisNotAvailable
from .config import STREAM_SECRET_TTL, get_redis_url
from .contracts import ProjectStore
from .types import ProjectKeyInfo, ProjectRecord

if TYPE_CHECKING:
    from .redis_store import RedisProjectStore as RedisProjectStoreCls

logger = get_contextunit_logger(__name__)


class InMemoryProjectStore(ProjectStore):
    """Process-local project store used when Redis is unavailable.

    Uses a thread-safe dictionary with an RLock to manage project records,
    public keys, stream secrets, and key material.
    """

    _records: ClassVar[dict[str, ProjectRecord]] = {}
    _lock: ClassVar[RLock] = RLock()

    _stream_secret_ttl: float

    def __init__(self, *, stream_secret_ttl: float = STREAM_SECRET_TTL) -> None:
        """Initialize the in-memory project store with a stream secret TTL.

        Args:
            stream_secret_ttl: Time-to-live in seconds for stream secrets.
        """
        self._stream_secret_ttl = stream_secret_ttl

    @override
    def register(
        self,
        project_id: str,
        *,
        owner_project: str | None = None,
        tools: list[str] | None = None,
        project_secret: str | None = None,
        public_key_b64: str | None = None,
        public_key_kid: str | None = None,
        api_keys: dict[str, str] | None = None,
    ) -> bool:
        """Register or update a project record in local memory."""
        owner = owner_project or project_id
        with self._lock:
            record = self._records.get(project_id, {"project_id": project_id})
            existing_owner = record.get("owner_project", "")
            if existing_owner and existing_owner != owner:
                logger.warning(
                    "Project registry: ownership conflict for '%s' — registered owner='%s', attempted owner='%s'",
                    project_id,
                    existing_owner,
                    owner,
                )
                return False

            record["owner_project"] = owner
            record["tools"] = tools or []
            if project_secret is not None:
                record["project_secret"] = project_secret
            if public_key_b64 is not None:
                record["public_key_b64"] = public_key_b64
            if public_key_kid is not None:
                record["public_key_kid"] = public_key_kid
            if api_keys is not None:
                record["api_keys"] = api_keys

            self._records[project_id] = record
            return True

    @override
    def verify_owner(self, project_id: str, claimed_owner: str) -> bool:
        """Verify if the claimed project id is the registered owner."""
        with self._lock:
            record = self._records.get(project_id)
            if not record:
                return True
            owner = record.get("owner_project", "")
            return not owner or owner == claimed_owner

    @override
    def list_projects(self) -> list[JsonDict]:
        """List registered projects.

        In the in-memory fallback store, this returns an empty list to keep public
        no-Redis dashboard behavior unchanged.

        Returns:
            list[JsonDict]: An empty list.
        """
        return []

    @override
    def update_public_key(self, project_id: str, public_key_b64: str, public_key_kid: str) -> bool:
        """Update cached public key material for a project.

        Args:
            project_id: The unique identifier of the project.
            public_key_b64: Base64-encoded public key.
            public_key_kid: The key identifier tag.

        Returns:
            bool: True once the update is applied successfully, False otherwise.
        """
        with self._lock:
            record = self._records.get(project_id, {"project_id": project_id})
            record["public_key_b64"] = public_key_b64
            record["public_key_kid"] = public_key_kid
            self._records[project_id] = record
            return True

    @override
    def update_stream_secret(self, project_id: str, stream_secret: str) -> bool:
        """Update and set an expiration time for the project stream secret.

        Args:
            project_id: The unique identifier of the project.
            stream_secret: The temporary stream authentication secret.

        Returns:
            bool: True once updated, False otherwise.
        """
        with self._lock:
            record = self._records.get(project_id, {"project_id": project_id})
            record["stream_secret"] = stream_secret
            record["stream_secret_expires_at"] = time.time() + self._stream_secret_ttl
            self._records[project_id] = record
            return True

    @override
    def get_stream_secret(self, project_id: str) -> str | None:
        """Retrieve the cached stream secret if it has not expired.

        Args:
            project_id: The unique identifier of the project.

        Returns:
            str | None: The stream secret string, or None if expired/not found.
        """
        with self._lock:
            record = self._records.get(project_id)
            if not record or "stream_secret" not in record:
                return None
            expires_at = float(record.get("stream_secret_expires_at") or 0)
            if expires_at and time.time() >= expires_at:
                return None
            stream_secret = record["stream_secret"]
            return str(stream_secret)

    @override
    def get_key_material(self, project_id: str) -> ProjectKeyInfo | None:
        """Retrieve key material and API keys registered for a project.

        Args:
            project_id: The unique identifier of the project.

        Returns:
            ProjectKeyInfo | None: A dictionary containing the project secret,
            public keys, and API keys, or None if the project record is not found.
        """
        with self._lock:
            record = self._records.get(project_id)
            if not record:
                return None

            result: ProjectKeyInfo = {}
            if "project_secret" in record:
                result["project_secret"] = str(record["project_secret"])
            if "public_key_b64" in record:
                result["public_key_b64"] = str(record["public_key_b64"])
            if "public_key_kid" in record:
                result["public_key_kid"] = str(record["public_key_kid"])
            api_keys_raw = record.get("api_keys")
            if isinstance(api_keys_raw, dict):
                result["api_keys"] = {str(key): str(value) for key, value in api_keys_raw.items()}
            return result or None

    @classmethod
    def clear(cls) -> None:
        """Clear all in-memory project records (used for test isolation)."""
        with cls._lock:
            cls._records.clear()


class FallbackProjectStore(ProjectStore):
    """Hybrid ProjectStore that delegates to Redis and falls back to memory.

    Allows the platform to survive transient Redis outages by proxying requests
    to a secondary, process-local in-memory store.
    """

    _primary: ProjectStore
    _fallback: InMemoryProjectStore

    def __init__(self, primary: ProjectStore, fallback: InMemoryProjectStore | None = None) -> None:
        """Initialize the fallback store wrapper.

        Args:
            primary: The primary store implementation (typically RedisProjectStore).
            fallback: Optional in-memory store to fall back on. Defaults to a shared singleton.
        """
        self._primary = primary
        self._fallback = fallback or InMemoryProjectStore()

    @override
    def register(
        self,
        project_id: str,
        *,
        owner_project: str | None = None,
        tools: list[str] | None = None,
        project_secret: str | None = None,
        public_key_b64: str | None = None,
        public_key_kid: str | None = None,
        api_keys: dict[str, str] | None = None,
    ) -> bool:
        """Register or update a project record."""
        try:
            return self._primary.register(
                project_id,
                owner_project=owner_project,
                tools=tools,
                project_secret=project_secret,
                public_key_b64=public_key_b64,
                public_key_kid=public_key_kid,
                api_keys=api_keys,
            )
        except Exception as exc:
            logger.warning("Project registry primary store failed for '%s': %s", project_id, exc)
            return self._fallback.register(
                project_id,
                owner_project=owner_project,
                tools=tools,
                project_secret=project_secret,
                public_key_b64=public_key_b64,
                public_key_kid=public_key_kid,
                api_keys=api_keys,
            )

    @override
    def verify_owner(self, project_id: str, claimed_owner: str) -> bool:
        """Verify owner against primary store, falling back to memory if needed."""
        try:
            return self._primary.verify_owner(project_id, claimed_owner)
        except Exception as exc:
            logger.warning("Project ownership primary store failed for '%s': %s", project_id, exc)
            return self._fallback.verify_owner(project_id, claimed_owner)

    @override
    def list_projects(self) -> list[JsonDict]:
        """List registered projects using the primary store.

        Returns:
            list[JsonDict]: A list of project record dictionaries,
            or an empty list on failure.
        """
        try:
            return self._primary.list_projects()
        except Exception as exc:
            logger.warning("Project registry primary list failed: %s", exc)
            return []

    @override
    def update_public_key(self, project_id: str, public_key_b64: str, public_key_kid: str) -> bool:
        """Update the public key in the primary store with fallback.

        Args:
            project_id: The unique identifier of the project.
            public_key_b64: Base64-encoded public key.
            public_key_kid: The key identifier tag.

        Returns:
            bool: True if successfully updated in either store, False otherwise.
        """
        try:
            return self._primary.update_public_key(project_id, public_key_b64, public_key_kid)
        except Exception as exc:
            logger.warning("Project public key primary store failed for '%s': %s", project_id, exc)
            return self._fallback.update_public_key(project_id, public_key_b64, public_key_kid)

    @override
    def update_stream_secret(self, project_id: str, stream_secret: str) -> bool:
        """Update stream secret in the primary store with fallback.

        Args:
            project_id: The unique identifier of the project.
            stream_secret: The temporary stream authentication secret.

        Returns:
            bool: True if updated, False otherwise.
        """
        try:
            return self._primary.update_stream_secret(project_id, stream_secret)
        except Exception as exc:
            logger.warning("Project stream secret primary store failed for '%s': %s", project_id, exc)
            return self._fallback.update_stream_secret(project_id, stream_secret)

    @override
    def get_stream_secret(self, project_id: str) -> str | None:
        """Retrieve stream secret from primary store with fallback.

        Args:
            project_id: The unique identifier of the project.

        Returns:
            str | None: The stream secret string, or None if expired/not found.
        """
        try:
            return self._primary.get_stream_secret(project_id)
        except Exception as exc:
            logger.warning("Project stream secret primary lookup failed for '%s': %s", project_id, exc)
            return self._fallback.get_stream_secret(project_id)

    @override
    def get_key_material(self, project_id: str) -> ProjectKeyInfo | None:
        """Retrieve project key material from primary store with fallback.

        Args:
            project_id: The unique identifier of the project.

        Returns:
            ProjectKeyInfo | None: A dictionary containing key material,
            or None if not found in either store.
        """
        try:
            return self._primary.get_key_material(project_id)
        except Exception as exc:
            logger.warning("Project key primary lookup failed for '%s': %s", project_id, exc)
            return self._fallback.get_key_material(project_id)


RedisProjectStore: type[RedisProjectStoreCls] | None = None
_project_store: ProjectStore | None = None


def _load_redis_store() -> type[RedisProjectStoreCls]:
    """Dynamically load the Redis-backed project store implementation.

    Imports `RedisProjectStore` on-demand to decouple dependency requirements and
    prevent circular import errors.

    Returns:
        The RedisProjectStore class object.
    """
    global RedisProjectStore
    if RedisProjectStore is None:
        from .redis_store import RedisProjectStore as LoadedRedisProjectStore

        RedisProjectStore = LoadedRedisProjectStore
    return RedisProjectStore


def _build_project_store(redis_url: str | None = None) -> ProjectStore:
    """Build and initialize a ProjectStore based on availability of Redis configuration.

    If Redis URL is present and connection succeeds, returns a FallbackProjectStore
    wrapping Redis. If Redis is unavailable, returns InMemoryProjectStore.

    Args:
        redis_url: Optional override connection URL.

    Returns:
        ProjectStore: A configured project store instance.
    """
    url = get_redis_url(redis_url)
    if not url:
        return InMemoryProjectStore()

    store_cls = _load_redis_store()
    try:
        redis_store = store_cls(url)
        return FallbackProjectStore(redis_store)
    except RedisNotAvailable:
        logger.warning("Project store: Redis unavailable, using in-memory fallback.")
        return InMemoryProjectStore()


def get_project_store(redis_url: str | None = None) -> ProjectStore:
    """Get the active singleton project store instance.

    If the project store has not been initialized yet, it builds one. If
    redis_url is explicitly provided, builds a new store instance instead.

    Args:
        redis_url: Optional connection URL to build a new instance.

    Returns:
        ProjectStore: The active ProjectStore instance.
    """
    global _project_store
    if redis_url is not None:
        return _build_project_store(redis_url)
    if _project_store is None:
        _project_store = _build_project_store()
    return _project_store


def set_project_store(store: ProjectStore) -> None:
    """Explicitly override the global project store instance.

    Args:
        store: The ProjectStore instance to set as the active store.
    """
    global _project_store
    _project_store = store


def reset_project_store() -> None:
    """Reset the global project store instance and clear in-memory project records.

    Used primarily to ensure isolation between test runs.
    """
    global _project_store
    _project_store = None
    InMemoryProjectStore.clear()
