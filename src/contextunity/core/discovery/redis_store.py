"""Redis-backed ProjectStore implementation."""

from __future__ import annotations

import time
from json import JSONDecodeError
from typing import override

from ..exceptions import RedisConnectionError, TamperDetectedError
from ..logging import get_contextunit_logger
from ..parsing import json_dumps, json_loads
from ..types import JsonDict, is_object_dict
from .client import SyncRedisClient
from .config import PROJECTS_PREFIX, STREAM_SECRET_TTL, project_key
from .contracts import ProjectStore
from .crypto import decrypt, encrypt
from .types import ProjectKeyInfo, ProjectRecord, parse_json_object

logger = get_contextunit_logger(__name__)


class RedisProjectStore(ProjectStore):
    """Redis-backed project ownership and key material store."""

    _redis_url: str

    def __init__(self, redis_url: str) -> None:
        """Initialize the Redis-backed project store with a connection URL.

        Args:
            redis_url: The connection URL for the Redis server.
        """
        self._redis_url = redis_url
        client = SyncRedisClient(redis_url)
        client.close()

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
        """Register or update a project record in Redis."""
        owner = owner_project or project_id
        client = SyncRedisClient(self._redis_url)
        try:
            key = project_key(project_id)
            existing = client.get(key)

            value_dict: ProjectRecord = {
                "project_id": project_id,
                "owner_project": owner,
                "tools": tools or [],
            }

            if existing:
                data = parse_json_object(existing)
                owner_raw = data.get("owner_project", "")
                existing_owner = owner_raw if isinstance(owner_raw, str) else ""
                if existing_owner and existing_owner != owner:
                    logger.warning(
                        "Project registry: ownership conflict for '%s' — registered owner='%s', attempted owner='%s'",
                        project_id,
                        existing_owner,
                        owner,
                    )
                    return False
                self._preserve_existing_key_material(
                    value_dict, data, project_secret, public_key_b64, public_key_kid, api_keys
                )

            if project_secret is not None:
                value_dict["project_secret"] = encrypt(project_secret)
            if public_key_b64 is not None:
                value_dict["public_key_b64"] = public_key_b64
            if public_key_kid is not None:
                value_dict["public_key_kid"] = public_key_kid
            if api_keys is not None:
                value_dict["api_keys"] = encrypt(json_dumps(api_keys))

            client.set(key, json_dumps(value_dict))
            logger.info(
                "Project registry: registered '%s' owner_project='%s' tools=%s",
                project_id,
                owner,
                tools or [],
            )
            return True
        except Exception as exc:
            logger.warning("Project '%s' registry failed: %s", project_id, RedisConnectionError(exc, self._redis_url))
            raise
        finally:
            client.close()

    @override
    def verify_owner(self, project_id: str, claimed_owner: str) -> bool:
        """Verify whether ``claimed_owner`` owns the given project in Redis."""
        client = SyncRedisClient(self._redis_url)
        try:
            raw = client.get(project_key(project_id))
            if not raw:
                return True

            data = parse_json_object(raw)
            owner_raw = data.get("owner_project", "")
            owner = owner_raw if isinstance(owner_raw, str) else ""
            return not owner or owner == claimed_owner
        except Exception as exc:
            logger.warning(
                "Project '%s' ownership verification failed: %s",
                project_id,
                RedisConnectionError(exc, self._redis_url),
            )
            raise
        finally:
            client.close()

    @override
    def list_projects(self) -> list[JsonDict]:
        """List all registered projects from Redis.

        Returns:
            list[JsonDict]: A list of registered project record dictionaries.
        """
        client = SyncRedisClient(self._redis_url)
        try:
            projects: list[JsonDict] = []
            for key in client.keys(f"{PROJECTS_PREFIX}:*"):
                raw = client.get(key)
                if not raw:
                    continue
                try:
                    projects.append(parse_json_object(raw))
                except JSONDecodeError:
                    pass
            return projects
        except Exception as exc:
            logger.warning("Project registry list failed: %s", exc)
            raise
        finally:
            client.close()

    @override
    def update_public_key(self, project_id: str, public_key_b64: str, public_key_kid: str) -> bool:
        """Update the cached public key material in Redis.

        Args:
            project_id: The unique identifier of the project.
            public_key_b64: The base64-encoded Ed25519 public key.
            public_key_kid: The key identifier (KID) for the public key.

        Returns:
            bool: True if the update was successful, False otherwise.
        """
        client = SyncRedisClient(self._redis_url)
        try:
            data = self._load_record(client, project_id)
            data["public_key_b64"] = public_key_b64
            data["public_key_kid"] = public_key_kid
            client.set(project_key(project_id), json_dumps(data))
            return True
        except Exception as exc:
            logger.warning(
                "Project '%s' public key update failed: %s",
                project_id,
                RedisConnectionError(exc, self._redis_url),
            )
            raise
        finally:
            client.close()

    @override
    def update_stream_secret(self, project_id: str, stream_secret: str) -> bool:
        """Update the cached stream secret in Redis.

        Args:
            project_id: The unique identifier of the project.
            stream_secret: The new stream secret to cache.

        Returns:
            bool: True if the update was successful, False otherwise.
        """
        client = SyncRedisClient(self._redis_url)
        try:
            data = self._load_record(client, project_id)
            data["stream_secret"] = encrypt(stream_secret)
            data["stream_secret_expires_at"] = time.time() + STREAM_SECRET_TTL
            client.set(project_key(project_id), json_dumps(data))
            return True
        except Exception as exc:
            logger.warning(
                "Project '%s' stream secret update failed: %s",
                project_id,
                RedisConnectionError(exc, self._redis_url),
            )
            raise
        finally:
            client.close()

    @override
    def get_stream_secret(self, project_id: str) -> str | None:
        """Retrieve the cached stream secret from Redis if valid.

        Purges stale records if tampering is detected.

        Args:
            project_id: The unique identifier of the project.

        Returns:
            str | None: The decrypted stream secret if it exists and has not expired, otherwise None.
        """
        client = SyncRedisClient(self._redis_url)
        try:
            raw = client.get(project_key(project_id))
            if not raw:
                return None

            data = parse_json_object(raw)
            if "stream_secret" not in data:
                return None
            expires_raw = data.get("stream_secret_expires_at")
            expires_at = float(expires_raw) if isinstance(expires_raw, (int, float)) else 0.0
            if expires_at and time.time() >= expires_at:
                logger.warning("Project stream secret for '%s' expired; re-registration required", project_id)
                return None
            stream_secret_raw = data.get("stream_secret")
            if not isinstance(stream_secret_raw, str):
                return None
            return decrypt(stream_secret_raw)
        except TamperDetectedError:
            logger.warning(
                "Project stream secret for '%s' encrypted with old key — purging stale entry",
                project_id,
            )
            self._purge_record(project_id)
            return None
        except Exception as exc:
            logger.warning(
                "Project '%s' stream secret lookup failed: %s",
                project_id,
                RedisConnectionError(exc, self._redis_url),
            )
            raise
        finally:
            client.close()

    @override
    def get_key_material(self, project_id: str) -> ProjectKeyInfo | None:
        """Retrieve the decrypted project key material from Redis.

        Purges stale records if tampering is detected.

        Args:
            project_id: The unique identifier of the project.

        Returns:
            ProjectKeyInfo | None: The key information if found, otherwise None.
        """
        client = SyncRedisClient(self._redis_url)
        try:
            raw = client.get(project_key(project_id))
            if not raw:
                return None

            data = parse_json_object(raw)
            result: ProjectKeyInfo = {}
            project_secret_raw = data.get("project_secret")
            if isinstance(project_secret_raw, str):
                result["project_secret"] = decrypt(project_secret_raw)
            public_key_raw = data.get("public_key_b64")
            if isinstance(public_key_raw, str):
                result["public_key_b64"] = public_key_raw
            public_kid_raw = data.get("public_key_kid")
            if isinstance(public_kid_raw, str):
                result["public_key_kid"] = public_kid_raw
            api_keys_raw = data.get("api_keys")
            if isinstance(api_keys_raw, str):
                result["api_keys"] = self._decrypt_api_keys(project_id, api_keys_raw)
            return result
        except TamperDetectedError:
            logger.warning(
                "Project key data for '%s' encrypted with old key — purging stale entry",
                project_id,
            )
            self._purge_record(project_id)
            return None
        except Exception as exc:
            logger.warning("Project '%s' lookup failed: %s", project_id, RedisConnectionError(exc, self._redis_url))
            raise
        finally:
            client.close()

    @staticmethod
    def _preserve_existing_key_material(
        value_dict: ProjectRecord,
        data: JsonDict,
        project_secret: str | None,
        public_key_b64: str | None,
        public_key_kid: str | None,
        api_keys: dict[str, str] | None,
    ) -> None:
        """Preserve existing key material when updating other fields of a project record.

        Args:
            value_dict: The target project record to update.
            data: The existing raw project record dictionary.
            project_secret: The new project secret override, if any.
            public_key_b64: The new public key override, if any.
            public_key_kid: The new public key ID override, if any.
            api_keys: The new API keys override, if any.
        """
        project_secret_raw = data.get("project_secret")
        if project_secret is None and isinstance(project_secret_raw, str):
            value_dict["project_secret"] = project_secret_raw

        stream_secret_raw = data.get("stream_secret")
        if isinstance(stream_secret_raw, str):
            value_dict["stream_secret"] = stream_secret_raw

        stream_secret_expires_raw = data.get("stream_secret_expires_at")
        if isinstance(stream_secret_expires_raw, (float, int)):
            value_dict["stream_secret_expires_at"] = float(stream_secret_expires_raw)

        public_key_b64_raw = data.get("public_key_b64")
        if public_key_b64 is None and isinstance(public_key_b64_raw, str):
            value_dict["public_key_b64"] = public_key_b64_raw

        public_key_kid_raw = data.get("public_key_kid")
        if public_key_kid is None and isinstance(public_key_kid_raw, str):
            value_dict["public_key_kid"] = public_key_kid_raw

        api_keys_raw = data.get("api_keys")
        if api_keys is None and isinstance(api_keys_raw, str):
            value_dict["api_keys"] = api_keys_raw

    @staticmethod
    def _load_record(client: SyncRedisClient, project_id: str) -> JsonDict:
        """Load a project record from Redis.

        Args:
            client: The active Redis client.
            project_id: The unique identifier of the project.

        Returns:
            JsonDict: The project record dictionary, or a default dictionary.
        """
        existing = client.get(project_key(project_id))
        if existing:
            return parse_json_object(existing)
        return {"project_id": project_id}

    @staticmethod
    def _decrypt_api_keys(project_id: str, encrypted_api_keys: str) -> dict[str, str]:
        """Decrypt the stored API keys dictionary for a project.

        Args:
            project_id: The unique identifier of the project.
            encrypted_api_keys: The base64-encoded encrypted API keys string.

        Returns:
            dict[str, str]: The decrypted API keys mapping.
        """
        try:
            decrypted_api_keys = decrypt(encrypted_api_keys)
            if not decrypted_api_keys:
                return {}
            parsed = json_loads(decrypted_api_keys)
            if not is_object_dict(parsed):
                return {}
            return {str(key): str(value) for key, value in parsed.items() if isinstance(value, str)}
        except Exception as exc:
            logger.warning("Failed to decrypt or parse api_keys for project %s: %s", project_id, exc)
            return {}

    def _purge_record(self, project_id: str) -> None:
        """Purge a project record from Redis.

        Args:
            project_id: The unique identifier of the project to delete.
        """
        try:
            client = SyncRedisClient(self._redis_url)
            client.delete(project_key(project_id))
            client.close()
        except Exception:
            pass
