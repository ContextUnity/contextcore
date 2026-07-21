"""Runtime-fenced Redis snapshot and wake-up hint transport."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol

from contextunity.core.discovery.async_client import (
    AsyncRedisCommandClient,
    RedisCommandPart,
    RedisResponse,
)
from contextunity.core.discovery.config import redis_key
from contextunity.core.logging import get_contextunit_logger

from .config import ResolvedServiceDegradationConfig
from .models import ServiceDegradationHint, ServiceDegradationSnapshot, ServiceRuntimeIdentity

logger = get_contextunit_logger(__name__)

_WRITE_SNAPSHOT_LUA = """
local raw = redis.call('get', KEYS[1])
if not raw then return 0 end
local ok, record = pcall(cjson.decode, raw)
if not ok or record['runtime_id'] ~= ARGV[1] then return 0 end
redis.call('setex', KEYS[2], tonumber(ARGV[2]), ARGV[3])
redis.call('publish', KEYS[3], ARGV[4])
return 1
"""

_READ_SNAPSHOT_LUA = """
local raw = redis.call('get', KEYS[1])
if not raw then return {'stale_runtime'} end
local ok, record = pcall(cjson.decode, raw)
if not ok or record['runtime_id'] ~= ARGV[1] then return {'stale_runtime'} end
local snapshot = redis.call('get', KEYS[2])
if not snapshot then return {'absent'} end
return {'snapshot', snapshot}
"""


@dataclass(frozen=True, slots=True)
class SnapshotReadResult:
    """Closed reader result; only a valid empty snapshot may indicate recovery."""

    state: Literal["absent", "invalid", "stale_runtime", "valid"]
    snapshot: ServiceDegradationSnapshot | None = None

    @classmethod
    def absent(cls) -> "SnapshotReadResult":
        return cls(state="absent")

    @classmethod
    def invalid(cls) -> "SnapshotReadResult":
        return cls(state="invalid")

    @classmethod
    def stale_runtime(cls) -> "SnapshotReadResult":
        return cls(state="stale_runtime")

    @classmethod
    def valid(cls, snapshot: ServiceDegradationSnapshot) -> "SnapshotReadResult":
        return cls(state="valid", snapshot=snapshot)


class _AsyncRedis(Protocol):
    async def eval(
        self,
        script: str,
        numkeys: int,
        *args: RedisCommandPart,
    ) -> RedisResponse: ...

    async def aclose(self) -> None: ...


def snapshot_key(identity: ServiceRuntimeIdentity) -> str:
    return ":".join(
        (
            "contextunity",
            "service-degradation",
            "v1",
            identity.environment,
            identity.service,
            identity.instance,
            str(identity.runtime_id),
        )
    )


class RedisServiceDegradationStore:
    """Persist full snapshots only while the matching registry runtime is live."""

    def __init__(
        self,
        *,
        client: _AsyncRedis,
        config: ResolvedServiceDegradationConfig,
    ) -> None:
        self._client = client
        self._config = config

    async def write_snapshot(self, snapshot: ServiceDegradationSnapshot) -> bool:
        payload = snapshot.model_dump_json()
        if len(payload.encode("utf-8")) > self._config.max_snapshot_bytes:
            logger.warning("Service degradation snapshot exceeds configured payload cap")
            return False
        identity = snapshot.identity
        hint = ServiceDegradationHint(
            identity=identity,
            revision=snapshot.revision,
        ).model_dump_json()
        result = await self._client.eval(
            _WRITE_SNAPSHOT_LUA,
            3,
            redis_key(identity.service, identity.instance),
            snapshot_key(identity),
            f"contextunity:service-degradation:v1:{identity.environment}:changed",
            str(identity.runtime_id),
            self._config.snapshot_ttl_seconds,
            payload,
            hint,
        )
        return result == 1

    async def read_snapshot(
        self,
        identity: ServiceRuntimeIdentity,
        *,
        now: datetime | None = None,
    ) -> SnapshotReadResult:
        result = await self._client.eval(
            _READ_SNAPSHOT_LUA,
            2,
            redis_key(identity.service, identity.instance),
            snapshot_key(identity),
            str(identity.runtime_id),
        )
        if not isinstance(result, list) or not result or not isinstance(result[0], str):
            logger.warning("Ignoring invalid service degradation read response")
            return SnapshotReadResult.invalid()
        state = result[0]
        if state == "absent" and len(result) == 1:
            return SnapshotReadResult.absent()
        if state == "stale_runtime" and len(result) == 1:
            return SnapshotReadResult.stale_runtime()
        if state != "snapshot" or len(result) != 2 or not isinstance(result[1], (str, bytes)):
            logger.warning("Ignoring invalid service degradation read response")
            return SnapshotReadResult.invalid()
        payload = result[1].encode("utf-8") if isinstance(result[1], str) else result[1]
        if len(payload) > self._config.max_snapshot_bytes:
            logger.warning("Ignoring oversized service degradation snapshot")
            return SnapshotReadResult.invalid()
        try:
            snapshot = ServiceDegradationSnapshot.model_validate_json(payload)
        except Exception as exc:
            logger.warning("Ignoring invalid service degradation snapshot: %s", type(exc).__name__)
            return SnapshotReadResult.invalid()
        if snapshot.identity != identity:
            logger.warning("Ignoring service degradation snapshot with mismatched runtime identity")
            return SnapshotReadResult.invalid()
        current = now or datetime.now(UTC)
        if (current - snapshot.updated_at).total_seconds() > self._config.snapshot_ttl_seconds:
            logger.warning("Ignoring expired service degradation snapshot")
            return SnapshotReadResult.invalid()
        return SnapshotReadResult.valid(snapshot)

    async def close(self) -> None:
        await self._client.aclose()


async def create_redis_degradation_store(
    config: ResolvedServiceDegradationConfig,
) -> RedisServiceDegradationStore:
    """Create a strict async Redis store without making projection startup-fatal."""
    client = AsyncRedisCommandClient(
        config.redis_url,
        connect_timeout=config.connect_timeout_seconds,
        io_timeout=config.io_timeout_seconds,
    )
    return RedisServiceDegradationStore(client=client, config=config)


__all__ = [
    "RedisServiceDegradationStore",
    "SnapshotReadResult",
    "create_redis_degradation_store",
    "snapshot_key",
]
