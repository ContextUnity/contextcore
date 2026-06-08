"""Typed Redis client adapter for discovery operations.

The ``redis-py`` stubs type ``.get()`` as ``Awaitable[Any] | Any`` because
the ``Redis`` class unifies sync and async.  This adapter narrows the return
types via ``isinstance`` checks so all downstream code receives clean
``str | None`` and ``list[str]``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from contextunity.core.types import is_object_list, is_object_pair

from ..exceptions import RedisConnectionError, RedisNotAvailable

if TYPE_CHECKING:
    import redis

__all__ = ["RedisConnectionError", "RedisNotAvailable", "SyncRedisClient"]


class _SyncRedisKeys(Protocol):
    def keys(self, pattern: str = "*", **kwargs: object) -> object: ...


class _SyncRedisScan(Protocol):
    def scan(
        self,
        cursor: int = 0,
        match: str | None = None,
        count: int | None = None,
        _type: str | None = None,
        **kwargs: object,
    ) -> object: ...


def _scan_redis_keys(reader: _SyncRedisKeys, pattern: str) -> object:
    return reader.keys(pattern)


def _scan_redis_page(
    reader: _SyncRedisScan,
    *,
    cursor: int,
    match: str | None,
    count: int | None,
) -> object:
    return reader.scan(cursor=cursor, match=match, count=count)


class SyncRedisClient:
    """Typed sync Redis client with ``decode_responses=True``.

    Wraps ``redis.Redis`` and exposes only the methods used by discovery,
    with accurate return types narrowed via ``isinstance`` checks.
    """

    def __init__(self, url: str) -> None:
        """Initialize the SyncRedisClient with a Redis connection URL.

        Args:
            url: The remote endpoint URL.

        Raises:
            RedisNotAvailable: If connection to the service is unavailable.
        """
        try:
            import redis as _redis
        except ImportError as exc:
            raise RedisNotAvailable from exc
        self._r: redis.Redis = _redis.from_url(
            url,
            decode_responses=True,
            socket_connect_timeout=3,
            socket_timeout=3,
        )

    # ── typed accessors ──────────────────────────────────────────

    def get(self, key: str) -> str | None:
        """Retrieve the string value associated with a key.

        Args:
            key: The Redis key to retrieve.

        Returns:
            str | None: The key value if it exists, otherwise None.
        """
        val: object = self._r.get(key)
        if val is None:
            return None
        return val if isinstance(val, str) else str(val)

    def keys(self, pattern: str) -> list[str]:
        """Find all keys matching the given pattern.

        Args:
            pattern: The glob-style pattern to search for (e.g., "service:*").

        Returns:
            list[str]: A list of matching key names.
        """
        raw: object = _scan_redis_keys(self._r, pattern)
        if not is_object_list(raw):
            return []
        return [item if isinstance(item, str) else str(item) for item in raw]

    def scan(
        self,
        *,
        cursor: int = 0,
        match: str | None = None,
        count: int | None = None,
    ) -> tuple[int, list[str]]:
        """Iterate Redis keys via ``SCAN`` with typed cursor/key batch results.

        Args:
            cursor: Scan cursor from a previous page (``0`` to start).
            match: Optional glob pattern filter.
            count: Optional hint for keys returned per page.

        Returns:
            tuple[int, list[str]]: The next cursor and key names from this page.
        """
        page: object = _scan_redis_page(self._r, cursor=cursor, match=match, count=count)
        if not is_object_pair(page):
            return 0, []
        cursor_obj, keys_obj = page
        if not isinstance(cursor_obj, int) or not is_object_list(keys_obj):
            return 0, []
        keys = [item if isinstance(item, str) else str(item) for item in keys_obj]
        return cursor_obj, keys

    # ── passthrough mutations (types are fine in stubs) ──────────

    def set(self, key: str, value: str) -> None:
        """Store a string value in Redis.

        Args:
            key: The Redis key under which the value will be stored.
            value: The string value to store.
        """
        _ = self._r.set(key, value)

    def setex(self, key: str, ttl: int, value: str) -> None:
        """Store a string value in Redis with a specified time-to-live expiration.

        Args:
            key: The Redis key under which the value will be stored.
            ttl: The expiration timeout in seconds.
            value: The string value to store.
        """
        _ = self._r.setex(key, ttl, value)

    def delete(self, key: str) -> None:
        """Remove a key and its value from the Redis store.

        Args:
            key: The Redis key to delete.
        """
        _ = self._r.delete(key)

    def close(self) -> None:
        """Close the underlying Redis client connection pool."""
        self._r.close()
