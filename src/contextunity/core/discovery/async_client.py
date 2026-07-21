"""Small strictly typed async Redis command boundary for Core control-plane hints."""

from __future__ import annotations

import asyncio
import ssl
from contextlib import suppress
from dataclasses import dataclass
from urllib.parse import unquote, urlparse

RedisCommandPart = str | bytes | int | float
RedisResponse = str | int | bytes | None | list["RedisResponse"]


class RedisCommandError(ConnectionError):
    """Redis transport or RESP protocol failure at the typed boundary."""


_MAX_RESP_LINE_BYTES = 4_096
_MAX_RESP_BULK_BYTES = 65_536
_MAX_RESP_ARRAY_ITEMS = 256
_MAX_RESP_DEPTH = 8
_MAX_RESP_TOTAL_BYTES = 131_072


@dataclass(slots=True)
class _RespBudget:
    remaining_bytes: int = _MAX_RESP_TOTAL_BYTES
    remaining_items: int = _MAX_RESP_ARRAY_ITEMS

    def consume_bytes(self, count: int) -> None:
        if count < 0 or count > self.remaining_bytes:
            raise RedisCommandError("Redis response exceeds aggregate byte limit")
        self.remaining_bytes -= count

    def consume_items(self, count: int) -> None:
        if count < 0 or count > self.remaining_items:
            raise RedisCommandError("Redis response exceeds aggregate item limit")
        self.remaining_items -= count


@dataclass(frozen=True, slots=True)
class _RedisEndpoint:
    scheme: str
    host: str
    port: int
    unix_path: str
    username: str
    password: str
    database: int


def _parse_endpoint(url: str) -> _RedisEndpoint:
    parsed = urlparse(url)
    if parsed.scheme not in {"redis", "rediss", "unix"}:
        raise ValueError("Redis URL must use redis, rediss, or unix")
    database_text = parsed.path.lstrip("/") if parsed.scheme != "unix" else ""
    try:
        database = int(database_text) if database_text else 0
    except ValueError as exc:
        raise ValueError("Redis database path must be an integer") from exc
    if database < 0:
        raise ValueError("Redis database must be non-negative")
    unix_path = unquote(parsed.path) if parsed.scheme == "unix" else ""
    if parsed.scheme == "unix" and not unix_path:
        raise ValueError("unix Redis URL requires a socket path")
    return _RedisEndpoint(
        scheme=parsed.scheme,
        host=parsed.hostname or "127.0.0.1",
        port=parsed.port or 6379,
        unix_path=unix_path,
        username=unquote(parsed.username or ""),
        password=unquote(parsed.password or ""),
        database=database,
    )


def _encode_command(parts: tuple[RedisCommandPart, ...]) -> bytes:
    encoded: list[bytes] = []
    for part in parts:
        encoded.append(part if isinstance(part, bytes) else str(part).encode("utf-8"))
    chunks = [f"*{len(encoded)}\r\n".encode()]
    for part in encoded:
        chunks.extend((f"${len(part)}\r\n".encode(), part, b"\r\n"))
    return b"".join(chunks)


async def _read_response(
    reader: asyncio.StreamReader,
    *,
    budget: _RespBudget | None = None,
    depth: int = 0,
) -> RedisResponse:
    if depth > _MAX_RESP_DEPTH:
        raise RedisCommandError("Redis response exceeds nesting limit")
    active_budget = budget or _RespBudget()
    marker = await reader.readexactly(1)
    line = await reader.readline()
    if len(line) > _MAX_RESP_LINE_BYTES:
        raise RedisCommandError("Redis response line exceeds limit")
    active_budget.consume_bytes(1 + len(line))
    if not line.endswith(b"\r\n"):
        raise RedisCommandError("invalid Redis response terminator")
    body = line[:-2]
    if marker == b"+":
        return body.decode("utf-8")
    if marker == b"-":
        raise RedisCommandError(body.decode("utf-8", errors="replace"))
    if marker == b":":
        return int(body)
    if marker == b"$":
        length = int(body)
        if length == -1:
            return None
        if length < -1 or length > _MAX_RESP_BULK_BYTES:
            raise RedisCommandError("invalid or oversized Redis bulk response")
        active_budget.consume_bytes(length + 2)
        payload = await reader.readexactly(length)
        if await reader.readexactly(2) != b"\r\n":
            raise RedisCommandError("invalid Redis bulk response terminator")
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError:
            return payload
    if marker == b"*":
        count = int(body)
        if count == -1:
            return None
        if count < -1 or count > _MAX_RESP_ARRAY_ITEMS:
            raise RedisCommandError("invalid or oversized Redis array response")
        active_budget.consume_items(count)
        return [
            await _read_response(
                reader,
                budget=active_budget,
                depth=depth + 1,
            )
            for _ in range(count)
        ]
    raise RedisCommandError("unknown Redis response marker")


class AsyncRedisCommandClient:
    """Execute one bounded Redis command per connection with strict response types."""

    def __init__(
        self,
        url: str,
        *,
        connect_timeout: float,
        io_timeout: float,
    ) -> None:
        self._endpoint = _parse_endpoint(url)
        self._connect_timeout = connect_timeout
        self._io_timeout = io_timeout

    async def ping(self) -> bool:
        return await self._execute("PING") == "PONG"

    async def setex(self, key: str, ttl: int, value: str) -> RedisResponse:
        return await self._execute("SETEX", key, ttl, value)

    async def eval(
        self,
        script: str,
        numkeys: int,
        *args: RedisCommandPart,
    ) -> RedisResponse:
        return await self._execute("EVAL", script, numkeys, *args)

    async def get(self, key: str) -> str | bytes | None:
        response = await self._execute("GET", key)
        if response is None or isinstance(response, (str, bytes)):
            return response
        raise RedisCommandError("Redis GET returned a non-bulk response")

    async def delete(self, key: str) -> int:
        response = await self._execute("DEL", key)
        if isinstance(response, int):
            return response
        raise RedisCommandError("Redis DEL returned a non-integer response")

    async def aclose(self) -> None:
        """Connections are command-scoped; retained for lifecycle symmetry."""

    async def _execute(self, *parts: RedisCommandPart) -> RedisResponse:
        reader, writer = await asyncio.wait_for(
            self._open_connection(),
            timeout=self._connect_timeout,
        )
        try:
            if self._endpoint.password:
                auth_parts: tuple[RedisCommandPart, ...] = (
                    ("AUTH", self._endpoint.username, self._endpoint.password)
                    if self._endpoint.username
                    else ("AUTH", self._endpoint.password)
                )
                await self._exchange(reader, writer, auth_parts)
            if self._endpoint.database:
                await self._exchange(
                    reader,
                    writer,
                    ("SELECT", self._endpoint.database),
                )
            return await self._exchange(reader, writer, parts)
        finally:
            writer.close()
            with suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), timeout=self._io_timeout)

    async def _open_connection(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        if self._endpoint.scheme == "unix":
            return await asyncio.open_unix_connection(self._endpoint.unix_path)
        tls = ssl.create_default_context() if self._endpoint.scheme == "rediss" else None
        return await asyncio.open_connection(
            self._endpoint.host,
            self._endpoint.port,
            ssl=tls,
            server_hostname=self._endpoint.host if tls is not None else None,
        )

    async def _exchange(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        parts: tuple[RedisCommandPart, ...],
    ) -> RedisResponse:
        writer.write(_encode_command(parts))
        await asyncio.wait_for(writer.drain(), timeout=self._io_timeout)
        return await asyncio.wait_for(_read_response(reader), timeout=self._io_timeout)


__all__ = [
    "AsyncRedisCommandClient",
    "RedisCommandError",
    "RedisCommandPart",
    "RedisResponse",
]
