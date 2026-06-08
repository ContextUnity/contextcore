"""Sync bridge for RouterClient streaming in sync environments.

Combines:
- Async RouterClient lifecycle (connect/disconnect)
- Async-to-sync iterator bridge (dedicated event loop in background thread)
- Optional heartbeat injection to prevent proxy timeouts

Usage in a Django/WSGI SSE view::

    from contextunity.core.sdk.streaming import sync_router_stream

    def my_sse_view(request):
        for item in sync_router_stream(
            graph_name="contextmed",
            payload={"messages": [...]},
            metadata={"user_id": "alice"},
            heartbeat_timeout=2.0,
        ):
            if item is None:
                yield ": heartbeat\\n\\n"
                continue
            event_type, event_data, metrics = item
            # handle progress / result / done / error

Usage in a sync script or Flask view (no heartbeats)::

    for event_type, event_data, metrics in sync_router_stream(
        graph_name="rlm_bulk_matcher",
        payload={"intent": "match"},
    ):
        print(event_type, event_data)
"""

from __future__ import annotations

import concurrent.futures
import queue
from collections.abc import Generator
from typing import TYPE_CHECKING, Generic, Literal, NamedTuple, TypeVar

from contextunity.core.sdk.types import SyncIteratorFactory
from contextunity.core.types import ContextUnitPayload, JsonDict

if TYPE_CHECKING:
    from contextunity.core.sdk.models import UnitMetrics
    from contextunity.core.sdk.responses import StreamPayload

T = TypeVar("T")


class _StreamDataMsg(NamedTuple, Generic[T]):
    tag: Literal["data"]
    item: T


class _StreamErrorMsg(NamedTuple):
    tag: Literal["error"]
    exc: Exception


class _StreamDoneMsg(NamedTuple):
    tag: Literal["done"]


_StreamMsg = _StreamDataMsg[T] | _StreamErrorMsg | _StreamDoneMsg

# Shared thread pool for all synchronous streaming across the application
# to prevent thread explosion under load.
_STREAM_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=10, thread_name_prefix="cu-stream")


def _stream_with_heartbeat(
    generator_func: SyncIteratorFactory[T],
    timeout: float = 2.0,
) -> Generator[T | None]:
    """Wrap a blocking generator with heartbeat injection.

    Runs *generator_func* in a background thread. When the generator
    produces no items within *timeout* seconds, yields ``None`` so the
    caller can emit a keepalive (e.g. SSE comment line).

    Args:
        generator_func: Factory returning the blocking iterator.
        timeout: Seconds to wait before yielding a heartbeat ``None``.

    Yields:
        Items from the generator, or ``None`` for heartbeats.
    """
    q: queue.Queue[_StreamMsg[T]] = queue.Queue()

    def _worker() -> None:
        try:
            for item in generator_func():
                q.put(_StreamDataMsg("data", item))
            q.put(_StreamDoneMsg("done"))
        except Exception as exc:
            q.put(_StreamErrorMsg("error", exc))

    _ = _STREAM_POOL.submit(_worker)

    while True:
        try:
            msg = q.get(timeout=timeout)
        except queue.Empty:
            yield None  # Signal caller to emit a heartbeat
            continue

        if isinstance(msg, _StreamDataMsg):
            yield msg.item
        elif isinstance(msg, _StreamErrorMsg):
            raise msg.exc
        else:
            break


def _make_sync_generator(
    *,
    graph_name: str,
    payload: ContextUnitPayload | None,
    metadata: JsonDict | None,
    host: str | None,
) -> Generator[tuple[str, StreamPayload, UnitMetrics | None]]:
    """Sync generator that bridges async RouterClient via a private event loop.

    Each item is yielded one-by-one — true streaming, not batch-then-yield.
    """
    import asyncio

    loop = asyncio.new_event_loop()
    try:
        from contextunity.core.sdk.clients.router import RouterClient

        async def _stream():
            async with RouterClient(host=host) as client:
                async for item in client.stream_agent(
                    graph_name=graph_name,
                    payload=payload,
                    metadata=metadata,
                ):
                    yield item

        ait = _stream().__aiter__()
        while True:
            try:
                yield loop.run_until_complete(ait.__anext__())
            except StopAsyncIteration:
                break
    finally:
        loop.close()


def sync_router_stream(
    *,
    graph_name: str,
    payload: ContextUnitPayload | None = None,
    metadata: JsonDict | None = None,
    host: str | None = None,
    heartbeat_timeout: float | None = None,
) -> Generator[tuple[str, StreamPayload, UnitMetrics | None] | None]:
    """Stream a Router graph synchronously.

    Designed for any sync environment that needs to consume
    ``RouterClient.stream_agent()`` — Django WSGI, Flask, CLI scripts.

    Args:
        graph_name: Name of the registered graph.
        payload: Graph input state.
        metadata: Per-call metadata (e.g. ``user_id``).
        host: Optional explicit gRPC host address.
        heartbeat_timeout: If set, wraps the stream with heartbeat injection
            — yielding ``None`` every ``heartbeat_timeout`` seconds when the
            gRPC stream is idle.  Set this for SSE endpoints to prevent
            proxy timeouts.  ``None`` (default) = no heartbeats, plain sync
            iteration.

    Yields:
        ``(event_type, event_data, metrics)`` tuples from the Router stream.
        When ``heartbeat_timeout`` is set, also yields ``None`` for heartbeat
        signals.
    """
    if heartbeat_timeout is not None:
        yield from _stream_with_heartbeat(
            lambda: _make_sync_generator(
                graph_name=graph_name,
                payload=payload,
                metadata=metadata,
                host=host,
            ),
            timeout=heartbeat_timeout,
        )
    else:
        yield from _make_sync_generator(
            graph_name=graph_name,
            payload=payload,
            metadata=metadata,
            host=host,
        )


__all__ = ["sync_router_stream"]
