"""Streaming utilities for ContextUnit SDK.

Provides helpers for synchronous environments (like Django WSGI)
to wrap blocking gRPC streams with asynchronous features such as
heartbeats to prevent connection timeouts.
"""

from __future__ import annotations

import concurrent.futures
import queue
from typing import Callable, Generator, Iterator, TypeVar

T = TypeVar("T")

# Shared thread pool for all synchronous gRPC streaming across the application
# to prevent thread explosion under load.
_DEFAULT_STREAM_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=10, thread_name_prefix="cu-stream")


def stream_with_heartbeat(
    generator_func: Callable[[], Iterator[T]],
    timeout: float = 2.0,
) -> Generator[T | None, None, None]:
    """Wraps a blocking generator with a background thread to inject heartbeats.

    Useful in synchronous WSGI environments (like Django) where a gRPC
    call might block for longer than the web proxy's timeout. By yielding
    `None` periodically, the caller can inject an SSE heartbeat.

    Args:
        generator_func: A lambda/function returning the blocking iterator.
        timeout: Seconds to wait before yielding a heartbeat (None).

    Yields:
        Items yielded by the generator, or `None` if `timeout` is reached.
    """
    q: queue.Queue = queue.Queue()

    def _worker():
        try:
            for item in generator_func():
                q.put(("data", item))
            q.put(("done", None))
        except Exception as e:
            q.put(("error", e))

    _DEFAULT_STREAM_POOL.submit(_worker)

    while True:
        try:
            msg_type, payload = q.get(timeout=timeout)
        except queue.Empty:
            yield None  # Signal caller to emit a heartbeat
            continue

        if msg_type == "data":
            yield payload
        elif msg_type == "error":
            raise payload
        elif msg_type == "done":
            break
