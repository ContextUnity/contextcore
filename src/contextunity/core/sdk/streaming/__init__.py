"""Bidirectional gRPC streaming for federated tool execution.

Provides ``run_stream_loop`` (persistent BiDi ``ToolExecutorStream``)
and ``sync_router_stream`` (sync bridge for Django/WSGI/Flask/CLI).
"""

from .bidi import FederatedToolCallContext, run_stream_loop
from .sync_bridge import sync_router_stream

__all__ = [
    "run_stream_loop",
    "FederatedToolCallContext",
    "sync_router_stream",
]
