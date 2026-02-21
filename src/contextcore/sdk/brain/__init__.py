"""BrainClient - SDK client for ContextBrain service.

Uses ContextUnit protocol for all gRPC communication.
Composed of modular mixins for different domains.
"""

from __future__ import annotations

from .base import BrainClientBase
from .commerce import CommerceMixin
from .knowledge import KnowledgeMixin
from .memory import MemoryMixin
from .news import NewsMixin
from .traces import TraceMixin


class BrainClient(
    KnowledgeMixin,
    NewsMixin,
    CommerceMixin,
    MemoryMixin,
    TraceMixin,
    BrainClientBase,
):
    """Client for interacting with ContextBrain using ContextUnit protocol.

    Supports 'local' (library) and 'grpc' (network) modes.
    All methods use ContextUnit internally for type safety and provenance tracking.

    Example:
        client = BrainClient(host="localhost:50051")
        results = await client.search(
            tenant_id="default",
            query_text="renewable energy breakthrough",
            limit=5,
        )
    """

    pass


__all__ = ["BrainClient"]
