"""BrainClient - SDK client for contextunity.brain service.

Uses ContextUnit protocol for all gRPC communication.
Composed of modular mixins for different domains.
"""

from __future__ import annotations

from .admin import BrainAdminMixin
from .base import BrainClientBase
from .commerce import CommerceCompatMixin
from .embedding import EmbeddingMixin
from .knowledge import KnowledgeMixin
from .memory import MemoryMixin
from .outcomes import OutcomeObservationMixin
from .synapses import SynapseMixin
from .traces import TraceMixin
from .udb import UdbMixin


class BrainClient(
    BrainAdminMixin,
    CommerceCompatMixin,
    OutcomeObservationMixin,
    KnowledgeMixin,
    EmbeddingMixin,
    MemoryMixin,
    SynapseMixin,
    TraceMixin,
    UdbMixin,
    BrainClientBase,
):
    """Client for interacting with contextunity.brain using ContextUnit protocol.

    Supports 'local' (library) and 'grpc' (network) modes.
    All methods use ContextUnit internally for type safety and provenance tracking.

    Example:
        client = BrainClient(host="localhost:50051")
        results = await client.search_cells(
            tenant_id="default",
            query_text="renewable energy breakthrough",
            limit=5,
        )
    """

    pass


__all__ = ["BrainClient"]
