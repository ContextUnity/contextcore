"""ContextUnit SDK - Core data structures and clients for ContextUnity protocol.

All gRPC communication uses ContextUnit as the universal data contract.
Domain-specific data is passed via the payload field.

This module re-exports all public API from submodules for backward compatibility.
"""

from __future__ import annotations

# Re-export all public API
from .brain import BrainClient
from .context_unit import ContextUnit
from .models import CotStep, SearchResult, SecurityScopes, UnitMetrics
from .smart_client import SmartBrainClient, SmartWorkerClient
from .worker_client import WorkerClient

__all__ = [
    # Core data structures
    "ContextUnit",
    "CotStep",
    "SearchResult",
    "UnitMetrics",
    "SecurityScopes",
    # Clients
    "BrainClient",
    "WorkerClient",
    "SmartBrainClient",
    "SmartWorkerClient",
]
