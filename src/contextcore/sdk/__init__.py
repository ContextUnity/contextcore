"""ContextUnit SDK - Core data structures and clients for ContextUnity protocol.

All gRPC communication uses ContextUnit as the universal data contract.
Domain-specific data is passed via the payload field.

This module re-exports all public API from submodules for backward compatibility.
"""

from __future__ import annotations

# Re-export all public API
from .bootstrap import bootstrap_django, bootstrap_standalone, register_and_start
from .clients import RouterClient, WorkerClient
from .clients.brain import BrainClient
from .context_unit import ContextUnit
from .models import CotStep, SearchResult, SecurityScopes, UnitMetrics
from .streaming import FederatedToolCallContext
from .tools import ToolRegistry, federated_tool

__all__ = [
    # Core data structures
    "ContextUnit",
    "CotStep",
    "SearchResult",
    "UnitMetrics",
    "SecurityScopes",
    "FederatedToolCallContext",
    # Clients
    "BrainClient",
    "RouterClient",
    "WorkerClient",
    # Bootstrap
    "register_and_start",
    "bootstrap_django",
    "bootstrap_standalone",
    # Tool decorator
    "federated_tool",
    "ToolRegistry",
]
