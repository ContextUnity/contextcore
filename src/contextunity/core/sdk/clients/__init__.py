"""Type-safe gRPC client SDKs for all platform services.

Each client wraps a gRPC stub with ``ContextUnit`` envelope handling,
automatic token injection, and ``PlatformServiceError`` translation.
"""

from .brain import BrainClient
from .router import RouterClient
from .shield import ShieldClient
from .worker import WorkerClient

__all__ = [
    "BrainClient",
    "RouterClient",
    "ShieldClient",
    "WorkerClient",
]
