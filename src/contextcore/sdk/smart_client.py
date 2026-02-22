"""Smart clients with service discovery and auto-fallback.

These clients extend base SDK clients to discover endpoints via Redis,
falling back to static environment variables when discovery fails or is disabled.
"""

from __future__ import annotations

import logging
import os

from .brain import BrainClient
from .worker_client import WorkerClient

logger = logging.getLogger(__name__)


class SmartBrainClient(BrainClient):
    """BrainClient with auto-discovery and failover.

    Tries to find a Brain Service instance serving the given tenant via Redis.
    Falls back to CONTEXT_BRAIN_URL if discovery fails.
    """

    def __init__(
        self,
        tenant_id: str | None = None,
        redis_url: str | None = None,
        mode: str | None = None,
        host: str | None = None,
        token=None,
    ):
        """Initialize SmartBrainClient.

        Args:
            tenant_id: Tenant to discover services for.
            redis_url: Optional Redis URL for discovery.
            mode: "grpc" or "local".
            host: Specific endpoint to circumvent discovery.
            token: Optional ContextToken for authorization.
        """
        self._tenant_id = tenant_id
        self._redis_url = redis_url

        mode = mode or os.getenv("CONTEXT_BRAIN_MODE", "grpc")
        if mode == "grpc":
            endpoint = host or self._discover_or_fallback()
        else:
            endpoint = None  # local mode doesn't need endpoint

        super().__init__(host=endpoint, mode=mode, token=token)

    def _discover_or_fallback(self) -> str:
        """Try Redis discovery, fall back to CONTEXT_BRAIN_URL env var."""
        try:
            from ..discovery import discover_endpoints

            endpoints = discover_endpoints("brain", tenant_id=self._tenant_id, redis_url=self._redis_url)
            if endpoints:
                # For now, pick first available. Future: gRPC client-side balancing
                endpoint = next(iter(endpoints.values()))
                logger.debug("Discovered Brain endpoint for tenant '%s': %s", self._tenant_id, endpoint)
                return endpoint
        except Exception as e:
            logger.debug("Brain discovery failed: %s", e)

        # Fallback to static env var
        fallback = os.getenv("CONTEXT_BRAIN_URL", "localhost:50051")
        logger.debug("Using Brain fallback endpoint: %s", fallback)
        return fallback


class SmartWorkerClient(WorkerClient):
    """WorkerClient with auto-discovery and failover.

    Tries to find a Worker Service instance serving the given tenant via Redis.
    Falls back to WORKER_ENDPOINT if discovery fails.
    """

    def __init__(
        self,
        tenant_id: str | None = None,
        redis_url: str | None = None,
        host: str | None = None,
        token=None,
    ):
        """Initialize SmartWorkerClient.

        Args:
            tenant_id: Tenant to discover services for.
            redis_url: Optional Redis URL for discovery.
            host: Specific endpoint to circumvent discovery.
            token: Optional ContextToken for authorization.
        """
        self._tenant_id = tenant_id
        self._redis_url = redis_url
        endpoint = host or self._discover_or_fallback()
        super().__init__(endpoint=endpoint, token=token)

    def _discover_or_fallback(self) -> str:
        """Try Redis discovery, fall back to WORKER_ENDPOINT env var."""
        try:
            from ..discovery import discover_endpoints

            endpoints = discover_endpoints("worker", tenant_id=self._tenant_id, redis_url=self._redis_url)
            if endpoints:
                endpoint = next(iter(endpoints.values()))
                logger.debug("Discovered Worker endpoint for tenant '%s': %s", self._tenant_id, endpoint)
                return endpoint
        except Exception as e:
            logger.debug("Worker discovery failed: %s", e)

        # Fallback to static env var
        fallback = os.getenv("WORKER_ENDPOINT", "localhost:50052")  # default if not set
        logger.debug("Using Worker fallback endpoint: %s", fallback)
        return fallback


__all__ = ["SmartBrainClient", "SmartWorkerClient"]
