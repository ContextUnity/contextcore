"""Shared configuration helpers for service discovery."""

from __future__ import annotations

from ..config import get_core_config
from ..logging import get_contextunit_logger

logger = get_contextunit_logger(__name__)

# Default prefix for all service discovery keys in Redis
DEFAULT_PREFIX = "contextunity:services"
DEFAULT_TTL = 30  # seconds


def _get_prefix() -> str:
    """Get service discovery key prefix from shared config.

    Returns:
        str: The configured key prefix, falling back to DEFAULT_PREFIX.
    """
    config = get_core_config()
    prefix = getattr(config, "service_discovery_prefix", None)
    return prefix if isinstance(prefix, str) and prefix else DEFAULT_PREFIX


def _get_ttl() -> int:
    """Get service discovery TTL from shared config.

    Returns:
        int: The configured TTL in seconds, falling back to DEFAULT_TTL.
    """
    config = get_core_config()
    ttl = getattr(config, "service_discovery_ttl", None)
    return ttl if isinstance(ttl, int) and ttl > 0 else DEFAULT_TTL


def _get_redis_url(redis_url: str | None) -> str | None:
    """Resolve Redis URL from explicit arg or shared config.

    Returns None when Redis is not configured. The model-level
    ``model_post_init`` already clears ``redis.url`` when
    ``redis.enabled`` is False, so checking the URL is sufficient.

    Args:
        redis_url: Optional explicit Redis connection URL.

    Returns:
        str | None: The resolved Redis URL, or None if not configured.
    """
    if redis_url:
        return redis_url
    return get_core_config().redis.url or None


def _redis_key(service: str, instance: str) -> str:
    """Generate a Redis key for a service instance.

    Args:
        service: The name of the service (e.g., "brain").
        instance: The unique instance identifier (e.g., host:port).

    Returns:
        str: The generated Redis key.
    """
    return f"{_get_prefix()}:{service}:{instance}"


get_prefix = _get_prefix
get_ttl = _get_ttl
get_redis_url = _get_redis_url
redis_key = _redis_key
