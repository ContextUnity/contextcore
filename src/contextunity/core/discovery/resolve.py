"""Service endpoint resolution with 3-tier fallback strategy."""

from __future__ import annotations

from ..config import get_core_config
from ..logging import get_contextunit_logger
from .services import discover_services

logger = get_contextunit_logger(__name__)


def resolve_service_endpoint(
    service_type: str,
    *,
    configured_host: str = "",
    default_host: str = "",
    tenant_id: str | None = None,
) -> str:
    """Resolve a service endpoint using a 3-tier strategy.

    Hierarchy:
      1. Explicit config - `configured_host` (from env var or config file)
      2. Redis auto-discovery - `discover_services(service_type)`
      3. Default fallback - `default_host` (e.g., "localhost:50051")

    Logs the resolution path to ensure that endpoint resolution issues are traceable.

    Args:
        service_type: Service type key (e.g., "brain", "worker", "shield").
        configured_host: Pre-configured host from env/config. Used directly if non-empty.
        default_host: Last-resort fallback. If empty, the service is considered optional.
        tenant_id: Optional tenant filter for Redis discovery.

    Returns:
        str: Resolved endpoint string, or an empty string if the service is unavailable
        and no default fallback is provided.
    """
    # 1. Explicit config
    if configured_host and configured_host != default_host:
        logger.debug("Service '%s': using configured host %s", service_type, configured_host)
        return configured_host

    # 2. Redis auto-discovery (only when Redis is configured/enabled)
    core_cfg = get_core_config()
    redis_enabled = bool(core_cfg.redis.enabled and core_cfg.redis.url)
    if redis_enabled:
        try:
            services = discover_services(service_type=service_type, tenant_id=tenant_id)
            if services:
                endpoint = services[0].endpoint
                logger.debug(
                    "Service '%s': auto-discovered via Redis → %s (instance=%s)",
                    service_type,
                    endpoint,
                    services[0].instance,
                )
                return endpoint
        except Exception as e:
            logger.debug("Service '%s': Redis auto-discovery failed: %s", service_type, e)

    # 3. Default fallback
    if default_host:
        logger.debug("Service '%s': using default host %s", service_type, default_host)
        return default_host

    # No endpoint found
    logger.info(
        "Service '%s': not available, dependent features will be disabled.",
        service_type,
    )
    return ""
