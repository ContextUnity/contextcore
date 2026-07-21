"""C0 resolution for the optional service-degradation projection."""

from __future__ import annotations

from typing import ClassVar

from contextunity.core.config import ServiceDegradationConfig, SharedConfig
from pydantic import BaseModel, ConfigDict


class ResolvedServiceDegradationConfig(BaseModel):
    """Validated runtime configuration with no caller-controlled authority."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    environment: str
    redis_url: str
    snapshot_ttl_seconds: int
    refresh_interval_seconds: int
    connect_timeout_seconds: float
    io_timeout_seconds: float
    max_active_signals: int
    max_snapshot_bytes: int


def resolve_service_degradation_config(
    config: SharedConfig,
) -> ResolvedServiceDegradationConfig | None:
    """Resolve the default-off projection from C0 and shared Redis only."""
    projection = config.service_degradation
    if not projection.enabled or not config.redis.enabled or not config.redis.url:
        return None
    environment = projection.environment
    if not environment:
        if config.local_mode:
            environment = "local"
        else:
            raise ValueError("service degradation environment is required when enabled outside local mode")
    return ResolvedServiceDegradationConfig(
        environment=environment,
        redis_url=config.redis.url,
        snapshot_ttl_seconds=projection.snapshot_ttl_seconds,
        refresh_interval_seconds=projection.refresh_interval_seconds,
        connect_timeout_seconds=projection.connect_timeout_seconds,
        io_timeout_seconds=projection.io_timeout_seconds,
        max_active_signals=projection.max_active_signals,
        max_snapshot_bytes=projection.max_snapshot_bytes,
    )


__all__ = [
    "ResolvedServiceDegradationConfig",
    "ServiceDegradationConfig",
    "resolve_service_degradation_config",
]
