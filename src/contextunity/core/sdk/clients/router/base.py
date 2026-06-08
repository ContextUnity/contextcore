"""Shared utilities for the Router client.

Provides ``build_default_metadata()`` for optional Router graph hints (platform).
Auth metadata is handled by ``BaseServiceClient``.
"""

from __future__ import annotations

from contextunity.core.logging import get_contextunit_logger

from ...contextunit import ContextUnit

logger = get_contextunit_logger(__name__)


def build_default_metadata() -> dict[str, str]:
    """Build optional graph metadata hints for Router execution.

    Tenant identity is carried by the ``ContextToken`` (SPOT) — never injected here.
    """
    from contextunity.core.config import get_core_config

    config = get_core_config()

    meta: dict[str, str] = {}
    if config.cu_platform:
        meta["platform"] = config.cu_platform

    return meta


__all__ = [
    "ContextUnit",
    "build_default_metadata",
    "logger",
]
