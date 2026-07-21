"""Global signing backend registry."""

from __future__ import annotations

from contextunity.core.exceptions import ConfigurationError
from contextunity.core.logging import get_contextunit_logger

from .hmac import HmacBackend
from .protocols import AuthBackend
from .session import SessionTokenBackend

logger = get_contextunit_logger(__name__)

_active_backend: AuthBackend | None = None


def set_signing_backend(backend: AuthBackend) -> None:
    """Set the global active signing backend."""
    global _active_backend
    _active_backend = backend
    logger.info(
        "Signing backend set: %s (project=%s)",
        type(backend).__name__,
        getattr(backend, "project_id", "?"),
    )


def get_signing_backend(
    project_id: str | None = None,
    project_secret: str | None = None,
    platform_secret: str | None = None,
    shield_url: str | None = None,
    *,
    shield_enabled: bool = False,
) -> AuthBackend:
    """Get the signing backend for token operations."""
    if _active_backend is not None and project_id is None:
        return _active_backend

    from contextunity.core.config import get_core_config

    config = get_core_config()
    if project_secret is None:
        project_secret = config.security.project_secret
    if platform_secret is None:
        platform_secret = config.security.platform_secret
    if shield_url is None:
        shield_url = config.shield_url

    if not project_id:
        raise ConfigurationError(
            message=(
                "No signing backend configured. Either:\n"
                "  1. Call set_signing_backend() during bootstrap, or\n"
                "  2. Pass project_id= with CU_PLATFORM_SECRET (no Shield) "
                "or CU_PROJECT_SECRET (Shield bootstrap)."
            ),
            code="CONFIGURATION_ERROR",
        )
    if shield_enabled:
        if not project_secret:
            raise ConfigurationError(
                message="CU_PROJECT_SECRET is required for Shield bootstrap.",
                code="CONFIGURATION_ERROR",
            )
        if not shield_url:
            raise ConfigurationError(
                message="Shield is enabled in manifest but CU_SHIELD_GRPC_URL is not set.",
                code="MISSING_SHIELD_URL",
            )
        hmac_backend = HmacBackend(project_id, project_secret)

        from contextunity.core.sdk.identity import get_required_services

        required_services = get_required_services()
        from contextunity.core.signing import _request_session_token

        token, kid, expires_at = _request_session_token(
            project_id, shield_url, hmac_backend, required_services=required_services
        )
        backend: AuthBackend = SessionTokenBackend(
            project_id=project_id,
            session_token=token,
            kid=kid,
            expires_at=expires_at,
            shield_url=shield_url,
        )
    else:
        from contextunity.core.auth_posture import (
            resolve_auth_runtime_posture,
            resolve_platform_hmac_secret,
        )

        posture = resolve_auth_runtime_posture(
            local_mode=config.local_mode,
            shield_enabled=False,
        )
        hmac_secret = resolve_platform_hmac_secret(
            posture,
            platform_secret=platform_secret or "",
            project_secret=project_secret or "",
        )
        if not hmac_secret:
            raise ConfigurationError(
                message="CU_PLATFORM_SECRET is required for no-Shield HMAC authentication.",
                code="CONFIGURATION_ERROR",
            )
        backend = HmacBackend(project_id=project_id, project_secret=hmac_secret)

    set_signing_backend(backend)
    return backend


def reset_signing_backend() -> None:
    """Reset the global backend (for testing only)."""
    global _active_backend
    _active_backend = None
