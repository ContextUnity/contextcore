"""Router-compatible Shield bootstrap for autonomous service processes."""

from __future__ import annotations

from contextunity.core.config.models import SharedSecurityConfig
from contextunity.core.exceptions import ConfigurationError
from contextunity.core.permissions import service_session_permissions
from contextunity.core.tokens import ContextToken, ProjectBound

from .hmac import HmacBackend
from .registry import set_signing_backend
from .session import SessionTokenBackend


def configure_service_signing_backend(
    security: SharedSecurityConfig,
    *,
    project_id: str,
    local_mode: bool,
    shield_enabled: bool,
    shield_url: str,
    service_name: str,
    allowed_tenants: tuple[str, ...],
    register_global: bool = True,
) -> HmacBackend | SessionTokenBackend:
    """Bootstrap HMAC or Shield auth using the Router-compatible exchange.

    Autonomous services embedded in a shared process must pass
    ``register_global=False`` and inject the returned backend into their SDK
    clients. The global registry remains the project bootstrap default.
    """
    project_id = project_id.strip()
    if not project_id:
        raise ConfigurationError("Project id is required for autonomous service authentication")

    if shield_enabled:
        if not shield_url.strip():
            raise ConfigurationError(
                "CU_SHIELD_GRPC_URL is required when manifest services.shield.enabled=true",
                code="MISSING_SHIELD_URL",
            )
        secret = security.project_secret.strip()
        if not secret:
            raise ConfigurationError(
                "CU_PROJECT_SECRET is required for initial Shield session bootstrap",
                code="MISSING_PROJECT_SECRET",
            )
        if not allowed_tenants:
            raise ConfigurationError("Shield service bootstrap requires explicit tenant scope")
        from .shield_client import request_session_token

        hmac = HmacBackend(project_id=project_id, project_secret=secret)
        raw_token, kid, expires_at = request_session_token(
            project_id,
            shield_url,
            hmac,
            required_services={service_name: True},
            requested_token=ContextToken(
                token_id=f"{service_name}-bootstrap",
                project_binding=ProjectBound(project_id),
                permissions=service_session_permissions(service_name),
                allowed_tenants=allowed_tenants,
                agent_id=f"service:{service_name}",
            ),
        )
        backend: HmacBackend | SessionTokenBackend = SessionTokenBackend(
            project_id=project_id,
            session_token=raw_token,
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
            local_mode=local_mode,
            shield_enabled=False,
        )
        secret = resolve_platform_hmac_secret(
            posture,
            platform_secret=security.platform_secret,
            project_secret=security.project_secret,
        )
        if not secret:
            raise ConfigurationError(
                "CU_PLATFORM_SECRET is required for no-Shield HMAC service authentication",
                code="MISSING_PLATFORM_SECRET",
            )
        backend = HmacBackend(project_id=project_id, project_secret=secret)

    if register_global:
        set_signing_backend(backend)
    return backend


__all__ = ["configure_service_signing_backend", "service_session_permissions"]
