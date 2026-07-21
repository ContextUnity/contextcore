"""Closed authentication posture and post-verification binding resolution."""

from __future__ import annotations

import warnings
from enum import StrEnum
from typing import Final

from .tokens import ContextToken, ProjectBinding, ProjectBound

# One code-owned compatibility window for previously issued project tokens.
# The resolver below still requires a non-platform verified key owner and can
# normalize only to that exact ProjectBound value. This gate never upgrades a
# missing binding to PlatformBound and is intentionally not operator-configurable.
LEGACY_PROJECT_BINDING_MIGRATION_ENABLED: Final = True


class AuthRuntimePosture(StrEnum):
    """Resolved deployment and Shield posture."""

    LOCAL_NO_SHIELD = "local-no-shield"
    LOCAL_SHIELD = "local-shield"
    PRODUCTION_NO_SHIELD = "production-no-shield"
    PRODUCTION_SHIELD = "production-shield"

    @property
    def is_local(self) -> bool:
        return self in {self.LOCAL_NO_SHIELD, self.LOCAL_SHIELD}

    @property
    def shield_enabled(self) -> bool:
        return self in {self.LOCAL_SHIELD, self.PRODUCTION_SHIELD}


class VerifierAuthority(StrEnum):
    """Trusted authority that completed cryptographic verification."""

    PLATFORM_HMAC = "platform-hmac"
    SHIELD_PROJECT = "shield-project"


def resolve_auth_runtime_posture(
    *,
    local_mode: bool,
    shield_enabled: bool,
) -> AuthRuntimePosture:
    """Resolve the closed Local/Production x Shield matrix from trusted config."""
    if local_mode:
        return AuthRuntimePosture.LOCAL_SHIELD if shield_enabled else AuthRuntimePosture.LOCAL_NO_SHIELD
    return AuthRuntimePosture.PRODUCTION_SHIELD if shield_enabled else AuthRuntimePosture.PRODUCTION_NO_SHIELD


def resolve_platform_hmac_secret(
    posture: AuthRuntimePosture,
    *,
    platform_secret: str,
    project_secret: str,
) -> str:
    """Resolve the shared HMAC root with the bounded no-Shield legacy alias."""
    canonical = platform_secret.strip()
    legacy = project_secret.strip()

    if posture.shield_enabled:
        return canonical
    if canonical and legacy and canonical != legacy:
        raise ValueError("CU_PLATFORM_SECRET and CU_PROJECT_SECRET contain conflicting values in a no-Shield posture")
    if canonical:
        return canonical
    if legacy:
        warnings.warn(
            "CU_PROJECT_SECRET as a no-Shield HMAC root is deprecated; set CU_PLATFORM_SECRET",
            DeprecationWarning,
            stacklevel=2,
        )
        return legacy
    return ""


def resolve_verified_project_binding(
    token: ContextToken,
    *,
    authority: VerifierAuthority,
    verifier_project_id: str,
    allow_legacy_project: bool,
) -> ProjectBinding:
    """Resolve semantic binding only after the caller verified the signature.

    ``verifier_project_id`` is the bounded key-owner candidate selected from
    ``kid``. It is compared with the signed claim here; it never becomes
    platform authority merely because the signed claim is absent.
    """
    verifier_project = verifier_project_id.strip()
    binding = token.project_binding

    if binding is None:
        if allow_legacy_project and verifier_project and verifier_project != "platform":
            return ProjectBound(verifier_project)
        raise PermissionError("Token is missing a signed project binding")

    if isinstance(binding, ProjectBound):
        if not verifier_project or binding.project_id != verifier_project:
            raise PermissionError("Signed project binding does not match the verified key owner")
        return binding

    if authority is not VerifierAuthority.PLATFORM_HMAC or verifier_project != "platform":
        raise PermissionError("PlatformBound token was not verified by platform authority")
    return binding


__all__ = [
    "AuthRuntimePosture",
    "LEGACY_PROJECT_BINDING_MIGRATION_ENABLED",
    "VerifierAuthority",
    "resolve_auth_runtime_posture",
    "resolve_platform_hmac_secret",
    "resolve_verified_project_binding",
]
