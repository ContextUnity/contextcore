"""Closed auth-posture and signed project-binding contracts."""

from __future__ import annotations

import pytest
from contextunity.core.auth_posture import (
    LEGACY_PROJECT_BINDING_MIGRATION_ENABLED,
    AuthRuntimePosture,
    VerifierAuthority,
    resolve_auth_runtime_posture,
    resolve_platform_hmac_secret,
    resolve_verified_project_binding,
)
from contextunity.core.parsing import json_dumps
from contextunity.core.signing import HmacBackend
from contextunity.core.token_utils import serialize_token, verify_token_string
from contextunity.core.tokens import ContextToken, PlatformBound, ProjectBound


@pytest.mark.parametrize(
    ("local_mode", "shield_enabled", "expected"),
    [
        (True, False, AuthRuntimePosture.LOCAL_NO_SHIELD),
        (True, True, AuthRuntimePosture.LOCAL_SHIELD),
        (False, False, AuthRuntimePosture.PRODUCTION_NO_SHIELD),
        (False, True, AuthRuntimePosture.PRODUCTION_SHIELD),
    ],
)
def test_runtime_posture_is_closed_four_way_matrix(
    local_mode: bool,
    shield_enabled: bool,
    expected: AuthRuntimePosture,
) -> None:
    assert (
        resolve_auth_runtime_posture(
            local_mode=local_mode,
            shield_enabled=shield_enabled,
        )
        is expected
    )


def test_project_bound_requires_non_empty_delimiter_free_project() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        ProjectBound("")
    with pytest.raises(ValueError, match="delimiter"):
        ProjectBound("project:other")


@pytest.mark.parametrize(
    "binding",
    [ProjectBound("sample-project"), PlatformBound()],
)
def test_signed_binding_round_trips(binding: ProjectBound | PlatformBound) -> None:
    backend = HmacBackend("sample-project" if isinstance(binding, ProjectBound) else "platform", "secret")
    raw = serialize_token(ContextToken(token_id="bound", project_binding=binding), backend=backend)

    verified = verify_token_string(raw, backend)

    assert verified is not None
    assert verified.project_binding == binding


@pytest.mark.parametrize(
    "binding_payload",
    [
        None,
        {"kind": "project", "project_id": None},
        {"kind": "platform", "project_id": "sample-project"},
        {"kind": "unknown", "project_id": None},
    ],
)
def test_malformed_or_null_binding_never_becomes_platform(binding_payload: object) -> None:
    backend = HmacBackend("sample-project", "secret")
    payload: dict[str, object] = {"token_id": "malformed"}
    if binding_payload is not None:
        payload["project_binding"] = binding_payload
    raw = backend.sign(json_dumps(payload, sort_keys=True).encode()).serialize()

    verified = verify_token_string(raw, backend)

    if binding_payload is None:
        assert verified is not None
        assert verified.project_binding is None
    else:
        assert verified is None


def test_legacy_binding_can_only_normalize_to_exact_project() -> None:
    token = ContextToken(token_id="legacy")

    binding = resolve_verified_project_binding(
        token,
        authority=VerifierAuthority.PLATFORM_HMAC,
        verifier_project_id="sample-project",
        allow_legacy_project=True,
    )

    assert binding == ProjectBound("sample-project")
    with pytest.raises(PermissionError, match="signed project binding"):
        resolve_verified_project_binding(
            token,
            authority=VerifierAuthority.PLATFORM_HMAC,
            verifier_project_id="platform",
            allow_legacy_project=False,
        )


def test_legacy_project_binding_rejects_when_migration_gate_is_disabled() -> None:
    token = ContextToken(token_id="legacy")

    assert LEGACY_PROJECT_BINDING_MIGRATION_ENABLED is True
    with pytest.raises(PermissionError, match="signed project binding"):
        resolve_verified_project_binding(
            token,
            authority=VerifierAuthority.SHIELD_PROJECT,
            verifier_project_id="sample-project",
            allow_legacy_project=False,
        )


def test_project_binding_must_match_verified_key_hint() -> None:
    token = ContextToken(
        token_id="wrong-project",
        project_binding=ProjectBound("other-project"),
        permissions=("admin:all",),
    )

    with pytest.raises(PermissionError, match="does not match"):
        resolve_verified_project_binding(
            token,
            authority=VerifierAuthority.PLATFORM_HMAC,
            verifier_project_id="sample-project",
            allow_legacy_project=True,
        )


def test_platform_binding_requires_platform_authority_and_hint() -> None:
    token = ContextToken(token_id="platform", project_binding=PlatformBound())

    assert (
        resolve_verified_project_binding(
            token,
            authority=VerifierAuthority.PLATFORM_HMAC,
            verifier_project_id="platform",
            allow_legacy_project=False,
        )
        == PlatformBound()
    )
    with pytest.raises(PermissionError, match="platform authority"):
        resolve_verified_project_binding(
            token,
            authority=VerifierAuthority.SHIELD_PROJECT,
            verifier_project_id="sample-project",
            allow_legacy_project=False,
        )


def test_no_shield_platform_secret_alias_is_bounded() -> None:
    posture = AuthRuntimePosture.PRODUCTION_NO_SHIELD
    with pytest.warns(DeprecationWarning, match="CU_PROJECT_SECRET"):
        assert (
            resolve_platform_hmac_secret(
                posture,
                platform_secret="",
                project_secret="legacy",
            )
            == "legacy"
        )

    with pytest.raises(ValueError, match="conflicting"):
        resolve_platform_hmac_secret(
            posture,
            platform_secret="canonical",
            project_secret="legacy",
        )


def test_shield_posture_never_uses_project_secret_as_platform_alias() -> None:
    assert (
        resolve_platform_hmac_secret(
            AuthRuntimePosture.PRODUCTION_SHIELD,
            platform_secret="",
            project_secret="bootstrap-only",
        )
        == ""
    )


@pytest.mark.parametrize(
    "binding",
    [PlatformBound(), ProjectBound("other-project")],
)
def test_admin_all_never_bypasses_registration_project_binding(
    binding: ProjectBound | PlatformBound,
) -> None:
    from contextunity.core.authz import authorize
    from contextunity.core.authz.context import VerifiedAuthContext

    token = ContextToken(
        token_id="admin",
        project_binding=binding,
        permissions=("admin:all",),
    )
    auth = VerifiedAuthContext.from_token(token, "verified", project_binding=binding)

    decision = authorize(auth, registration_project_id="sample-project")

    assert decision.denied
    assert "project binding" in (decision.reason or "")


@pytest.mark.asyncio
async def test_backend_resolution_rejects_cross_posture_token_families() -> None:
    from contextunity.core.config import SharedConfig, SharedSecurityConfig
    from contextunity.core.security.backend_resolver import build_verifier_backend

    config = SharedConfig(
        local_mode=False,
        shield_url="shield:50054",
        security=SharedSecurityConfig(
            platform_secret="platform-secret",
            project_secret="bootstrap-secret",
        ),
    )
    assert (
        await build_verifier_backend(
            "sample-project:hmac-001.payload.signature",
            shield_url=config.shield_url,
            config=config,
            posture=AuthRuntimePosture.PRODUCTION_SHIELD,
        )
        is None
    )
    assert (
        await build_verifier_backend(
            "sample-project:session-001.payload.signature",
            shield_url="",
            config=config,
            posture=AuthRuntimePosture.PRODUCTION_NO_SHIELD,
        )
        is None
    )


@pytest.mark.asyncio
async def test_local_shield_admits_only_platform_prefixed_hmac_candidate() -> None:
    from contextunity.core.config import SharedConfig, SharedSecurityConfig
    from contextunity.core.security.backend_resolver import build_verifier_backend

    config = SharedConfig(
        local_mode=True,
        shield_url="shield:50054",
        security=SharedSecurityConfig(
            platform_secret="platform-secret",
            project_secret="bootstrap-secret",
        ),
    )
    platform_backend = await build_verifier_backend(
        "platform:hmac-001.payload.signature",
        shield_url=config.shield_url,
        config=config,
        posture=AuthRuntimePosture.LOCAL_SHIELD,
        allow_local_platform_hmac=True,
    )
    project_hmac = await build_verifier_backend(
        "sample-project:hmac-001.payload.signature",
        shield_url=config.shield_url,
        config=config,
        posture=AuthRuntimePosture.LOCAL_SHIELD,
        allow_local_platform_hmac=True,
    )

    assert isinstance(platform_backend, HmacBackend)
    assert project_hmac is None
