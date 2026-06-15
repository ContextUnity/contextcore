"""Operator config/credentials path resolution."""

from __future__ import annotations

from pathlib import Path

import pytest
from contextunity.core.config.paths import (
    resolve_config_dir,
    resolve_credentials_path,
    resolve_operator_profile,
)
from contextunity.core.operator_credentials import (
    KIND_LOCAL_PLATFORM_ADMIN,
    KIND_LOCAL_SCOPED,
    TARGET_LOCAL,
    has_active_local_operator_credentials,
    load_profile_token,
    save_profile,
)


def test_resolve_config_dir_from_cu_config_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg_dir = tmp_path / "state"
    cfg_dir.mkdir()
    monkeypatch.setenv("CU_CONFIG_DIR", str(cfg_dir))
    assert resolve_config_dir() == cfg_dir


def test_resolve_config_dir_falls_back_to_existing_project_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_dir = tmp_path / ".contextunity"
    project_dir.mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CU_CONFIG_DIR", raising=False)
    monkeypatch.delenv("CONTEXTUNITY_CONFIG_DIR", raising=False)
    assert resolve_config_dir() == project_dir


def test_resolve_credentials_path_defaults_to_config_dir_credentials_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    monkeypatch.setenv("CU_CONFIG_DIR", str(cfg_dir))
    monkeypatch.delenv("CU_OPERATOR_CREDENTIALS", raising=False)
    assert resolve_credentials_path() == cfg_dir / "credentials.json"


def test_resolve_credentials_path_explicit_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    explicit = tmp_path / "ops.json"
    monkeypatch.setenv("CU_OPERATOR_CREDENTIALS", str(explicit))
    assert resolve_credentials_path() == explicit


def test_resolve_operator_profile_defaults_local(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CU_PROFILE", raising=False)
    monkeypatch.delenv("CU_OPERATOR_PROFILE", raising=False)
    assert resolve_operator_profile() == "local"


def test_resolve_operator_profile_env_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CU_PROFILE", "legacy")
    monkeypatch.setenv("CU_OPERATOR_PROFILE", "remote")
    assert resolve_operator_profile() == "remote"


def test_multi_profile_storage_and_cu_operator_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cred_path = tmp_path / "credentials.json"
    monkeypatch.setenv("CU_OPERATOR_CREDENTIALS", str(cred_path))

    save_profile(
        "local-platform",
        {
            "token": "local-token",
            "kind": KIND_LOCAL_PLATFORM_ADMIN,
            "target": TARGET_LOCAL,
            "project_id": "ctx",
            "exp_unix": 9999999999.0,
            "minted_at": "2026-06-12T00:00:00Z",
        },
    )
    save_profile(
        "tenant-demo",
        {
            "token": "scoped-token",
            "kind": KIND_LOCAL_SCOPED,
            "target": TARGET_LOCAL,
            "project_id": "ctx",
            "exp_unix": 9999999999.0,
            "minted_at": "2026-06-12T00:00:00Z",
            "allowed_tenants": ["demo"],
        },
    )

    assert load_profile_token("local-platform") == "local-token"
    assert load_profile_token("tenant-demo") == "scoped-token"

    monkeypatch.setenv("CU_OPERATOR_PROFILE", "tenant-demo")
    assert load_profile_token() == "scoped-token"
    assert has_active_local_operator_credentials("local-platform") is True
