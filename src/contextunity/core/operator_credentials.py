"""Operator credential store — shared by CLI and Forge (local platform)."""

from __future__ import annotations

import os
import time
from collections.abc import Sequence
from pathlib import Path
from typing import NotRequired, TypedDict

from contextunity.core.config.paths import resolve_credentials_path, resolve_operator_profile
from contextunity.core.parsing import json_dumps, json_loads
from contextunity.core.types import is_json_dict

CREDENTIALS_VERSION = 1

# Profile metadata — not embedded in the token wire format.
TARGET_LOCAL = "local"
TARGET_REMOTE = "remote"

KIND_LOCAL_PLATFORM_ADMIN = "local-platform-admin"
KIND_LOCAL_SCOPED = "local-scoped"
KIND_SHIELD_SESSION = "shield-session"

# Legacy kinds written before the explicit naming contract.
_LEGACY_LOCAL_KINDS: frozenset[str] = frozenset(
    {
        "hmac-local-platform",
        "hmac-local-scoped",
        "hmac-local",
    }
)

LOCAL_CREDENTIAL_KINDS: frozenset[str] = frozenset(
    {
        KIND_LOCAL_PLATFORM_ADMIN,
        KIND_LOCAL_SCOPED,
        *_LEGACY_LOCAL_KINDS,
    }
)

REMOTE_CREDENTIAL_KINDS: frozenset[str] = frozenset({KIND_SHIELD_SESSION})


class CredentialProfile(TypedDict):
    token: str
    kind: str
    project_id: str
    exp_unix: float
    minted_at: str
    target: NotRequired[str]
    brain_url: NotRequired[str]
    allowed_tenants: NotRequired[list[str]]


class CredentialsFile(TypedDict):
    version: int
    profiles: dict[str, CredentialProfile]


def is_local_credential_kind(kind: str) -> bool:
    return kind in LOCAL_CREDENTIAL_KINDS or kind.startswith("local-")


def is_remote_credential_kind(kind: str) -> bool:
    return kind in REMOTE_CREDENTIAL_KINDS


def normalize_service_url(url: str) -> str:
    """Normalize host:port for credential audience matching."""
    raw = url.strip()
    if raw.startswith("remote:"):
        raw = raw.removeprefix("remote:")
    if raw.startswith("grpc://"):
        raw = raw.removeprefix("grpc://")
    if raw.startswith("http://"):
        raw = raw.removeprefix("http://")
    if raw.startswith("https://"):
        raw = raw.removeprefix("https://")
    return raw.rstrip("/")


def is_loopback_host(host: str) -> bool:
    normalized = host.strip("[]").lower()
    return normalized in {"127.0.0.1", "::1", "localhost"}


def brain_url_is_local(brain_url: str) -> bool:
    normalized = normalize_service_url(brain_url)
    if not normalized:
        return True
    host = normalized.split(":", 1)[0]
    return is_loopback_host(host)


def credential_target(profile: CredentialProfile) -> str:
    target = profile.get("target")
    if isinstance(target, str) and target.strip():
        return target.strip()
    if is_local_credential_kind(profile["kind"]):
        return TARGET_LOCAL
    if is_remote_credential_kind(profile["kind"]):
        return TARGET_REMOTE
    return ""


def credential_is_expired(profile: CredentialProfile, *, now: float | None = None) -> bool:
    clock = time.time() if now is None else now
    return profile["exp_unix"] <= clock


def _credentials_path(*, fallback_dirs: Sequence[Path] | None = None) -> Path:
    return resolve_credentials_path(fallback_dirs=fallback_dirs)


def _parse_profile_entry(entry: object) -> CredentialProfile | None:
    if not is_json_dict(entry):
        return None
    token = entry.get("token")
    kind = entry.get("kind")
    project_id = entry.get("project_id")
    exp_unix = entry.get("exp_unix")
    minted_at = entry.get("minted_at")
    if not (
        isinstance(token, str)
        and isinstance(kind, str)
        and isinstance(project_id, str)
        and isinstance(exp_unix, (int, float))
        and isinstance(minted_at, str)
    ):
        return None
    profile = CredentialProfile(
        token=token,
        kind=kind,
        project_id=project_id,
        exp_unix=float(exp_unix),
        minted_at=minted_at,
    )
    target = entry.get("target")
    if isinstance(target, str) and target.strip():
        profile["target"] = target.strip()
    brain_url = entry.get("brain_url")
    if isinstance(brain_url, str) and brain_url.strip():
        profile["brain_url"] = normalize_service_url(brain_url)
    tenants_raw = entry.get("allowed_tenants")
    if isinstance(tenants_raw, list):
        tenants = [t for t in tenants_raw if isinstance(t, str) and t.strip()]
        if tenants:
            profile["allowed_tenants"] = tenants
    return profile


def load_credentials(*, fallback_dirs: Sequence[Path] | None = None) -> CredentialsFile | None:
    path = _credentials_path(fallback_dirs=fallback_dirs)
    if not path.is_file():
        return None
    parsed = json_loads(path.read_text(encoding="utf-8"))
    if not is_json_dict(parsed):
        return None
    profiles_raw = parsed.get("profiles")
    if not is_json_dict(profiles_raw):
        return None
    version_raw = parsed.get("version", 1)
    version = int(version_raw) if isinstance(version_raw, int) else 1
    profiles: dict[str, CredentialProfile] = {}
    for name, entry in profiles_raw.items():
        profile = _parse_profile_entry(entry)
        if profile is not None:
            profiles[name] = profile
    return CredentialsFile(version=version, profiles=profiles)


def save_profile(
    profile_name: str,
    profile: CredentialProfile,
    *,
    fallback_dirs: Sequence[Path] | None = None,
) -> None:
    path = _credentials_path(fallback_dirs=fallback_dirs)
    existing = load_credentials(fallback_dirs=fallback_dirs)
    data: CredentialsFile
    if existing is None:
        data = CredentialsFile(version=CREDENTIALS_VERSION, profiles={})
    else:
        data = existing
    data["profiles"][profile_name] = profile
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json_dumps(data, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def load_profile_token(
    profile: str | None = None,
    *,
    fallback_dirs: Sequence[Path] | None = None,
) -> str | None:
    name = profile if profile is not None else resolve_operator_profile()
    creds = load_credentials(fallback_dirs=fallback_dirs)
    if creds is None:
        return None
    entry = creds["profiles"].get(name)
    if entry is None:
        return None
    return entry["token"]


def load_profile(
    profile: str | None = None,
    *,
    fallback_dirs: Sequence[Path] | None = None,
) -> CredentialProfile | None:
    name = profile if profile is not None else resolve_operator_profile()
    creds = load_credentials(fallback_dirs=fallback_dirs)
    if creds is None:
        return None
    return creds["profiles"].get(name)


def has_active_local_operator_credentials(
    profile: str | None = None,
    *,
    fallback_dirs: Sequence[Path] | None = None,
) -> bool:
    entry = load_profile(profile, fallback_dirs=fallback_dirs)
    if entry is None:
        return False
    if not is_local_credential_kind(entry["kind"]):
        return False
    if credential_target(entry) != TARGET_LOCAL:
        return False
    return not credential_is_expired(entry)


def list_profiles(*, fallback_dirs: Sequence[Path] | None = None) -> tuple[str, ...]:
    creds = load_credentials(fallback_dirs=fallback_dirs)
    if creds is None:
        return ()
    return tuple(sorted(creds["profiles"].keys()))


def clear_profile(
    profile: str | None = None,
    *,
    fallback_dirs: Sequence[Path] | None = None,
) -> bool:
    name = profile if profile is not None else resolve_operator_profile()
    path = _credentials_path(fallback_dirs=fallback_dirs)
    creds = load_credentials(fallback_dirs=fallback_dirs)
    if creds is None or name not in creds["profiles"]:
        return False
    del creds["profiles"][name]
    if not creds["profiles"]:
        path.unlink(missing_ok=True)
        return True
    path.write_text(json_dumps(creds, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return True


__all__ = [
    "CREDENTIALS_VERSION",
    "CredentialProfile",
    "CredentialsFile",
    "KIND_LOCAL_PLATFORM_ADMIN",
    "KIND_LOCAL_SCOPED",
    "KIND_SHIELD_SESSION",
    "LOCAL_CREDENTIAL_KINDS",
    "REMOTE_CREDENTIAL_KINDS",
    "TARGET_LOCAL",
    "TARGET_REMOTE",
    "brain_url_is_local",
    "clear_profile",
    "credential_is_expired",
    "credential_target",
    "has_active_local_operator_credentials",
    "is_local_credential_kind",
    "is_loopback_host",
    "is_remote_credential_kind",
    "list_profiles",
    "load_credentials",
    "load_profile",
    "load_profile_token",
    "normalize_service_url",
    "save_profile",
]
