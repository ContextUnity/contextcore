"""ProjectStore contract tests for discovery project metadata."""

from __future__ import annotations

import time

import pytest


@pytest.fixture(autouse=True)
def _reset_store():
    """Ensure each test gets a fresh singleton state."""
    from contextunity.core.discovery.store import reset_project_store

    reset_project_store()
    yield
    reset_project_store()


def test_inmemory_register_and_retrieve_key_material() -> None:
    from contextunity.core.discovery.store import InMemoryProjectStore

    store = InMemoryProjectStore()

    assert store.register(
        "proj-a",
        owner_project="proj-a",
        tools=["tool_a"],
        project_secret="hmac-secret",
        public_key_b64="pub",
        public_key_kid="kid-1",
        api_keys={"OPENAI_API_KEY": "sk-test"},
    )

    key_material = store.get_key_material("proj-a")
    assert key_material == {
        "project_secret": "hmac-secret",
        "public_key_b64": "pub",
        "public_key_kid": "kid-1",
        "api_keys": {"OPENAI_API_KEY": "sk-test"},
    }


def test_inmemory_owner_conflict_is_rejected() -> None:
    from contextunity.core.discovery.store import InMemoryProjectStore

    store = InMemoryProjectStore()

    assert store.register("proj-a", tools=[])
    assert store.verify_owner("proj-a", "proj-a") is True
    store._records["proj-a"]["owner_project"] = "other"
    assert store.register("proj-a", tools=[]) is False
    assert store.verify_owner("proj-a", "proj-a") is False


def test_inmemory_stream_secret_ttl() -> None:
    from contextunity.core.discovery.store import InMemoryProjectStore

    store = InMemoryProjectStore(stream_secret_ttl=0.01)
    assert store.update_stream_secret("proj-a", "stream-secret") is True
    assert store.get_stream_secret("proj-a") == "stream-secret"

    time.sleep(0.02)

    assert store.get_stream_secret("proj-a") is None


def test_project_store_factory_falls_back_to_inmemory_when_redis_unavailable(monkeypatch) -> None:
    from contextunity.core.discovery.client import RedisNotAvailable
    from contextunity.core.discovery.store import (
        InMemoryProjectStore,
        get_project_store,
        reset_project_store,
    )

    class BrokenRedisStore:
        def __init__(self, redis_url: str) -> None:
            raise RedisNotAvailable("redis unavailable")

    monkeypatch.setattr(
        "contextunity.core.discovery.store.get_redis_url",
        lambda redis_url=None: "redis://localhost:6379/0",
    )
    monkeypatch.setattr("contextunity.core.discovery.store.RedisProjectStore", BrokenRedisStore)
    reset_project_store()

    try:
        assert isinstance(get_project_store(), InMemoryProjectStore)
    finally:
        reset_project_store()


def test_public_functions_proxy_to_configured_store() -> None:
    from contextunity.core.discovery import get_project_key, register_project, verify_project_owner
    from contextunity.core.discovery.store import InMemoryProjectStore, reset_project_store, set_project_store

    store = InMemoryProjectStore()
    set_project_store(store)

    try:
        assert register_project(
            "proj-a",
            tools=["tool_a"],
            project_secret="hmac-secret",
            api_keys={"OPENAI_API_KEY": "sk-test"},
        )
        assert verify_project_owner("proj-a") is True
        assert get_project_key("proj-a") == {
            "project_secret": "hmac-secret",
            "api_keys": {"OPENAI_API_KEY": "sk-test"},
        }
    finally:
        reset_project_store()


def test_redis_store_encrypt_decrypt(monkeypatch) -> None:
    """RedisProjectStore encrypts secrets on write and decrypts on read.

    Mocks SyncRedisClient so no real Redis is needed.  Verifies that:
    - project_secret is stored via encrypt() (not plaintext)
    - api_keys are stored via encrypt(json.dumps(...))
    - get_key_material() returns decrypted values
    """
    import base64
    import json
    import os

    # Generate a real encryption key so encrypt/decrypt roundtrip works
    real_key = base64.b64encode(os.urandom(32)).decode()
    monkeypatch.setattr(
        "contextunity.core.discovery.crypto._get_redis_secret_key",
        lambda: real_key,
    )
    # Clear the cached log status so our key takes effect
    from contextunity.core.discovery.crypto import _log_crypto_status_once

    _log_crypto_status_once.cache_clear()

    # ── Mock SyncRedisClient (in-memory dict) ──
    _store: dict[str, str] = {}

    class MockRedisClient:
        def __init__(self, redis_url: str) -> None:
            pass

        def get(self, key: str) -> str | None:
            return _store.get(key)

        def set(self, key: str, value: str) -> None:
            _store[key] = value

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        "contextunity.core.discovery.redis_store.SyncRedisClient",
        MockRedisClient,
    )

    from contextunity.core.discovery.redis_store import RedisProjectStore

    store = RedisProjectStore("redis://mock:6379/0")

    # Register with secrets
    assert store.register(
        "proj-crypto",
        tools=["tool_x"],
        project_secret="super-secret-hmac",
        api_keys={"OPENAI_API_KEY": "sk-live-test123"},
    )

    # Verify raw storage is encrypted (not plaintext)
    assert len(_store) == 1
    raw_json = list(_store.values())[0]
    raw_data = json.loads(raw_json)

    # project_secret must be encrypted (prefixed with "enc:")
    assert raw_data["project_secret"].startswith("enc:"), (
        f"project_secret should be encrypted, got: {raw_data['project_secret'][:20]}..."
    )
    assert "super-secret-hmac" not in raw_data["project_secret"]

    # api_keys must be encrypted too
    assert isinstance(raw_data["api_keys"], str)
    assert raw_data["api_keys"].startswith("enc:")
    assert "sk-live-test123" not in raw_data["api_keys"]

    # Now verify get_key_material decrypts correctly
    key_material = store.get_key_material("proj-crypto")
    assert key_material is not None
    assert key_material.get("project_secret") == "super-secret-hmac"
    assert key_material.get("api_keys") == {"OPENAI_API_KEY": "sk-live-test123"}

    # Cleanup cached crypto status
    _log_crypto_status_once.cache_clear()


pytestmark = pytest.mark.unit
