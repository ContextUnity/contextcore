"""Bootstrap client auth metadata — SessionTokenBackend attenuation."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from contextunity.core.signing import SessionTokenBackend


@pytest.mark.unit
def test_bootstrap_metadata_prefers_global_signing_backend():
    from contextunity.core.sdk.bootstrap.client import _bootstrap_metadata

    session = MagicMock(spec=SessionTokenBackend)
    session.create_grpc_metadata.return_value = (("authorization", "Bearer session-token"),)

    with patch("contextunity.core.signing.get_signing_backend", return_value=session):
        meta = _bootstrap_metadata(
            project_id="nszu",
            backend=None,
            token_id_suffix="shield-sync",
            permissions=("shield:secrets:write",),
        )

    assert meta == (("authorization", "Bearer session-token"),)
    session.create_grpc_metadata.assert_called_once()
    sent_token = session.create_grpc_metadata.call_args.args[0]
    assert sent_token.permissions == ("shield:secrets:write",)
    assert sent_token.allowed_tenants == ("nszu",)


@pytest.mark.unit
def test_put_secrets_to_shield_writes_each_allowed_tenant(monkeypatch):
    from contextunity.core import ContextUnit
    from contextunity.core.sdk.bootstrap import client

    captured: list[dict[str, object]] = []
    metadata_calls: list[dict[str, object]] = []

    class Stub:
        def __init__(self, channel):
            self.channel = channel

        def PutSecret(self, request, *, metadata, timeout):
            _ = (metadata, timeout)
            captured.append(dict(ContextUnit.from_protobuf(request).payload))
            return object()

    channel = MagicMock()
    monkeypatch.setattr("contextunity.core.grpc_utils.create_channel_sync", lambda _url: channel)
    monkeypatch.setattr("contextunity.core.shield_pb2_grpc.ShieldServiceStub", Stub)
    monkeypatch.setattr(
        client,
        "_bootstrap_metadata",
        lambda **kwargs: metadata_calls.append(kwargs) or (("authorization", "Bearer token"),),
    )

    synced = client.put_secrets_to_shield(
        "nszu",
        {"planner/model_secret_ref": "api-key"},
        "shield:50054",
        None,
        allowed_tenants=("tenant-a", "tenant-b"),
    )

    assert synced == [
        "tenant-a:planner/model_secret_ref",
        "tenant-b:planner/model_secret_ref",
    ]
    assert [payload["path"] for payload in captured] == [
        "tenant-a/api_keys/planner/model_secret_ref",
        "tenant-b/api_keys/planner/model_secret_ref",
    ]
    assert [payload["tenant_id"] for payload in captured] == ["tenant-a", "tenant-b"]
    assert metadata_calls[0]["allowed_tenants"] == ("tenant-a", "tenant-b")
    assert metadata_calls[0]["permissions"] == ("shield:secrets:write",)
    channel.close.assert_called_once()


@pytest.mark.unit
def test_put_prompts_to_shield_writes_project_path_in_each_tenant(monkeypatch):
    from contextunity.core import ContextUnit
    from contextunity.core.sdk.bootstrap import client

    captured: list[dict[str, object]] = []
    metadata_calls: list[dict[str, object]] = []

    class Stub:
        def __init__(self, channel):
            self.channel = channel

        def PutSecret(self, request, *, metadata, timeout):
            _ = (metadata, timeout)
            captured.append(dict(ContextUnit.from_protobuf(request).payload))
            return object()

    channel = MagicMock()
    monkeypatch.setattr("contextunity.core.grpc_utils.create_channel_sync", lambda _url: channel)
    monkeypatch.setattr("contextunity.core.shield_pb2_grpc.ShieldServiceStub", Stub)
    monkeypatch.setattr(
        client,
        "_bootstrap_metadata",
        lambda **kwargs: metadata_calls.append(kwargs) or (("authorization", "Bearer token"),),
    )

    synced = client.put_prompts_to_shield(
        "nszu",
        {"planner": "Canonical prompt"},
        "shield:50054",
        None,
        allowed_tenants=("tenant-a", "tenant-b"),
    )

    assert synced == ["tenant-a:planner", "tenant-b:planner"]
    assert [payload["path"] for payload in captured] == [
        "nszu/prompts/planner",
        "nszu/prompts/planner",
    ]
    assert [payload["tenant_id"] for payload in captured] == ["tenant-a", "tenant-b"]
    assert all(payload["value"] == "Canonical prompt" for payload in captured)
    assert metadata_calls[0]["allowed_tenants"] == ("tenant-a", "tenant-b")
    assert metadata_calls[0]["permissions"] == ("shield:secrets:write",)
    channel.close.assert_called_once()
