from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from contextunity.core import contextunit_pb2
from contextunity.core.manifest.models import ContextUnityProject
from contextunity.core.sdk import ShieldClient
from contextunity.core.sdk.bootstrap.api import _resolve_toolkits
from contextunity.core.sdk.clients import BrainClient
from contextunity.core.sdk.clients import RouterClient as ExportedRouterClient
from contextunity.core.sdk.clients import ShieldClient as ExportedShieldClient
from contextunity.core.sdk.clients import WorkerClient as ExportedWorkerClient
from contextunity.core.sdk.clients import router as router_module
from contextunity.core.sdk.clients.worker import WorkerClient
from contextunity.core.sdk.contextunit import ContextUnit
from contextunity.core.sdk.toolkit import FederatedToolkit, tool
from contextunity.core.sdk.tools import ToolRegistry
from google.protobuf.json_format import MessageToDict


def test_sdk_exports_include_live_service_clients():
    assert BrainClient is not None
    assert ExportedRouterClient is not None
    assert ExportedWorkerClient is not None
    assert ExportedShieldClient is ShieldClient


@pytest.mark.asyncio
async def test_brain_client_keeps_legacy_match_duckdb_surface():
    captured: dict[str, object] = {}

    class _Stub:
        async def MatchDuckDB(self, req, metadata=None):
            captured["payload"] = MessageToDict(req.payload)
            return ContextUnit(payload={"duckdb_matches": [{"id": "a"}], "duckdb_leftovers_count": 2}).to_protobuf(
                contextunit_pb2
            )

    client = BrainClient.__new__(BrainClient)
    client._stub = _Stub()
    client._cu_pb2 = contextunit_pb2
    client._get_metadata = lambda: ()

    result = await client.match_duckdb(
        tenant_id="tenant-a",
        unmatched_url="https://example.test/unmatched.parquet",
        canonical_url="https://example.test/canonical.parquet",
        leftovers_put_url="https://example.test/leftovers.json",
    )

    assert captured["payload"] == {
        "tenant_id": "tenant-a",
        "unmatched_url": "https://example.test/unmatched.parquet",
        "canonical_url": "https://example.test/canonical.parquet",
        "leftovers_put_url": "https://example.test/leftovers.json",
    }
    assert result["duckdb_leftovers_count"] == 2


@pytest.mark.asyncio
async def test_shield_scan_preserves_firewall_wire_fields():
    """ShieldClient must return the live firewall wire payload, not getter projections."""
    from contextunity.core.sdk.clients import shield as shield_module

    client = shield_module.ShieldClient.__new__(shield_module.ShieldClient)
    client._stub = type("_Stub", (), {"Scan": object()})()

    async def _fake_call_unary(_rpc, _payload, *, rpc_name):
        return {
            "allowed": True,
            "blocked": False,
            "reason": "",
            "severity": "LOW",
            "latency_ms": 1.5,
            "threats": [],
        }

    client._call_unary = _fake_call_unary  # type: ignore[method-assign]

    result = await client.scan(content="hello")

    assert result["allowed"] is True
    assert result["blocked"] is False
    assert "passed" not in result
    assert "violations" not in result


@pytest.mark.asyncio
async def test_shield_secret_methods_preserve_explicit_tenant_id():
    """Multi-tenant Shield secret calls must choose tenant explicitly on the wire."""
    from contextunity.core.sdk.clients import shield as shield_module

    client = shield_module.ShieldClient.__new__(shield_module.ShieldClient)
    client._stub = type(
        "_Stub",
        (),
        {
            "GetSecret": object(),
            "PutSecret": object(),
            "ListSecrets": object(),
            "RotateSecret": object(),
        },
    )()
    captured: list[dict[str, object]] = []

    async def _fake_call_unary(_rpc, payload, *, rpc_name):
        captured.append(dict(payload))
        return {"rpc": rpc_name}

    client._call_unary = _fake_call_unary  # type: ignore[method-assign]

    await client.get_secret(path="db/password", tenant_id="tenant-b")
    await client.put_secret(
        path="db/password",
        value="secret",
        tags={"scope": "db"},
        tenant_id="tenant-b",
    )
    await client.list_secrets(prefix="db/", tenant_id="tenant-b")
    await client.rotate_secret(path="db/password", new_value="new", tenant_id="tenant-b")

    assert [payload["tenant_id"] for payload in captured] == [
        "tenant-b",
        "tenant-b",
        "tenant-b",
        "tenant-b",
    ]
    assert captured[1]["tags"] == {"scope": "db"}


@pytest.mark.asyncio
async def test_router_client_has_no_dead_execute_tool_wrapper():
    client = router_module.RouterClient.__new__(router_module.RouterClient)
    assert not hasattr(client, "execute_tool")


@pytest.mark.asyncio
async def test_router_execute_agent_preserves_graph_state_keys():
    """ExecuteAgent must return the full wire payload, not only envelope fields."""

    class _Stub:
        async def ExecuteAgent(self, req, metadata=None):
            return ContextUnit(
                payload={
                    "response": "done",
                    "session_id": "sess-1",
                    "metadata": {"langfuse_enabled": False},
                    "match_stats": {"matched": 3},
                    "matches": [{"id": "a"}],
                }
            ).to_protobuf(contextunit_pb2)

    client = router_module.RouterClient.__new__(router_module.RouterClient)
    client._stub = _Stub()
    client._cu_pb2 = contextunit_pb2
    client._get_metadata = lambda: ()

    result = await client.execute_agent("rlm_bulk_matcher", {"intent": "match"})

    assert result["response"] == "done"
    assert result["session_id"] == "sess-1"
    assert result["match_stats"] == {"matched": 3}
    assert result["matches"] == [{"id": "a"}]


@pytest.mark.asyncio
async def test_router_execute_node_preserves_extra_wire_keys():
    """ExecuteNode must return the full wire payload, not a getter projection."""

    class _Stub:
        async def ExecuteNode(self, req, metadata=None):
            return ContextUnit(
                payload={
                    "output": {"rlm_matches": [{"id": "a"}]},
                    "node_name": "rlm_process",
                    "execution_ms": 42,
                    "langfuse_trace_id": "trace-1",
                    "custom_metric": 99,
                }
            ).to_protobuf(contextunit_pb2)

    client = router_module.RouterClient.__new__(router_module.RouterClient)
    client._stub = _Stub()
    client._cu_pb2 = contextunit_pb2
    client._get_metadata = lambda: ()

    result = await client.execute_node(
        graph_name="rlm_bulk_matcher",
        node_name="rlm_process",
        state={"value": 1},
    )

    assert result["node_name"] == "rlm_process"
    assert result["output"] == {"rlm_matches": [{"id": "a"}]}
    assert result["execution_ms"] == 42
    assert result["langfuse_trace_id"] == "trace-1"
    assert result["custom_metric"] == 99


@pytest.mark.asyncio
async def test_router_execute_node_omits_tenant_id_in_payload():
    captured: dict[str, object] = {}

    class _Stub:
        async def ExecuteNode(self, req, metadata=None):
            captured["payload"] = MessageToDict(req.payload)
            return ContextUnit(
                payload={
                    "output": {"ok": True},
                    "node_name": "node-a",
                    "execution_ms": 0,
                }
            ).to_protobuf(contextunit_pb2)

    client = router_module.RouterClient.__new__(router_module.RouterClient)
    client._stub = _Stub()
    client._cu_pb2 = contextunit_pb2
    client._get_metadata = lambda: ()

    result = await client.execute_node(
        graph_name="graph-a",
        node_name="node-a",
        state={"value": 1},
    )

    assert result["output"] == {"ok": True}
    assert result["node_name"] == "node-a"
    assert captured["payload"] == {
        "graph_name": "graph-a",
        "node_name": "node-a",
        "state": {"value": 1.0},
    }


def test_router_execute_node_rejects_removed_tenant_id_kwarg():
    """Deprecated ``tenant_id`` kwarg has been removed from the SDK surface
    — callers attempting to pass it must fail loudly (SPOT enforcement)."""
    client = router_module.RouterClient.__new__(router_module.RouterClient)
    with pytest.raises(TypeError):
        client.execute_node(  # type: ignore[call-arg]
            graph_name="graph-a",
            node_name="node-a",
            state={},
            tenant_id="tenant-a",
        )


@pytest.mark.asyncio
async def test_router_stream_agent_yields_brain_events():
    class _Stub:
        async def StreamAgent(self, req, metadata=None, timeout=None):
            yield ContextUnit(payload={"event_type": "brain_event", "event": {"type": "node_start"}}).to_protobuf(
                contextunit_pb2
            )

    client = router_module.RouterClient.__new__(router_module.RouterClient)
    client._stub = _Stub()
    client._cu_pb2 = contextunit_pb2
    client._get_metadata = lambda: ()

    events = [
        item
        async for item in client.stream_agent(
            graph_name="graph-a",
            payload={"value": 1},
        )
    ]

    assert len(events) == 1
    event_type, event_data, metrics = events[0]
    assert event_type == "brain_event"
    assert event_data["event_type"] == "brain_event"
    assert event_data["event"] == {"type": "node_start"}
    assert metrics is not None


def test_stream_guards_narrow_open_result_payload():
    from contextunity.core.sdk.responses import is_result_event

    payload = {"event_type": "result", "matches": [{"id": "a"}]}
    assert is_result_event(payload)
    if is_result_event(payload):
        assert payload.get("matches") == [{"id": "a"}]


def test_worker_client_has_no_dead_local_mode():
    init_vars = WorkerClient.__init__.__code__.co_varnames
    assert "mode" not in init_vars


@pytest.mark.asyncio
async def test_worker_client_get_status_omits_tenant_id_payload():
    """SPOT: tenant flows via ContextToken, never in payload."""
    from contextunity.core.sdk.clients import worker as worker_module

    worker_module.contextunit_pb2 = contextunit_pb2

    client = WorkerClient.__new__(WorkerClient)
    client._cu_pb2 = contextunit_pb2
    client._get_metadata = lambda: ()
    client._stub = type(
        "_Stub",
        (),
        {
            "GetTaskStatus": AsyncMock(
                return_value=ContextUnit(payload={"status": "running"}).to_protobuf(contextunit_pb2)
            )
        },
    )()

    result = await client.get_task_status("wf-123")
    assert result["status"] == "running"

    sent_req = client._stub.GetTaskStatus.await_args.args[0]
    assert MessageToDict(sent_req.payload) == {"workflow_id": "wf-123"}


def test_worker_client_get_status_rejects_removed_tenant_id_kwarg():
    """Deprecated ``tenant_id`` positional/kwarg has been removed from the
    SDK — callers attempting to pass it must fail loudly."""
    client = WorkerClient.__new__(WorkerClient)
    with pytest.raises(TypeError):
        client.get_task_status("wf-123", "tenant-a")  # type: ignore[call-arg]


def test_toolkit_resolution_preserves_bidi_tool_path():
    ToolRegistry.clear()

    class ContractToolkit(FederatedToolkit):
        @tool()
        async def summarize(self, value: int) -> dict[str, object]:
            return {"value": value, "tenant": self.ctx.caller_tenant}

    manifest = ContextUnityProject.model_validate(
        {
            "apiVersion": "contextunity/v1alpha7",
            "kind": "ContextUnityProject",
                "project": {"id": "proj", "name": "Project"},
            "services": {"router": {"enabled": True}},
            "router": {
                "default_graph": "demo",
                "toolkits": ["ContractToolkit"],
                "graph": {"demo": {"template": "yaml:demo"}},
                "policy": {"models": {"llm": {"default": "openai/gpt-4o"}}},
            },
        }
    )

    try:
        _resolve_toolkits(manifest)

        handler = ToolRegistry.build_handler()
        assert handler is not None
        result = handler(
            "summarize",
            {"value": 7},
            type("Ctx", (), {"caller_tenant": "tenant-a"})(),
        )
        assert result == {"value": 7, "tenant": "tenant-a"}
    finally:
        ToolRegistry.clear()
        FederatedToolkit._registry.pop("ContractToolkit", None)


pytestmark = pytest.mark.unit
