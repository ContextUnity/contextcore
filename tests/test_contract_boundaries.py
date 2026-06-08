"""Contract boundary tests for core L2/L3 seams (stream payload, transformer configure)."""

from __future__ import annotations

from datetime import datetime

import pytest
from contextunity.core.exceptions import ConfigurationError
from contextunity.core.sdk.interfaces import BaseTransformer, JsonConfigurableTransformer
from contextunity.core.sdk.payload import (
    get_object_list,
    get_optional_str,
    get_required_str,
    normalize_tool_result,
    parse_federated_execute,
)
from contextunity.core.sdk.responses import (
    StreamPayload,
    is_progress_event,
    is_result_event,
)
from contextunity.core.types import ContextUnitPayload


class _JsonStubTransformer(JsonConfigurableTransformer):
    async def transform(self, unit):  # type: ignore[no-untyped-def]
        return unit


class _OpenStubTransformer(BaseTransformer):
    async def transform(self, unit):  # type: ignore[no-untyped-def]
        return unit


def test_json_configurable_transformer_accepts_json_params():
    transformer = _JsonStubTransformer()
    transformer.configure({"mode": "llm", "min_score": 0.5})
    assert transformer.params == {"mode": "llm", "min_score": 0.5}


def test_json_configurable_transformer_rejects_non_json_params():
    transformer = _JsonStubTransformer()
    with pytest.raises(ConfigurationError, match="JSON object"):
        transformer.configure({"when": datetime(2020, 1, 1)})


def test_base_transformer_allows_non_json_params():
    """Service overrides may store domain objects — core open bag only."""
    transformer = _OpenStubTransformer()
    sentinel = object()
    transformer.configure({"config": sentinel})
    assert transformer.params["config"] is sentinel


def test_stream_result_guard_accepts_open_graph_state():
    payload: ContextUnitPayload = {
        "event_type": "result",
        "answer": "hello",
        "citations": [{"id": "1"}],
    }
    assert is_result_event(payload)
    if is_result_event(payload):
        assert payload.get("answer") == "hello"


def test_stream_progress_guard_checks_discriminant_only():
    payload: StreamPayload = {"event_type": "progress", "node": "summarize", "custom": 1}
    assert is_progress_event(payload)


def test_parse_federated_execute_uses_getters():
    payload: ContextUnitPayload = {
        "request_id": "req-1",
        "tool": "sql",
        "args": {"sql": "SELECT 1"},
        "caller_tenant": "t1",
        "caller_user": "u1",
    }
    parsed = parse_federated_execute(payload)
    assert parsed["request_id"] == "req-1"
    assert parsed["tool"] == "sql"
    assert parsed["args"]["sql"] == "SELECT 1"
    assert parsed["caller_tenant"] == "t1"
    assert parsed["user_id"] == "u1"


def test_get_optional_str_distinguishes_missing_from_empty():
    payload: ContextUnitPayload = {"present": "", "typed": "abc"}
    assert get_optional_str(payload, "missing") is None
    assert get_optional_str(payload, "present") == ""
    assert get_optional_str(payload, "typed") == "abc"


def test_get_required_str_raises_on_missing_or_empty():
    payload: ContextUnitPayload = {"present": ""}
    with pytest.raises(ValueError, match="workflow_type is required"):
        get_required_str(payload, "workflow_type")
    assert get_required_str({"workflow_type": "run"}, "workflow_type") == "run"


def test_get_object_list_returns_list_or_empty():
    assert get_object_list({"args": [1, "a"]}, "args") == [1, "a"]
    assert get_object_list({"args": "bad"}, "args") == []
    assert get_object_list({}, "args") == []


def test_normalize_tool_result_wraps_non_dict():
    assert normalize_tool_result({"ok": True}) == {"ok": True}
    assert normalize_tool_result(42) == {"result": 42}


def test_get_json_value_preserves_nested_json():
    from contextunity.core.sdk.payload import get_json_value

    payload: ContextUnitPayload = {"fact_value": {"color": "blue"}, "bad": object()}
    assert get_json_value(payload, "fact_value") == {"color": "blue"}
    assert get_json_value(payload, "bad") == ""
    assert get_json_value(payload, "missing") == ""


# ── Recursive JSON alias / Pydantic forward-ref resolution ──────────────────
#
# Regression guard: ``JsonValue`` must be a PEP 695 ``type`` alias
# (``TypeAliasType``) so its recursive self-reference resolves against
# ``core.types``'s namespace. A plain ``TypeAlias`` with quoted ``"JsonValue"``
# forward refs fails to rebuild in Pydantic models declared in *other* modules
# (e.g. router ``ModelRequest``), raising
# ``PydanticUserError: ... not fully defined; you should define JsonValue``.


def test_json_value_is_pep695_type_alias():
    from typing import TypeAliasType

    from contextunity.core.types import JsonValue

    assert isinstance(JsonValue, TypeAliasType), (
        "JsonValue must be a PEP 695 `type` alias so recursive forward refs resolve cross-module in Pydantic models"
    )


def test_struct_data_value_field_rebuilds_without_jsonvalue_in_scope():
    """A model that imports ``StructDataValue`` but NOT ``JsonValue`` must still build.

    This mirrors the real consumer (``router.modules.models.types.ModelRequest``):
    the model's module namespace knows ``StructDataValue`` but never imports the
    recursive ``JsonValue`` alias it expands to. With a plain ``TypeAlias`` this
    raised ``PydanticUserError`` (class-not-fully-defined); with the PEP 695
    ``type`` alias it resolves against ``core.types``.
    """
    import pydantic
    from contextunity.core.sdk.types import StructDataValue

    # Synthetic module namespace: StructDataValue present, JsonValue ABSENT —
    # and no ``from __future__ import annotations`` so the annotation is
    # evaluated eagerly at class creation, exactly like the failing module.
    namespace: dict[str, object] = {
        "BaseModel": pydantic.BaseModel,
        "StructDataValue": StructDataValue,
        "dict": dict,
        "str": str,
    }
    exec(  # noqa: S102 — deliberate: reproduces a real cross-module model definition
        "class _Probe(BaseModel):\n    metadata: dict[str, StructDataValue] = {}\n",
        namespace,
    )
    probe_cls = namespace["_Probe"]
    instance = probe_cls(metadata={"a": [1, {"b": True}], "n": None})
    assert instance.metadata["a"] == [1, {"b": True}]
    assert instance.metadata["n"] is None


def test_router_model_request_accepts_recursive_metadata():
    """End-to-end guard on the real model that crashed the nszu analytics graph."""
    pytest.importorskip("contextunity.router")
    from contextunity.router.modules.models.types import ModelRequest, TextPart

    request = ModelRequest(
        parts=[TextPart(text="hi")],
        metadata={"nested": {"list": [1, 2.5, "x", None, {"deep": True}]}},
    )
    assert request.metadata["nested"]["list"][-1] == {"deep": True}
