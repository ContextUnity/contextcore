"""Tests for cu.core.sdk.tools — @federated_tool decorator and ToolRegistry."""

from __future__ import annotations

import asyncio

import pytest
from contextunity.core.sdk.streaming.bidi import FederatedToolCallContext
from contextunity.core.sdk.tools import ToolRegistry, federated_tool


@pytest.fixture(autouse=True)
def _clean_registry():
    """Clear the tool registry before and after each test."""
    ToolRegistry.clear()
    yield
    ToolRegistry.clear()


def _make_ctx(tool_name: str = "test_tool") -> FederatedToolCallContext:
    return FederatedToolCallContext(
        project_id="test-project",
        tool_name=tool_name,
        request_id="req-001",
        caller_tenant="test-tenant",
        user_id="user-1",
    )


class TestFederatedToolDecorator:
    """Test @federated_tool registration."""

    def test_registers_sync_tool(self):
        @federated_tool("my_sync_tool")
        def my_tool(x: int) -> dict:
            return {"result": x}

        assert ToolRegistry.has_tools()
        assert "my_sync_tool" in ToolRegistry.tool_names()

    def test_registers_async_tool(self):
        @federated_tool("my_async_tool")
        async def my_tool(x: int) -> dict:
            return {"result": x}

        assert "my_async_tool" in ToolRegistry.tool_names()

    def test_duplicate_name_raises(self):
        @federated_tool("same_name")
        def tool_a() -> dict:
            return {}

        with pytest.raises(ValueError, match="already registered"):

            @federated_tool("same_name")
            def tool_b() -> dict:
                return {}

    def test_decorator_preserves_function(self):
        @federated_tool("preserved")
        def my_fn(x: int) -> dict:
            return {"x": x}

        # The function itself is unchanged
        assert my_fn(42) == {"x": 42}


class TestToolRegistryHandler:
    """Test ToolRegistry.build_handler()."""

    def test_build_handler_empty_registry(self):
        handler = ToolRegistry.build_handler()
        assert handler is None

    def test_sync_tool_dispatch(self):
        @federated_tool("add_numbers")
        def add_numbers(a: int, b: int) -> dict:
            return {"sum": a + b}

        handler = ToolRegistry.build_handler()
        assert handler is not None

        ctx = _make_ctx("add_numbers")
        result = handler("add_numbers", {"a": 3, "b": 7}, ctx)
        assert result == {"sum": 10}

    def test_async_tool_dispatch(self):
        @federated_tool("async_greet")
        async def async_greet(name: str) -> dict:
            await asyncio.sleep(0)
            return {"greeting": f"Hello, {name}!"}

        handler = ToolRegistry.build_handler()
        ctx = _make_ctx("async_greet")
        result = handler("async_greet", {"name": "World"}, ctx)
        assert result == {"greeting": "Hello, World!"}

    def test_unknown_tool_raises(self):
        @federated_tool("known_tool")
        def known_tool() -> dict:
            return {}

        handler = ToolRegistry.build_handler()
        ctx = _make_ctx("unknown_tool")

        with pytest.raises(ValueError, match="Unknown federated tool.*'unknown_tool'"):
            handler("unknown_tool", {}, ctx)

    def test_ctx_injection(self):
        @federated_tool("with_ctx")
        def with_ctx(data: str, *, ctx: FederatedToolCallContext) -> dict:
            return {
                "data": data,
                "tenant": ctx.caller_tenant,
                "user": ctx.user_id,
            }

        handler = ToolRegistry.build_handler()
        ctx = _make_ctx("with_ctx")
        result = handler("with_ctx", {"data": "test"}, ctx)

        assert result["data"] == "test"
        assert result["tenant"] == "test-tenant"
        assert result["user"] == "user-1"

    def test_extra_args_ignored(self):
        """Handler should not pass args the function doesn't accept."""

        @federated_tool("selective")
        def selective(needed: str) -> dict:
            return {"needed": needed}

        handler = ToolRegistry.build_handler()
        ctx = _make_ctx("selective")
        result = handler("selective", {"needed": "yes", "extra": "ignored"}, ctx)
        assert result == {"needed": "yes"}

    def test_kwargs_tool_receives_all(self):
        """Function with **kwargs should receive all arguments."""

        @federated_tool("with_kwargs")
        def with_kwargs(**kwargs) -> dict:
            return {"received": list(sorted(kwargs.keys()))}

        handler = ToolRegistry.build_handler()
        ctx = _make_ctx("with_kwargs")
        result = handler("with_kwargs", {"a": 1, "b": 2, "c": 3}, ctx)
        assert result == {"received": ["a", "b", "c"]}

    def test_multiple_tools_dispatch(self):
        @federated_tool("tool_a")
        def tool_a() -> dict:
            return {"tool": "a"}

        @federated_tool("tool_b")
        def tool_b() -> dict:
            return {"tool": "b"}

        handler = ToolRegistry.build_handler()
        assert handler("tool_a", {}, _make_ctx("tool_a")) == {"tool": "a"}
        assert handler("tool_b", {}, _make_ctx("tool_b")) == {"tool": "b"}


class TestToolRegistryMeta:
    """Test registry metadata methods."""

    def test_clear(self):
        @federated_tool("temp")
        def temp() -> dict:
            return {}

        assert ToolRegistry.has_tools()
        ToolRegistry.clear()
        assert not ToolRegistry.has_tools()
        assert ToolRegistry.tool_names() == []

    def test_tool_names_order(self):
        @federated_tool("beta")
        def beta() -> dict:
            return {}

        @federated_tool("alpha")
        def alpha() -> dict:
            return {}

        names = ToolRegistry.tool_names()
        assert set(names) == {"alpha", "beta"}
