"""ContextUnity SDK — Federated Tool Decorator & Registry.

Eliminates boilerplate if/elif dispatch in project tool handlers.
Projects register tools with ``@federated_tool("name")`` and the SDK
builds the unified ``tool_handler`` callback automatically.

Usage in project code::

    from contextunity.core.sdk.tools import federated_tool

    @federated_tool("medical_sql")
    def execute_medical_sql(sql: str, *, ctx: ToolCallContext) -> dict:
        '''All tools execute within your project process.
        The SDK automatically connects them to the Router via gRPC BiDi stream.
        '''
        assert ctx.caller_tenant
        return execute_safe_query(sql)

    @federated_tool("store_news_results")
    async def store_news(posts: list[dict], *, ctx: ToolCallContext) -> dict:
        # Async tools are wrapped in asyncio.run() automatically.
        ...
        return {"status": "stored", "count": len(posts)}

The registry is consumed by ``register_and_start()`` as a fallback when
no explicit ``tool_handler`` is provided.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from contextunity.core.sdk.streaming.bidi import FederatedToolCallContext

logger = logging.getLogger(__name__)

# Type alias — matches the tool_handler signature expected by bidi.py
ToolHandlerFn = Callable[[str, dict[str, Any], "FederatedToolCallContext"], dict[str, Any]]


class _ToolEntry:
    """Internal: wraps a registered tool function."""

    __slots__ = ("name", "fn", "is_async", "sig_params")

    def __init__(self, name: str, fn: Callable, is_async: bool):
        self.name = name
        self.fn = fn
        self.is_async = is_async
        # Cache parameter names for arg injection
        self.sig_params = set(inspect.signature(fn).parameters.keys())


class ToolRegistry:
    """Singleton registry of ``@federated_tool`` decorated functions.

    Thread-safe for registration (decoration happens at import time).
    The built handler is called from a single BiDi stream thread.
    """

    _tools: dict[str, _ToolEntry] = {}

    @classmethod
    def register(cls, name: str, fn: Callable) -> None:
        """Register a tool function. Called by the ``@federated_tool`` decorator."""
        if name in cls._tools:
            raise ValueError(
                f"Federated tool '{name}' already registered "
                f"(existing: {cls._tools[name].fn.__module__}.{cls._tools[name].fn.__qualname__})"
            )
        is_async = inspect.iscoroutinefunction(fn)
        cls._tools[name] = _ToolEntry(name, fn, is_async)
        logger.debug("Registered federated tool: %s (async=%s)", name, is_async)

    @classmethod
    def has_tools(cls) -> bool:
        """Return True if any tools are registered."""
        return bool(cls._tools)

    @classmethod
    def tool_names(cls) -> list[str]:
        """Return list of registered tool names."""
        return list(cls._tools.keys())

    @classmethod
    def build_handler(cls) -> ToolHandlerFn | None:
        """Build a unified tool_handler callback from all registered tools.

        Returns None if no tools are registered.
        The returned handler has the standard SDK signature:
            (tool_name: str, args: dict, auth_ctx: FederatedToolCallContext) -> dict
        """
        if not cls._tools:
            return None

        # Snapshot the registry so late registrations don't cause races
        tools = dict(cls._tools)

        def handler(
            tool_name: str,
            args: dict[str, Any],
            auth_ctx: FederatedToolCallContext,
        ) -> dict[str, Any]:
            entry = tools.get(tool_name)
            if entry is None:
                registered = ", ".join(sorted(tools.keys()))
                raise ValueError(f"Unknown federated tool: '{tool_name}'. Registered: [{registered}]")

            # Build kwargs: pass only what the function accepts
            call_kwargs: dict[str, Any] = {}
            for key, value in args.items():
                if key in entry.sig_params:
                    call_kwargs[key] = value

            # Inject ctx if the function declares it
            if "ctx" in entry.sig_params:
                call_kwargs["ctx"] = auth_ctx

            # If the function accepts **kwargs, pass everything
            has_var_keyword = any(
                p.kind == inspect.Parameter.VAR_KEYWORD for p in inspect.signature(entry.fn).parameters.values()
            )
            if has_var_keyword:
                # Merge remaining args that weren't matched
                for key, value in args.items():
                    if key not in call_kwargs:
                        call_kwargs[key] = value

            if entry.is_async:
                return asyncio.run(entry.fn(**call_kwargs))

            return entry.fn(**call_kwargs)

        return handler

    @classmethod
    def clear(cls) -> None:
        """Clear all registrations. Used in tests."""
        cls._tools.clear()


def federated_tool(name: str) -> Callable:
    """Decorator to register a project-side federated tool.

    The decorated function receives **typed keyword arguments** extracted
    from the raw ``args`` dict, plus an optional ``ctx`` parameter of type
    ``FederatedToolCallContext`` (injected automatically if declared).

    Async functions are supported — the SDK wraps them with ``asyncio.run()``.

    Args:
        name: Tool name as declared in ``contextunity.project.yaml`` under
              ``router.tools[].name``.

    Example::

        @federated_tool("medical_sql")
        def execute_sql(sql: str, *, ctx: FederatedToolCallContext) -> dict:
            '''All tools execute within your project process.
            The SDK automatically connects them to the Router via gRPC BiDi stream.
            '''
            assert ctx.caller_tenant
            return run_query(sql)

        @federated_tool("publish_post")
        async def publish(post_id: int, *, ctx: FederatedToolCallContext) -> dict:
            '''All tools execute within your project process.
            The SDK automatically connects them to the Router via gRPC BiDi stream.
            '''
            assert ctx.caller_tenant
            await send_to_telegram(post_id)
            return {"status": "published"}
    """

    def decorator(fn: Callable) -> Callable:
        ToolRegistry.register(name, fn)
        return fn

    return decorator


__all__ = [
    "ToolRegistry",
    "federated_tool",
]
