"""ContextUnity SDK — Federated Tool Registration and Dispatch.
Projects register tools with ``@federated_tool("name")`` and the SDK builds
the unified ``tool_handler`` callback automatically.
Usage in project code::
    from contextunity.core.sdk.tools import federated_tool
    @federated_tool("medical_sql")
    def execute_medical_sql(sql: str, *, ctx: FederatedToolCallContext) -> dict:
        '''All tools execute within your project process.
        The SDK automatically connects them to the Router via gRPC BiDi stream.
        '''
        assert ctx.caller_tenant
        return execute_safe_query(sql)
    @federated_tool("store_news_results")
    async def store_news(posts: list[dict], *, ctx: FederatedToolCallContext) -> dict:
        ...
        return {"status": "stored", "count": len(posts)}
The registry is consumed by ``register_and_start()`` as a fallback when no
explicit ``tool_handler`` is provided. ``ToolRegistry.execute()`` exposes the
same dispatch contract for in-process callers such as durable workflows.
"""

from __future__ import annotations

import abc
import asyncio
import inspect
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, TypeVar, override

from contextunity.core.exceptions import ConfigurationError, ContextUnityError
from contextunity.core.sdk.payload import normalize_tool_result
from contextunity.core.sdk.types import FederatedToolHandler, ToolResult
from contextunity.core.types import ContextUnitPayload

if TYPE_CHECKING:
    from contextunity.core.sdk.streaming.bidi import FederatedToolCallContext
    from contextunity.core.sdk.types import ToolHandler

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Base tool hierarchy
# ---------------------------------------------------------------------------


class BaseTool(abc.ABC):
    """Abstract base class for all federated tools.

    Subclass this to create custom tool execution strategies (e.g. remote
    invocation, workflow-backed tools). The registry accepts any ``BaseTool``.

    Subclasses **must** implement ``execute()`` (async path, used by
    ``ToolRegistry.execute()`` inside a running loop) and **may** override
    ``execute_sync()`` (sync path, used by ``build_handler()``).

    The default ``execute_sync()`` delegates to ``asyncio.run(self.execute(...))``.
    Override it in subclasses whose tools touch sync-only frameworks
    (e.g. Django ORM) that forbid being called from within an event loop.
    """

    name: str

    @abc.abstractmethod
    async def execute(
        self,
        args: ContextUnitPayload,
        auth_ctx: FederatedToolCallContext,
    ) -> ToolResult:
        """Async execution — used when a running event loop is available.

        Args:
            args: The arguments passed to the tool.
            auth_ctx: The federated tool call context.

        Returns:
            ToolResult: Tool execution payload returned to the Router.
        """

    def execute_sync(
        self,
        args: ContextUnitPayload,
        auth_ctx: FederatedToolCallContext,
    ) -> ToolResult:
        """Sync execution — used by ``build_handler()`` from a plain thread.

        Args:
            args: The arguments passed to the tool.
            auth_ctx: The federated tool call context.

        Returns:
            ToolResult: Tool execution payload returned to the Router.
        """
        return asyncio.run(self.execute(args, auth_ctx))


class FunctionTool(BaseTool):
    """A tool created by wrapping a plain function via ``@federated_tool``."""

    name: str
    fn: FederatedToolHandler
    is_async: bool
    sig_params: set[str]

    def __init__(self, name: str, fn: FederatedToolHandler) -> None:
        """Initialize a FunctionTool wrapper.

        Args:
            name: The registered name of the tool.
            fn: The target function to wrap.
        """
        self.name = name
        self.fn = fn
        call_target = fn if inspect.isfunction(fn) or inspect.ismethod(fn) else fn.__call__
        self.is_async = inspect.iscoroutinefunction(call_target)
        # Cache parameter names for arg injection.
        # follow_wrapped=False preserves the runtime wrapper signature used by
        # Toolkit bridge functions (ctx injection happens there).
        self.sig_params = set(
            inspect.signature(call_target, follow_wrapped=False).parameters.keys(),
        )

    def _build_call_kwargs(
        self,
        args: ContextUnitPayload,
        auth_ctx: FederatedToolCallContext,
    ) -> ContextUnitPayload:
        """Build keyword arguments for the wrapped function.

        Args:
            args: The arguments passed to the tool.
            auth_ctx: The federated tool call context.

        Returns:
            ContextUnitPayload: Keyword arguments filtered to the wrapped signature.
        """
        call_kwargs: ContextUnitPayload = {}
        for key, value in args.items():
            if key in self.sig_params:
                call_kwargs[key] = value

        if "ctx" in self.sig_params:
            call_kwargs["ctx"] = auth_ctx

        # Pass through extra kwargs if the function accepts **kwargs
        has_var_keyword = any(
            p.kind == inspect.Parameter.VAR_KEYWORD
            for p in inspect.signature(
                self.fn if inspect.isfunction(self.fn) or inspect.ismethod(self.fn) else self.fn.__call__,
                follow_wrapped=False,
            ).parameters.values()
        )
        if has_var_keyword:
            for key, value in args.items():
                if key not in call_kwargs:
                    call_kwargs[key] = value

        return call_kwargs

    @staticmethod
    def _normalize_result(result: object) -> ToolResult:
        """Normalize the result of a tool execution into a dictionary."""
        return normalize_tool_result(result)

    @override
    async def execute(
        self,
        args: ContextUnitPayload,
        auth_ctx: FederatedToolCallContext,
    ) -> ToolResult:
        """Execute the wrapped function asynchronously.

        Args:
            args: The arguments passed to the tool.
            auth_ctx: The federated tool call context.

        Returns:
            ToolResult: Tool execution payload returned to the Router.
        """
        call_kwargs = self._build_call_kwargs(args, auth_ctx)
        result = self.fn(**call_kwargs)
        if inspect.isawaitable(result):
            result = await result
        return self._normalize_result(result)

    @override
    def execute_sync(
        self,
        args: ContextUnitPayload,
        auth_ctx: FederatedToolCallContext,
    ) -> ToolResult:
        """Sync path — sync tools run directly, async tools via ``asyncio.run()``.

        Args:
            args: The arguments passed to the tool.
            auth_ctx: The federated tool call context.

        Returns:
            ToolResult: Tool execution payload returned to the Router.
        """
        call_kwargs = self._build_call_kwargs(args, auth_ctx)
        if self.is_async:
            coro = self.fn(**call_kwargs)
            if not inspect.iscoroutine(coro):
                raise TypeError(f"Async federated tool '{self.name}' must return a coroutine")
            return self._normalize_result(asyncio.run(coro))
        return self._normalize_result(self.fn(**call_kwargs))


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class ToolRegistry:
    """Singleton registry of ``BaseTool`` objects.

    Thread-safe for registration (decoration happens at import time).
    The built handler is called from a single BiDi stream thread.
    """

    _tools: dict[str, BaseTool] = {}

    @classmethod
    def register(cls, tool: BaseTool) -> None:
        """Register a tool instance. Called by the ``@federated_tool`` decorator.

        Args:
            tool: The tool instance to register.

        Raises:
            ValueError: If a tool with the same name is already registered.
        """
        if tool.name in cls._tools:
            existing = cls._tools[tool.name]
            raise ConfigurationError(
                f"Federated tool '{tool.name}' already registered (existing: {type(existing).__name__})"
            )
        cls._tools[tool.name] = tool
        logger.debug("Registered federated tool: %s", tool.name)

    @classmethod
    def has_tools(cls) -> bool:
        """Return True if any tools are registered.

        Returns:
            bool: True if any tools are registered, False otherwise.
        """
        return bool(cls._tools)

    @classmethod
    def tool_names(cls) -> list[str]:
        """Return a list of registered tool names.

        Returns:
            list[str]: The list of registered tool names.
        """
        return list(cls._tools.keys())

    @classmethod
    async def execute(
        cls,
        tool_name: str,
        args: ContextUnitPayload,
        auth_ctx: FederatedToolCallContext,
    ) -> ToolResult:
        """Execute a registered tool inside an existing event loop.

        Args:
            tool_name: The name of the registered tool to execute.
            args: The arguments to pass to the tool.
            auth_ctx: The federated tool call context.

        Returns:
            ToolResult: Tool execution payload returned to the Router.

        Raises:
            ValueError: If the tool_name is not registered.
        """
        tool = cls._tools.get(tool_name)
        if tool is None:
            registered = ", ".join(sorted(cls._tools.keys()))
            raise ContextUnityError(f"Unknown federated tool: '{tool_name}'. Registered: [{registered}]")

        return await tool.execute(args, auth_ctx)

    @classmethod
    def build_handler(cls) -> ToolHandler | None:
        """Build a unified tool_handler callback from all registered tools.

        Returns:
            ToolHandler | None: The unified tool handler callback, or None
            if no tools are registered.
        """
        if not cls._tools:
            return None

        # Snapshot the registry so late registrations don't cause races
        tools = dict(cls._tools)

        def handler(
            tool_name: str,
            args: ContextUnitPayload,
            auth_ctx: FederatedToolCallContext,
        ) -> ToolResult:
            """Handle an incoming tool invocation request synchronously.

            Args:
                tool_name: The name of the tool to invoke.
                args: The arguments passed to the tool.
                auth_ctx: The federated tool call context.

            Returns:
                ToolResult: Tool execution payload returned to the Router.

            Raises:
                ValueError: If the tool_name is not registered.
            """
            tool = tools.get(tool_name)
            if tool is None:
                registered = ", ".join(sorted(tools.keys()))
                raise ContextUnityError(f"Unknown federated tool: '{tool_name}'. Registered: [{registered}]")

            return tool.execute_sync(args, auth_ctx)

        return handler

    @classmethod
    def clear(cls) -> None:
        """Clear all registrations. Used in tests."""
        cls._tools.clear()


# ---------------------------------------------------------------------------
# @federated_tool decorator
# ---------------------------------------------------------------------------

_F = TypeVar("_F", bound=FederatedToolHandler)


def federated_tool(name: str) -> Callable[[_F], _F]:
    """Decorator to register a project-side federated tool.

    Args:
        name: The name to register the tool under.

    Returns:
        Callable[[_F], _F]: The decorator function wrapping and registering the target.
    """

    def decorator(fn: _F) -> _F:
        """Wrap and register the federated tool.

        Args:
            fn: The target function/callable to wrap.

        Returns:
            _F: The original function/callable unchanged (registered in registry).
        """
        tool = FunctionTool(name, fn)
        ToolRegistry.register(tool)
        return fn

    return decorator


__all__ = [
    "BaseTool",
    "FunctionTool",
    "ToolRegistry",
    "federated_tool",
]
