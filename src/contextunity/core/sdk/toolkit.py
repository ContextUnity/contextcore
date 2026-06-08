"""Federated toolkit framework — ``@tool`` decorator and ``FederatedToolkit`` base."""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import ClassVar, Literal, Protocol, TypeGuard, TypeVar, runtime_checkable

from contextunity.core.exceptions import ContextUnityError, register_error
from contextunity.core.narrowing import await_object
from contextunity.core.sdk.streaming.bidi import FederatedToolCallContext
from contextunity.core.sdk.types import FederatedToolHandler, StrictPayloadModel
from pydantic import BaseModel, ConfigDict, Field

# Unconstrained: preserves bound-method signatures under strict pyright (FederatedToolHandler's
# ``*args: object`` protocol is too wide for contravariant parameter checking on ``self``).
_F = TypeVar("_F")


@runtime_checkable
class _AnnotatedTool(Protocol):
    """Tool method decorated with ``@tool``."""

    tool_name: str
    tool_config: ToolConfig

    def __call__(self, *args: object, **kwargs: object) -> object: ...


@runtime_checkable
class _ToolContextLike(Protocol):
    caller_tenant: str


def _is_tool_context(value: object | None) -> TypeGuard[_ToolContextLike | None]:
    if value is None:
        return True
    if isinstance(value, FederatedToolCallContext):
        return True
    caller_tenant = getattr(value, "caller_tenant", None)
    return isinstance(caller_tenant, str)


def _is_annotated_tool(method: object) -> TypeGuard[_AnnotatedTool]:
    return (
        callable(method)
        and isinstance(getattr(method, "tool_name", None), str)
        and isinstance(getattr(method, "tool_config", None), ToolConfig)
    )


def _class_namespace_members(base: type) -> dict[str, object]:
    """Return class namespace entries as an ``object`` map for tool discovery.

    Introspection boundary: ``type.__dict__`` is an open namespace at runtime.
    Values are stored as ``object`` and narrowed by ``_is_annotated_tool``.
    """
    return dict(base.__dict__)


@register_error("TOOLKIT_RESOLUTION_ERROR")
class ToolkitResolutionError(ContextUnityError):
    """Raised when toolkit resolution fails (unknown name, duplicate, etc.)."""

    code: str = "TOOLKIT_RESOLUTION_ERROR"


class ToolConfig(BaseModel):
    """Per-tool runtime configuration."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", frozen=True)

    timeout: int = Field(default=30, ge=1)
    retries: int = Field(default=2, ge=0, le=10)
    retry_policy: Literal["exponential", "linear", "none"] = "exponential"


class ToolDefinition(StrictPayloadModel, arbitrary_types_allowed=True):
    """Internal definition of a registered federated tool."""

    name: str
    fn: FederatedToolHandler
    config: ToolConfig


def tool(
    name: str | None = None,
    *,
    timeout: int = 30,
    retries: int = 2,
    retry_policy: Literal["exponential", "linear", "none"] = "exponential",
) -> Callable[[_F], _F]:
    """Mark a method as a federated tool."""
    config = ToolConfig(timeout=timeout, retries=retries, retry_policy=retry_policy)

    def decorator(fn: _F) -> _F:
        tool_name = name or getattr(fn, "__name__", None)
        if tool_name is None:
            raise TypeError("@tool() requires an explicit name= argument for callables without __name__")
        setattr(fn, "tool_name", tool_name)
        setattr(fn, "tool_config", config)
        return fn

    return decorator


class FederatedToolkit:
    """Base class for federated tool groups."""

    _registry: ClassVar[dict[str, type[FederatedToolkit]]] = {}
    _stateful: ClassVar[bool] = False

    def __init__(self) -> None:
        self.ctx: _ToolContextLike | None = None

    def __init_subclass__(cls, stateful: bool = False, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        cls._stateful = stateful
        name = cls.__name__
        if name in cls._registry:
            raise ToolkitResolutionError(f"Toolkit '{name}' already registered by {cls._registry[name].__module__}")
        cls._registry[name] = cls

    @classmethod
    def resolve(cls, name: str) -> type[FederatedToolkit]:
        if name not in cls._registry:
            registered = ", ".join(sorted(cls._registry))
            raise ToolkitResolutionError(f"Unknown toolkit '{name}'. Registered: [{registered}]")
        return cls._registry[name]

    @classmethod
    def discover_tools(cls, *args: object, **kwargs: object) -> dict[str, ToolDefinition]:
        tools: dict[str, ToolDefinition] = {}
        shared_instance = cls(*args, **kwargs) if cls._stateful else None

        seen_names: set[str] = set()
        for base in reversed(cls.__mro__):
            if base is object:
                continue
            # Class namespace introspection — values are ``object`` until narrowed by guard.
            for attr_name, member in _class_namespace_members(base).items():
                if attr_name in seen_names:
                    continue
                seen_names.add(attr_name)
                if not _is_annotated_tool(member):
                    continue

                method = member
                tool_name = method.tool_name
                tool_config = method.tool_config

                def create_wrapper(
                    bound_method: _AnnotatedTool = method,
                    tk_cls: type[FederatedToolkit] = cls,
                    tk_instance: FederatedToolkit | None = shared_instance,
                ) -> FederatedToolHandler:
                    @functools.wraps(bound_method)
                    async def wrapper(*call_args: object, **call_kwargs: object) -> object:
                        instance = tk_instance if tk_instance is not None else tk_cls()
                        ctx_raw = call_kwargs.pop("ctx", None)
                        if _is_tool_context(ctx_raw):
                            instance.ctx = ctx_raw
                        else:
                            instance.ctx = None
                        raw_outcome: object = bound_method(instance, *call_args, **call_kwargs)
                        if inspect.iscoroutine(raw_outcome):
                            return await await_object(raw_outcome)
                        return raw_outcome

                    params = list(inspect.signature(bound_method).parameters.values())
                    if not any(param.name == "ctx" for param in params):
                        params.append(inspect.Parameter("ctx", inspect.Parameter.KEYWORD_ONLY, default=None))
                    object.__setattr__(wrapper, "__signature__", inspect.Signature(params))
                    return wrapper

                tools[tool_name] = ToolDefinition(
                    name=tool_name,
                    fn=create_wrapper(),
                    config=tool_config,
                )
        return tools
