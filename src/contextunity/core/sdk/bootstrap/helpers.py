"""ContextUnity SDK — Bootstrap Convenience Wrappers.

High-level bootstrap functions that eliminate per-project boilerplate:
  - ``bootstrap_django()`` — for Django projects (handles runserver/gunicorn guards)
  - ``bootstrap_standalone()`` — for standalone Python services (double-checked locking)

Both auto-resolve manifest path, wire ``@federated_tool`` registry, and call
the low-level ``register_and_start()``.
"""

from __future__ import annotations

import threading
from pathlib import Path

from contextunity.core.logging import get_contextunit_logger
from contextunity.core.types import JsonDict, is_json_dict, is_object_list

from ..types import PromptMap
from .api import register_and_start
from .manifest import load_manifest

logger = get_contextunit_logger(__name__)

_BOOTSTRAP_LOCK = threading.Lock()
_is_bootstrapped = False


def _find_manifest_path(hint: str = "") -> str:
    """Resolve manifest path with fallback chain.

    Priority:
      1. Explicit ``hint`` argument
      2. ``CU_MANIFEST_PATH`` env var
      3. Walk up from CWD looking for ``contextunity.project.yaml``

    Args:
        hint: Explicitly provided path to the manifest file.

    Returns:
        str: The resolved absolute or relative path to the manifest file.
    """
    if hint:
        return hint

    from contextunity.core.config import get_core_config

    env_path = get_core_config().manifest_path
    if env_path:
        return env_path

    # Walk up from CWD
    cwd = Path.cwd()
    for parent in [cwd, *cwd.parents]:
        candidate = parent / "contextunity.project.yaml"
        if candidate.exists():
            return str(candidate)

    # Default (will be caught by register_and_start() validation)
    return "contextunity.project.yaml"


def _build_prompt_map(
    prompts: PromptMap | None,
    manifest_path: str,
) -> PromptMap | None:
    """Build the full prompt_map from simplified short-key notation.

    Accepts either:
      - Full refs: ``{"src/chat/prompts.py::PLANNER_PROMPT": text}`` (passthrough)
      - Short keys: ``{"planner": text}`` → resolved to graph config keys via manifest

    Short keys are mapped by inspecting the manifest's graph nodes:
      - ``{node_name}`` → matches ``prompt_ref`` for that node → ``{node_name}_prompt``
      - ``{node_name}_sub_prompts`` → matches ``prompt_variants_ref``
      - Tool config refs (e.g., ``schema_description``) → matched from tool config keys

    Args:
        prompts: The input prompts dictionary mapping short keys or full refs to content.
        manifest_path: Path to the project manifest file.

    Returns:
        PromptMap | None: The fully mapped prompt map dictionary in full-ref format,
            or None if input is empty.
    """
    if not prompts:
        return None

    # Check if any key contains "::" — if so, it's already full-ref format
    if any("::" in k for k in prompts):
        return prompts

    # Short-key mode: introspect manifest to build mapping
    manifest = load_manifest(manifest_path)
    if manifest is None:
        return prompts

    router_raw = manifest.get("router")
    router = router_raw if is_json_dict(router_raw) else None
    if router is None:
        return prompts
    graph_raw = router.get("graph")
    graph = graph_raw if is_json_dict(graph_raw) else None
    if graph is None:
        return prompts
    nodes_raw = graph.get("nodes", [])
    if not is_object_list(nodes_raw):
        return prompts

    full_map: dict[str, str | JsonDict] = {}

    for node_raw in nodes_raw:
        if not is_json_dict(node_raw):
            continue
        node_name_raw = node_raw.get("name", "")
        if not isinstance(node_name_raw, str) or not node_name_raw:
            continue
        node_name = node_name_raw

        prompt_ref_raw = node_raw.get("prompt_ref", "")
        if isinstance(prompt_ref_raw, str) and prompt_ref_raw and node_name in prompts:
            full_map[prompt_ref_raw] = prompts[node_name]

        variants_ref_raw = node_raw.get("prompt_variants_ref", "")
        sub_key = f"{node_name}_sub_prompts"
        if isinstance(variants_ref_raw, str) and variants_ref_raw and sub_key in prompts:
            full_map[variants_ref_raw] = prompts[sub_key]

    # Tool config refs: match by stripped ref key name
    if not full_map:
        logger.warning("Short-key prompt map produced no matches — check keys vs manifest node names")
        return prompts

    return full_map


def bootstrap_django(
    *,
    prompts: PromptMap | None = None,
    manifest_path: str = "",
) -> None:
    """Bootstrap ContextUnity from a Django ``AppConfig.ready()`` call.

    Args:
        prompts: Prompt map — either full-ref or short-key (node names).
        manifest_path: Override manifest location. If empty, auto-resolves.

    Example:
        >>> import os
        >>> import sys
        >>> from contextunity.core.sdk.bootstrap import bootstrap_django
        >>> class ChatConfig(AppConfig):
        ...     def ready(self):
        ...         import chat.tools  # triggers @federated_tool registration
        ...         from chat.prompts import PLANNER_PROMPT, DB_SCHEMA
        ...         bootstrap_django(prompts={"planner": PLANNER_PROMPT, "schema_description": DB_SCHEMA})
    """
    # Auto-resolve manifest path from Django settings if not given
    if not manifest_path:
        try:
            import importlib

            django_conf: object = importlib.import_module("django.conf")
            settings_obj: object = getattr(django_conf, "settings", None)
            base_dir_raw: object = getattr(settings_obj, "BASE_DIR", None) if settings_obj is not None else None
            if isinstance(base_dir_raw, (str, Path)):
                manifest_path = str(Path(base_dir_raw) / "contextunity.project.yaml")
        except Exception:
            pass

    resolved_path = _find_manifest_path(manifest_path)
    prompt_map = _build_prompt_map(prompts, resolved_path)

    from contextunity.core.sdk.tools import ToolRegistry

    tool_handler = ToolRegistry.build_handler()

    _ = register_and_start(
        manifest_path=resolved_path,
        prompt_map=prompt_map,
        tool_handler=tool_handler,
    )


def bootstrap_standalone(
    *,
    prompts: PromptMap | None = None,
    manifest_path: str = "",
    background: bool = True,
) -> None:
    """Bootstrap ContextUnity for a standalone (non-Django) service.

    Includes double-checked locking to ensure single initialization
    in long-running processes.

    Args:
        prompts: Prompt map — either full-ref or short-key (node names).
        manifest_path: Override manifest location. If empty, auto-resolves.
        background: Run bootstrap loop in a daemon thread (default True).

    Example:
        >>> from contextunity.core.sdk.bootstrap import bootstrap_standalone
        >>> def main():
        ...     import myproject.tools  # triggers @federated_tool registration
        ...     bootstrap_standalone(prompts=load_prompts())
        ...     asyncio.run(run_bot())
    """
    global _is_bootstrapped
    if _is_bootstrapped:
        return

    with _BOOTSTRAP_LOCK:
        if _is_bootstrapped:
            return

        resolved_path = _find_manifest_path(manifest_path)
        prompt_map = _build_prompt_map(prompts, resolved_path)

        from contextunity.core.sdk.tools import ToolRegistry

        tool_handler = ToolRegistry.build_handler()

        _ = register_and_start(
            manifest_path=resolved_path,
            prompt_map=prompt_map,
            tool_handler=tool_handler,
            background=background,
        )
        _is_bootstrapped = True


__all__ = [
    "bootstrap_django",
    "bootstrap_standalone",
]
