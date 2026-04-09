"""ContextUnity SDK — Bootstrap Convenience Wrappers.

High-level bootstrap functions that eliminate per-project boilerplate:
  - ``bootstrap_django()`` — for Django projects (handles runserver/gunicorn guards)
  - ``bootstrap_standalone()`` — for standalone Python services (double-checked locking)

Both auto-resolve manifest path, wire ``@federated_tool`` registry, and call
the low-level ``register_and_start()``.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any

from contextcore.logging import get_context_unit_logger

from . import api as _bootstrap_api

logger = get_context_unit_logger(__name__)

_BOOTSTRAP_LOCK = threading.Lock()
_BOOTSTRAPPED = False


def _find_manifest_path(hint: str = "") -> str:
    """Resolve manifest path with fallback chain.

    Priority:
      1. Explicit ``hint`` argument
      2. ``CONTEXTUNITY_MANIFEST_PATH`` env var
      3. Walk up from CWD looking for ``contextunity.project.yaml``
    """
    if hint:
        return hint

    env_path = os.environ.get("CONTEXTUNITY_MANIFEST_PATH", "")
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
    prompts: dict[str, Any] | None,
    manifest_path: str,
) -> dict[str, Any] | None:
    """Build the full prompt_map from simplified short-key notation.

    Accepts either:
      - Full refs: ``{"src/chat/prompts.py::PLANNER_PROMPT": text}`` (passthrough)
      - Short keys: ``{"planner": text}`` → resolved to graph config keys via manifest

    Short keys are mapped by inspecting the manifest's graph nodes:
      - ``{node_name}`` → matches ``prompt_ref`` for that node → ``{node_name}_prompt``
      - ``{node_name}_sub_prompts`` → matches ``prompt_variants_ref``
      - Tool config refs (e.g., ``schema_description``) → matched from tool config keys

    Returns the prompt_map in the format expected by ``_resolve_prompt_refs()``.
    """
    if not prompts:
        return None

    # Check if any key contains "::" — if so, it's already full-ref format
    if any("::" in k for k in prompts):
        return prompts

    # Short-key mode: introspect manifest to build mapping
    try:
        import yaml

        with open(manifest_path, encoding="utf-8") as f:
            manifest_dict = yaml.safe_load(f)
    except Exception as e:
        logger.warning("Cannot read manifest for prompt mapping: %s — using keys as-is", e)
        return prompts

    router = manifest_dict.get("router", {})
    graph = router.get("graph", {})
    nodes = graph.get("nodes", [])
    tools = router.get("tools", [])

    full_map: dict[str, Any] = {}

    for node in nodes:
        node_name = node.get("name", "")
        if not node_name:
            continue

        # Single prompt: "planner" → prompt_ref value
        prompt_ref = node.get("prompt_ref", "")
        if prompt_ref and node_name in prompts:
            full_map[prompt_ref] = prompts[node_name]

        # Sub-prompts: "visualizer_sub_prompts" key
        variants_ref = node.get("prompt_variants_ref", "")
        sub_key = f"{node_name}_sub_prompts"
        if variants_ref and sub_key in prompts:
            full_map[variants_ref] = prompts[sub_key]

    # Tool config refs: match by stripped ref key name
    for tool in tools:
        tool_config = tool.get("config", {})
        for ref_key in tool_config:
            if ref_key.endswith("_ref"):
                ref_value = tool_config[ref_key]
                # Try matching by the config field name without _ref suffix
                short_name = ref_key[:-4]  # e.g., "schema_description_ref" → "schema_description"
                if short_name in prompts:
                    full_map[ref_value] = prompts[short_name]

    if not full_map:
        logger.warning("Short-key prompt map produced no matches — check keys vs manifest node names")
        return prompts

    return full_map


def bootstrap_django(
    *,
    prompts: dict[str, Any] | None = None,
    manifest_path: str = "",
) -> None:
    """Bootstrap ContextUnity from a Django ``AppConfig.ready()`` call.

    Args:
        prompts: Prompt map — either full-ref or short-key (node names).
        manifest_path: Override manifest location. If empty, auto-resolves.

    Example::

        import os
        import sys
        from contextcore.sdk.bootstrap import bootstrap_django

        class ChatConfig(AppConfig):
            def ready(self):
                # Avoid double startup in runserver parent process
                is_runserver = "runserver" in sys.argv
                is_gunicorn = "gunicorn" in os.environ.get("SERVER_SOFTWARE", "")

                if is_gunicorn or (is_runserver and os.environ.get("RUN_MAIN") == "true"):
                    import chat.tools  # triggers @federated_tool registration
                    from chat.prompts import PLANNER_PROMPT, DB_SCHEMA

                    bootstrap_django(prompts={"planner": PLANNER_PROMPT, "schema_description": DB_SCHEMA})
    """
    # Auto-resolve manifest path from Django settings if not given
    if not manifest_path:
        try:
            from django.conf import settings as django_settings

            manifest_path = str(Path(django_settings.BASE_DIR) / "contextunity.project.yaml")
        except Exception:
            pass

    resolved_path = _find_manifest_path(manifest_path)
    prompt_map = _build_prompt_map(prompts, resolved_path)

    from contextcore.sdk.tools import ToolRegistry

    tool_handler = ToolRegistry.build_handler()

    _bootstrap_api.register_and_start(
        manifest_path=resolved_path,
        prompt_map=prompt_map,
        tool_handler=tool_handler,
    )


def bootstrap_standalone(
    *,
    prompts: dict[str, Any] | None = None,
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

    Example::

        from contextcore.sdk.bootstrap import bootstrap_standalone

        def main():
            import myproject.tools  # triggers @federated_tool registration
            bootstrap_standalone(prompts=load_prompts())
            asyncio.run(run_bot())
    """
    global _BOOTSTRAPPED
    if _BOOTSTRAPPED:
        return

    with _BOOTSTRAP_LOCK:
        if _BOOTSTRAPPED:
            return

        resolved_path = _find_manifest_path(manifest_path)
        prompt_map = _build_prompt_map(prompts, resolved_path)

        from contextcore.sdk.tools import ToolRegistry

        tool_handler = ToolRegistry.build_handler()

        _bootstrap_api.register_and_start(
            manifest_path=resolved_path,
            prompt_map=prompt_map,
            tool_handler=tool_handler,
            background=background,
        )
        _BOOTSTRAPPED = True


__all__ = [
    "bootstrap_django",
    "bootstrap_standalone",
]
