from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import Any

import yaml
from contextunity.core.logging import get_contextunit_logger

logger = get_contextunit_logger(__name__)


def _load_manifest(manifest_path: str) -> dict[str, Any] | None:
    """Load and return manifest dict from YAML file."""
    try:
        with open(manifest_path, encoding="utf-8") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logger.error("Manifest not found: %s", manifest_path)
        return None
    except Exception as e:
        logger.error("Failed to read manifest %s: %s", manifest_path, e)
        return None


def _resolve_prompt_refs(
    manifest_dict: dict[str, Any],
    prompt_map: dict[str, Any],
    project_id: str,
) -> None:
    """Resolve prompt_ref and config refs in-place inside the manifest dict."""
    router = manifest_dict.get("router", {})
    graph = router.get("graph", {})

    if "config" not in graph or not graph["config"]:
        graph["config"] = {}

    for node in graph.get("nodes", []):
        node_name = node.get("name")
        if not node_name:
            continue

        prompt_ref = node.get("prompt_ref")
        if prompt_ref and prompt_ref in prompt_map:
            graph["config"][f"{node_name}_prompt"] = prompt_map[prompt_ref]

        variants_ref = node.get("prompt_variants_ref")
        if variants_ref and variants_ref in prompt_map:
            graph["config"][f"{node_name}_sub_prompts"] = prompt_map[variants_ref]

    for tool in router.get("tools", []):
        tool_config = tool.get("config", {})
        ref_keys = [k for k in tool_config if k.endswith("_ref")]
        for ref_key in ref_keys:
            ref_value = tool_config.pop(ref_key)
            if ref_value in prompt_map:
                target_key = ref_key[:-4]
                tool_config[target_key] = prompt_map[ref_value]
        tool_config["project_id"] = project_id


def _auto_resolve_prompt_refs(
    manifest_dict: dict[str, Any],
    manifest_path: str,
) -> dict[str, Any]:
    """Auto-resolve prompt_ref values from Python modules or YAML files.

    Supports two formats:

    1. **Python module refs** (contains ``::``):
       ``"src/chat/prompts.py::PLANNER_PROMPT"`` → imports the module,
       reads the variable, and maps ``ref → value``.

    2. **Short keys** (no ``::``):
       ``"tech_reporter"`` → looks for ``<project_root>/prompts/agents/<key>.yaml``
       or ``<project_root>/prompts/<key>.yaml`` and reads ``system_prompt`` or
       ``base_prompt`` from it.

    Returns a prompt_map dict suitable for ``_resolve_prompt_refs()``.
    Falls back to empty dict on any resolution failure (non-fatal).
    """
    router = manifest_dict.get("router", {})
    graph = router.get("graph", {})
    nodes = graph.get("nodes", [])
    tools = router.get("tools", [])

    if not nodes and not tools:
        return {}

    # Collect all refs that need resolving
    refs: list[str] = []
    for node in nodes:
        if pr := node.get("prompt_ref"):
            refs.append(pr)
        if vr := node.get("prompt_variants_ref"):
            refs.append(vr)
    for tool in tools:
        for key, val in (tool.get("config") or {}).items():
            if key.endswith("_ref") and isinstance(val, str):
                refs.append(val)

    if not refs:
        return {}

    project_root = Path(manifest_path).resolve().parent
    prompt_map: dict[str, Any] = {}

    for ref in refs:
        if ref in prompt_map:
            continue

        if "::" in ref:
            # Python module ref: "src/chat/prompts.py::VARIABLE_NAME"
            resolved = _resolve_python_ref(ref, project_root)
            if resolved is not None:
                prompt_map[ref] = resolved
        else:
            # Short key: "tech_reporter" → prompts YAML file
            resolved = _resolve_yaml_prompt(ref, project_root)
            if resolved is not None:
                prompt_map[ref] = resolved

    if prompt_map:
        logger.info("Auto-resolved %d prompt ref(s) from project code", len(prompt_map))

    return prompt_map


def _resolve_python_ref(ref: str, project_root: Path) -> Any | None:
    """Resolve ``"path/to/module.py::VARIABLE"`` by importing the module.

    Adds project_root to sys.path temporarily if needed.
    """
    try:
        file_part, var_name = ref.split("::", 1)
    except ValueError:
        logger.warning("Invalid Python prompt_ref format: %s (expected 'path::VAR')", ref)
        return None

    # Convert file path to module path: "src/chat/prompts.py" → "chat.prompts"
    # or "src/chat/prompts.py" if under src/
    file_path = project_root / file_part
    if not file_path.exists():
        logger.debug("Prompt ref file not found: %s", file_path)
        return None

    # Find the Python root (first parent that's in sys.path or has __init__.py chain)
    module_path = _file_to_module_path(file_path, project_root)
    if not module_path:
        logger.warning("Cannot determine module path for: %s", file_path)
        return None

    # Ensure project root or src/ is on sys.path
    src_dir = project_root / "src"
    search_root = str(src_dir) if src_dir.is_dir() else str(project_root)
    if search_root not in sys.path:
        sys.path.insert(0, search_root)

    try:
        module = importlib.import_module(module_path)
        value = getattr(module, var_name, None)
        if value is None:
            logger.warning("Variable '%s' not found in module '%s'", var_name, module_path)
            return None
        return value
    except Exception as e:
        logger.warning("Failed to import prompt ref %s: %s", ref, e)
        return None


def _file_to_module_path(file_path: Path, project_root: Path) -> str | None:
    """Convert a .py file path to a dotted module path."""
    # Try relative to src/ first, then project root
    src_dir = project_root / "src"
    for base in [src_dir, project_root]:
        if not base.is_dir():
            continue
        try:
            rel = file_path.relative_to(base)
            parts = list(rel.parts)
            # Remove .py extension from last part
            if parts[-1].endswith(".py"):
                parts[-1] = parts[-1][:-3]
            return ".".join(parts)
        except ValueError:
            continue
    return None


def _resolve_yaml_prompt(key: str, project_root: Path) -> str | None:
    """Resolve a short key like ``"tech_reporter"`` from YAML prompt files.

    Search order:
      1. ``<project_root>/prompts/agents/<key>.yaml``
      2. ``<project_root>/prompts/<key>.yaml``
      3. ``<project_root>/src/*/prompts/<key>.yaml`` (glob)

    Returns the ``system_prompt`` or ``base_prompt`` value from the YAML.
    """
    candidates = [
        project_root / "prompts" / "agents" / f"{key}.yaml",
        project_root / "prompts" / f"{key}.yaml",
    ]
    # Also try under src/*/prompts/
    src_dir = project_root / "src"
    if src_dir.is_dir():
        for pkg_dir in src_dir.iterdir():
            if pkg_dir.is_dir():
                candidates.append(pkg_dir / "prompts" / "agents" / f"{key}.yaml")
                candidates.append(pkg_dir / "prompts" / f"{key}.yaml")

    for candidate in candidates:
        if candidate.exists():
            try:
                with open(candidate, encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                if isinstance(data, dict):
                    return data.get("system_prompt") or data.get("base_prompt") or ""
            except Exception as e:
                logger.warning("Failed to read prompt YAML %s: %s", candidate, e)
    return None


def _sign_prompt_integrity(
    manifest_dict: dict[str, Any],
    project_id: str,
) -> None:
    """Sign resolved prompts and compute content-addressable versions.

    Must run AFTER ``_resolve_prompt_refs`` (prompts must be resolved to text).
    Modifies manifest_dict nodes in-place, injecting ``prompt_signature`` and
    ``prompt_version`` so they flow through Pydantic validation → ArtifactGenerator
    → Router bundle.

    Uses ``CU_PROJECT_SECRET`` from env. If absent, signing is skipped silently
    (open-source projects without security may not have a secret).
    """
    from contextunity.core.config import get_core_config

    project_secret = get_core_config().security.project_secret
    if not project_secret:
        logger.debug("CU_PROJECT_SECRET not set — skipping prompt signing")
        return

    router = manifest_dict.get("router", {})
    graph = router.get("graph", {})
    config = graph.get("config", {})
    nodes = graph.get("nodes", [])

    if not nodes:
        return

    from contextunity.core.sdk.prompt_integrity import compute_prompt_version, sign_prompt
    from contextunity.core.signing import HmacBackend

    backend = HmacBackend(project_id, project_secret)
    signed_count = 0

    # Pre-compute hashes and signatures directly into the node object
    for node in nodes:
        node_name = node.get("name")
        if not node_name:
            continue

        # Single prompts
        prompt_key = f"{node_name}_prompt"
        if prompt_key in config and isinstance(config[prompt_key], str):
            prompt_val = config[prompt_key]
            node["prompt_version"] = compute_prompt_version(prompt_val)
            node["prompt_signature"] = sign_prompt(prompt_val, backend)
            signed_count += 1

        # Variants map
        sub_prompts_key = f"{node_name}_sub_prompts"
        if sub_prompts_key in config and isinstance(config[sub_prompts_key], dict):
            node["prompt_variants_versions"] = {}
            for sub_key, sub_text in config[sub_prompts_key].items():
                if isinstance(sub_text, str):
                    node["prompt_variants_versions"][sub_key] = compute_prompt_version(sub_text)
                    signed_count += 1

    if signed_count:
        logger.info("Signed %d prompt(s) for project '%s'", signed_count, project_id)
