"""Manifest loading, prompt resolution, and integrity signing.
Responsible for:
- Loading ``contextunity.project.yaml`` from disk
- Resolving ``prompt_ref`` values (Python module refs and YAML files)
- Computing HMAC signatures over resolved prompts for tamper detection
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

from contextunity.core.logging import get_contextunit_logger
from contextunity.core.parsing import yaml_load
from contextunity.core.sdk.payload import get_json_dict, get_json_dict_list, get_str
from contextunity.core.types import JsonDict, is_json_dict, is_json_value

from ..types import PromptMap

logger = get_contextunit_logger(__name__)


def _as_json_dict(value: object) -> JsonDict | None:
    """Return ``value`` when it is a recursive JSON object mapping."""
    return value if is_json_dict(value) else None


def _router_graph(manifest_dict: JsonDict) -> JsonDict | None:
    router = _as_json_dict(manifest_dict.get("router", {}))
    if router is None:
        return None
    graph = _as_json_dict(router.get("graph", {}))
    if graph is None:
        return None
    return graph


def _manifest_shield_enabled(manifest_dict: JsonDict) -> bool:
    """Return true when the project manifest explicitly enables Shield."""
    services = _as_json_dict(manifest_dict.get("services", {}))
    if services is None:
        return False
    shield = _as_json_dict(services.get("shield", {}))
    return bool(shield and shield.get("enabled") is True)


def _graph_node_entries(graph: JsonDict) -> list[JsonDict]:
    if "nodes" in graph:
        return [graph]
    entries: list[JsonDict] = []
    for entry in graph.values():
        entry_dict = _as_json_dict(entry)
        if entry_dict is not None and "nodes" in entry_dict:
            entries.append(entry_dict)
    return entries


def load_manifest(manifest_path: str) -> JsonDict | None:
    """Load and return manifest dict from YAML file.

    Args:
        manifest_path: The filesystem path to the manifest file.

    Returns:
        JsonDict | None: The loaded manifest dictionary, or None if loading fails.
    """
    try:
        with open(manifest_path, encoding="utf-8") as f:
            loaded: object = yaml_load(f)
            if is_json_dict(loaded):
                return loaded
            return None
    except FileNotFoundError:
        logger.error("Manifest not found: %s", manifest_path)
        return None
    except Exception as e:
        logger.error("Failed to read manifest %s: %s", manifest_path, e)
        return None


_load_manifest = load_manifest


def resolve_prompt_refs(
    manifest_dict: JsonDict,
    prompt_map: PromptMap,
) -> None:
    """Resolve prompt_ref and config refs in-place inside the manifest dict.

    Args:
        manifest_dict: The manifest dictionary to update in-place.
        prompt_map: Mapping of resolved prompt references to their text values.
    """
    graph = _router_graph(manifest_dict)
    if graph is None:
        return

    for entry in _graph_node_entries(graph):
        config = dict(get_json_dict(entry, "config"))
        entry["config"] = config

        for node in get_json_dict_list(entry, "nodes"):
            node_name = get_str(node, "name")
            if not node_name:
                continue

            prompt_ref = get_str(node, "prompt_ref")
            if prompt_ref and prompt_ref in prompt_map:
                val = prompt_map[prompt_ref]
                if is_json_value(val):
                    config[f"{node_name}_prompt"] = val

            variants_ref = get_str(node, "prompt_variants_ref")
            if variants_ref and variants_ref in prompt_map:
                val = prompt_map[variants_ref]
                if is_json_value(val):
                    config[f"{node_name}_sub_prompts"] = val


def auto_resolve_prompt_refs(
    manifest_dict: JsonDict,
    manifest_path: str,
) -> dict[str, str | JsonDict]:
    """Auto-resolve prompt_ref values from Python modules or YAML files.

    Args:
        manifest_dict: The manifest dictionary.
        manifest_path: The path to the manifest file (used to resolve project root).

    Returns:
        dict[str, str | JsonDict]: Mapping of prompt refs to resolved content.
    """
    graph = _router_graph(manifest_dict)
    if graph is None:
        return {}

    nodes: list[JsonDict] = []
    if "nodes" in graph:
        nodes = get_json_dict_list(graph, "nodes")
    else:
        for entry in graph.values():
            entry_dict = _as_json_dict(entry)
            if entry_dict is not None:
                nodes.extend(get_json_dict_list(entry_dict, "nodes"))
    if not nodes:
        return {}

    refs: list[str] = []
    for node in nodes:
        prompt_ref = get_str(node, "prompt_ref")
        if prompt_ref:
            refs.append(prompt_ref)
        variants_ref = get_str(node, "prompt_variants_ref")
        if variants_ref:
            refs.append(variants_ref)
    if not refs:
        return {}

    project_root = Path(manifest_path).resolve().parent
    prompt_map: dict[str, str | JsonDict] = {}

    for ref in refs:
        if ref in prompt_map:
            continue

        if "::" in ref:
            resolved = _resolve_python_ref(ref, project_root)
            if resolved is not None and is_json_value(resolved):
                if isinstance(resolved, str) or is_json_dict(resolved):
                    prompt_map[ref] = resolved
        else:
            resolved = _resolve_yaml_prompt(ref, project_root)
            if resolved is not None:
                prompt_map[ref] = resolved

    if prompt_map:
        logger.info("Auto-resolved %d prompt ref(s) from project code", len(prompt_map))

    return prompt_map


def _resolve_python_ref(ref: str, project_root: Path) -> object | None:
    """Resolve ``"path/to/module.py::VARIABLE"`` by importing the module.

    Args:
        ref: The Python module/variable reference string.
        project_root: The root path of the project.

    Returns:
        object | None: The value of the referenced variable, or None if resolution fails.
    """
    try:
        file_part, var_name = ref.split("::", 1)
    except ValueError:
        logger.warning("Invalid Python prompt_ref format: %s (expected 'path::VAR')", ref)
        return None

    file_path = project_root / file_part
    if not file_path.exists():
        logger.debug("Prompt ref file not found: %s", file_path)
        return None

    module_path = _file_to_module_path(file_path, project_root)
    if not module_path:
        logger.warning("Cannot determine module path for: %s", file_path)
        return None

    src_dir = project_root / "src"
    search_root = str(src_dir) if src_dir.is_dir() else str(project_root)
    if search_root not in sys.path:
        sys.path.insert(0, search_root)

    try:
        module = importlib.import_module(module_path)
        value: object = getattr(module, var_name, None)
        if value is None:
            logger.warning("Variable '%s' not found in module '%s'", var_name, module_path)
            return None
        if isinstance(value, str):
            return value
        if is_json_dict(value):
            variants: JsonDict = {}
            for key, item in value.items():
                if isinstance(item, str):
                    variants[key] = item
            if variants:
                return variants
        logger.warning("Prompt ref %s resolved to unsupported value in module '%s'", ref, module_path)
        return None
    except Exception as e:
        logger.warning("Failed to import prompt ref %s: %s", ref, e)
        return None


def _file_to_module_path(file_path: Path, project_root: Path) -> str | None:
    """Convert a .py file path to a dotted module path.

    Args:
        file_path: The file path to the module.
        project_root: The root path of the project.

    Returns:
        str | None: The dotted module path, or None if it cannot be determined.
    """
    src_dir = project_root / "src"
    for base in [src_dir, project_root]:
        if not base.is_dir():
            continue
        try:
            rel = file_path.relative_to(base)
            parts = list(rel.parts)
            if parts[-1].endswith(".py"):
                parts[-1] = parts[-1][:-3]
            return ".".join(parts)
        except ValueError:
            continue
    return None


def _resolve_yaml_prompt(key: str, project_root: Path) -> str | None:
    """Resolve a short key like ``"tech_reporter"`` from YAML prompt files.

    Args:
        key: The prompt key to search for.
        project_root: The root path of the project.

    Returns:
        str | None: The resolved system or base prompt, or None if not found.
    """
    candidates = [
        project_root / "prompts" / "agents" / f"{key}.yaml",
        project_root / "prompts" / f"{key}.yaml",
    ]
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
                    loaded: object = yaml_load(f)
                loaded_dict = _as_json_dict(loaded)
                if loaded_dict is None:
                    continue
                system_prompt = get_str(loaded_dict, "system_prompt")
                if system_prompt:
                    return system_prompt
                base_prompt = get_str(loaded_dict, "base_prompt")
                if base_prompt:
                    return base_prompt
                return ""
            except Exception as e:
                logger.warning("Failed to read prompt YAML %s: %s", candidate, e)
    return None


def sign_prompt_integrity(
    manifest_dict: JsonDict,
    project_id: str,
) -> None:
    """Sign resolved prompts or mark Shield-backed prompt versions.

    Args:
        manifest_dict: The manifest dictionary to sign in-place.
        project_id: The identifier of the project.
    """
    from contextunity.core.config import get_core_config

    graph = _router_graph(manifest_dict)
    if graph is None:
        return

    graph_entries: list[tuple[JsonDict, list[JsonDict]]] = []
    if "nodes" in graph:
        graph_config = dict(get_json_dict(graph, "config"))
        graph_entries.append((graph_config, get_json_dict_list(graph, "nodes")))
    else:
        for entry in graph.values():
            entry_dict = _as_json_dict(entry)
            if entry_dict is not None and "nodes" in entry_dict:
                entry_config = dict(get_json_dict(entry_dict, "config"))
                graph_entries.append((entry_config, get_json_dict_list(entry_dict, "nodes")))

    if not graph_entries:
        return

    from contextunity.core.sdk.prompt_integrity import compute_prompt_version

    shield_enabled = _manifest_shield_enabled(manifest_dict)

    def _has_prompts() -> bool:
        for config, nodes in graph_entries:
            for node in nodes:
                node_name = get_str(node, "name")
                if not node_name:
                    continue
                if get_str(config, f"{node_name}_prompt"):
                    return True
                if get_json_dict(config, f"{node_name}_sub_prompts"):
                    return True
        return False

    if shield_enabled:
        versioned_count = 0
        for config, nodes in graph_entries:
            for node in nodes:
                node_name = get_str(node, "name")
                if not node_name:
                    continue

                prompt_value = get_str(config, f"{node_name}_prompt")
                if prompt_value:
                    node["prompt_version"] = compute_prompt_version(prompt_value)
                    node.pop("prompt_signature", None)
                    versioned_count += 1

                sub_prompts_dict = get_json_dict(config, f"{node_name}_sub_prompts")
                if sub_prompts_dict:
                    node["prompt_variants_versions"] = {
                        sub_key: compute_prompt_version(sub_text)
                        for sub_key, sub_text in sub_prompts_dict.items()
                        if isinstance(sub_text, str)
                    }
                    versioned_count += len(node["prompt_variants_versions"])

        if versioned_count:
            logger.info(
                "Prepared %d Shield-backed prompt version(s) for project '%s'",
                versioned_count,
                project_id,
            )
        return

    project_secret = get_core_config().security.project_secret
    if not project_secret:
        # Fail closed: a manifest that ships LLM prompts MUST sign them. Silently
        # skipping (the old behaviour) would register unsigned prompts that the
        # runtime then cannot tamper-check — i.e. infra-level prompt injection.
        if _has_prompts():
            from contextunity.core.exceptions import ConfigurationError

            raise ConfigurationError(
                f"Project '{project_id}' manifest defines LLM prompt(s) but CU_PROJECT_SECRET "
                "is not set. Prompt-integrity signing is mandatory when prompts are present: "
                "set CU_PROJECT_SECRET (OSS) or enable services.shield.enabled (Enterprise). "
                "Refusing to register unsigned prompts (fail-closed — WS-9)."
            )
        logger.debug("No CU_PROJECT_SECRET and no signable prompts — nothing to sign")
        return

    from contextunity.core.sdk.prompt_integrity import sign_prompt
    from contextunity.core.signing import HmacBackend

    backend = HmacBackend(project_id, project_secret)
    signed_count = 0

    for config, nodes in graph_entries:
        for node in nodes:
            node_name = get_str(node, "name")
            if not node_name:
                continue

            prompt_key = f"{node_name}_prompt"
            prompt_value = get_str(config, prompt_key)
            if prompt_value:
                node["prompt_version"] = compute_prompt_version(prompt_value)
                node["prompt_signature"] = sign_prompt(prompt_value, backend)
                signed_count += 1

            sub_prompts_key = f"{node_name}_sub_prompts"
            sub_prompts_dict = get_json_dict(config, sub_prompts_key)
            if sub_prompts_dict:
                node["prompt_variants_versions"] = {}
                for sub_key, sub_text in sub_prompts_dict.items():
                    if isinstance(sub_text, str):
                        node["prompt_variants_versions"][sub_key] = compute_prompt_version(sub_text)
                        signed_count += 1

    if signed_count:
        logger.info("Signed %d prompt(s) for project '%s'", signed_count, project_id)


def extract_node_prompts(manifest_dict: JsonDict) -> dict[str, str]:
    """Return prompt texts keyed for Shield publish.

    Keys are the path suffix after ``{project_id}/prompts/``:

    - Multi-graph map: ``{graph_key}/{node_name}`` → full path
      ``{project_id}/prompts/{graph_key}/{node_name}``.
    - Legacy top-level ``graph.nodes``: ``{node_name}`` (flat path, dual-read
      at runtime still works).

    Same node name in two graphs is allowed and does not collide.
    """
    graph = _router_graph(manifest_dict)
    if graph is None:
        return {}

    # (graph_key_or_None, config, nodes)
    graph_entries: list[tuple[str | None, JsonDict, list[JsonDict]]] = []
    if "nodes" in graph:
        graph_entries.append((None, dict(get_json_dict(graph, "config")), get_json_dict_list(graph, "nodes")))
    else:
        for graph_key in sorted(graph):
            entry_dict = _as_json_dict(graph.get(graph_key))
            if entry_dict is not None and "nodes" in entry_dict:
                graph_entries.append(
                    (
                        graph_key,
                        dict(get_json_dict(entry_dict, "config")),
                        get_json_dict_list(entry_dict, "nodes"),
                    )
                )

    prompts: dict[str, str] = {}
    for graph_key, config, nodes in graph_entries:
        for node in nodes:
            node_name = get_str(node, "name")
            if not node_name:
                continue
            prompt_value = get_str(config, f"{node_name}_prompt")
            if not prompt_value:
                continue
            # Path suffix under {project_id}/prompts/
            key = f"{graph_key}/{node_name}" if graph_key else node_name
            prompts[key] = prompt_value
    return prompts


_resolve_prompt_refs = resolve_prompt_refs
_auto_resolve_prompt_refs = auto_resolve_prompt_refs
_sign_prompt_integrity = sign_prompt_integrity
