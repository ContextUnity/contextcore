"""SDK bootstrap entry point — ``register_and_start()``.
This module provides the single function that consumer projects call to
connect to ContextRouter.  It loads the ``contextunity.project.yaml``
manifest, compiles tool/prompt bindings, acquires a Shield session token
(when Shield is enabled), and opens the BiDi ``ToolExecutorStream``.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from contextunity.core.logging import get_contextunit_logger
from contextunity.core.manifest.helpers import parse_tool_ref as _parse_tool_binding
from contextunity.core.types import JsonDict, is_json_dict, is_object_dict, is_object_list

from ..types import PromptMap, ToolHandler, ToolPayload
from .loop import bootstrap_loop
from .manifest import (
    auto_resolve_prompt_refs,
    extract_node_prompts,
    load_manifest,
    resolve_prompt_refs,
    sign_prompt_integrity,
)

if TYPE_CHECKING:
    from contextunity.core.manifest import ContextUnityProject
    from contextunity.core.sdk.config import ProjectBootstrapConfig
    from contextunity.core.signing import AuthBackend

logger = get_contextunit_logger(__name__)


def register_and_start(
    *,
    config: ProjectBootstrapConfig | None = None,
    prompt_map: PromptMap | None = None,
    tool_handler: ToolHandler | None = None,
    background: bool = True,
    start_executor: bool = True,
    graceful_fallback: bool = True,
    manifest_path: str = "",
    router_url: str = "",
    project_id: str = "",
) -> threading.Thread | None:
    """Register project manifest with Router and start BiDi stream executor.

    Args:
        config: Explicit ProjectBootstrapConfig. If None, loaded from env.
        prompt_map: Mappings of prompt names to their resolved text values.
        tool_handler: Custom tool handler callable. If None, builds from ToolRegistry.
        background: If True, executes the event loop in a background thread.
        start_executor: If False, perform auth/session setup and registration
            without starting the federated tool executor stream.
        graceful_fallback: If True, catches bootstrap errors and returns None.
        manifest_path: Custom path to the manifest file.
        router_url: Router gRPC URL override.
        project_id: Project identifier override.

    Returns:
        threading.Thread | None: The background thread if started in background,
            otherwise None.

    Raises:
        ConfigurationError: If bootstrap fails and graceful_fallback is False.
    """
    try:
        return _register_and_start_impl(
            config=config,
            prompt_map=prompt_map,
            tool_handler=tool_handler,
            background=background,
            start_executor=start_executor,
            manifest_path=manifest_path,
            router_url=router_url,
            project_id=project_id,
        )
    except Exception as e:
        if graceful_fallback:
            logger.error("Bootstrap failed: %s", e)
            return None
        raise


def _register_and_start_impl(
    *,
    config: ProjectBootstrapConfig | None = None,
    prompt_map: PromptMap | None = None,
    tool_handler: ToolHandler | None = None,
    background: bool = True,
    start_executor: bool = True,
    manifest_path: str = "",
    router_url: str = "",
    project_id: str = "",
) -> threading.Thread | None:
    """Internal registry logic.

    Args:
        config: Explicit ProjectBootstrapConfig. If None, loaded from env.
        prompt_map: Mappings of prompt names to their resolved text values.
        tool_handler: Custom tool handler callable. If None, builds from ToolRegistry.
        background: If True, executes the event loop in a background thread.
        start_executor: If False, skip the federated tool executor stream.
        manifest_path: Custom path to the manifest file.
        router_url: Router gRPC URL override.
        project_id: Project identifier override.

    Returns:
        threading.Thread | None: The background thread if started in background,
            otherwise None.

    Raises:
        ConfigurationError: If configuration parameters are invalid.
    """
    # Auto-wire ToolRegistry if no explicit handler given
    if start_executor and tool_handler is None:
        from contextunity.core.sdk.tools import ToolRegistry

        tool_handler = ToolRegistry.build_handler()
    if config is None:
        from contextunity.core.sdk.config import ProjectBootstrapConfig

        config = ProjectBootstrapConfig.from_env(
            project_id=project_id,
            manifest_path=manifest_path or "contextunity.project.yaml",
        )
        if router_url:
            config.router_url = router_url

    if not config.router_url:
        logger.warning("router_url not set — skipping ContextUnity registration")
        return None

    manifest_dict_or_none = load_manifest(config.manifest_path)
    if manifest_dict_or_none is None:
        from contextunity.core.exceptions import ConfigurationError

        raise ConfigurationError(f"Failed to load manifest at {config.manifest_path}")
    manifest_dict: JsonDict = manifest_dict_or_none

    # Early-validate project section for identity (typed, before raw dict mutations)
    raw_project = manifest_dict.get("project")
    if not is_json_dict(raw_project):
        from contextunity.core.exceptions import ConfigurationError

        raise ConfigurationError("Manifest missing required 'project' section")

    try:
        from contextunity.core.manifest.models import ProjectSection

        project = ProjectSection.model_validate(raw_project)
    except Exception as e:
        from contextunity.core.exceptions import ConfigurationError

        raise ConfigurationError(f"Invalid project section: {e}") from e

    config.project_id = project.id

    from contextunity.core.manifest.tenants import resolve_project_allowed_tenants
    from contextunity.core.sdk.identity import set_project_identity

    allowed_tenants = resolve_project_allowed_tenants(project)
    set_project_identity(
        project_id=project.id,
        allowed_tenants=tuple(allowed_tenants),
    )

    if not prompt_map:
        # Auto-resolve prompt_ref values from project Python modules / YAML files
        prompt_map = auto_resolve_prompt_refs(manifest_dict, config.manifest_path)

    if prompt_map:
        resolve_prompt_refs(manifest_dict, dict(prompt_map))

    sign_prompt_integrity(manifest_dict, config.project_id)

    try:
        from contextunity.core.manifest import ArtifactGenerator, ContextUnityProject

        manifest = ContextUnityProject.model_validate(manifest_dict)
    except Exception as e:
        from contextunity.core.exceptions import ConfigurationError

        raise ConfigurationError(f"Manifest validation failed: {str(e)}") from e

    _resolve_toolkits(manifest)

    config.validate_service_urls(manifest)

    resolved_secrets = config.resolve_secrets(manifest)
    generator = ArtifactGenerator(manifest)
    shield_enabled = bool(manifest.services and manifest.services.shield and manifest.services.shield.enabled)

    prompts_for_shield = extract_node_prompts(manifest_dict) if shield_enabled else {}
    bundle = generator.generate_router_registration_bundle()
    if shield_enabled:
        _strip_resolved_prompt_text(bundle)
    worker_bindings = generator.generate_worker_bindings()

    from contextunity.core.sdk.identity import set_required_services, set_worker_bindings

    set_worker_bindings(worker_bindings)

    # Cache enabled services for Shield auto-provisioning of session token permissions
    if manifest.services:
        svc_flags: dict[str, bool] = {}
        for svc_name in ("router", "brain", "worker", "shield"):
            svc: object = getattr(manifest.services, svc_name, None)
            if svc is not None:
                enabled_raw: object = getattr(svc, "enabled", False)
                if isinstance(enabled_raw, bool) and enabled_raw:
                    svc_flags[svc_name] = True
        set_required_services(svc_flags)

    if not bundle.enabled:
        from contextunity.core.exceptions import ConfigurationError

        raise ConfigurationError("Empty bundle — manifest has no router config")

    payload: ToolPayload = {"bundle": bundle.model_dump(exclude_none=True)}

    tool_names = _extract_stream_tool_names(bundle) if start_executor else []

    if shield_enabled:
        # In Shield mode, pass HMAC backend — the bootstrap loop will
        # acquire the Shield session token with retry.
        from contextunity.core.config import get_core_config
        from contextunity.core.signing import HmacBackend

        backend: AuthBackend = HmacBackend(
            project_id=config.project_id,
            project_secret=get_core_config().security.project_secret,
        )
    else:
        backend = config.get_auth_backend(shield_enabled=False)

    from contextunity.core.signing import set_signing_backend

    set_signing_backend(backend)

    bootstrap_args = (
        config.router_url,
        config.project_id,
        payload,
        tool_names,
        tool_handler,
        resolved_secrets if shield_enabled else None,
        shield_enabled,
        config.shield_url,
        backend,
        prompts_for_shield,
        tuple(allowed_tenants),
        config.delivery_resume_window_seconds,
        config.delivery_max_cache_entries,
        config.delivery_max_message_bytes,
    )

    if background:
        thread = threading.Thread(
            target=bootstrap_loop,
            args=bootstrap_args,
            daemon=True,
            name=f"cu-bootstrap-{config.project_id}",
        )
        thread.start()
        logger.info("Bootstrap started | project=%s router=%s", config.project_id, config.router_url)
        return thread
    else:
        bootstrap_loop(*bootstrap_args)
        return None


def _resolve_toolkits(manifest: ContextUnityProject) -> None:
    """Read toolkits from manifest and instantiate them, registering bound methods as tools.

    Args:
        manifest: The loaded ContextUnityProject manifest.

    Raises:
        ToolkitResolutionError: If a toolkit name in the manifest is unregistered or duplicate.
    """
    if not manifest.router:
        return

    from contextunity.core.manifest.models import RouterNodeMeta, ToolkitOverride, ToolkitRef
    from contextunity.core.sdk.toolkit import FederatedToolkit, ToolkitResolutionError
    from contextunity.core.sdk.tools import ToolRegistry

    # Collect global toolkit refs
    global_refs = manifest.router.toolkits or []

    for graph_key, graph in manifest.router.graph.items():
        # Merge global, per-graph, and agent-node toolkit refs.
        node_refs: list[str | ToolkitRef] = []
        for node in graph.nodes or []:
            node_refs.extend(node.toolkits or [])
        graph_refs = global_refs + (graph.toolkits or []) + node_refs
        if not graph_refs:
            continue

        resolved_graph_tools: dict[str, tuple[str, str]] = {}

        for tk_ref_or_str in graph_refs:
            # Normalize to ToolkitRef-like structure
            if isinstance(tk_ref_or_str, str):
                tk_name = tk_ref_or_str
                exclude: set[str] = set()
                overrides: dict[str, ToolkitOverride] = {}
            else:
                tk_name = tk_ref_or_str.name
                exclude = set(tk_ref_or_str.exclude or [])
                overrides = tk_ref_or_str.overrides or {}

            try:
                tk_class = FederatedToolkit.resolve(tk_name)
            except ToolkitResolutionError as e:
                # Fail-closed semantic
                raise ToolkitResolutionError(
                    f"Failed to resolve toolkit '{tk_name}' for graph '{graph_key}': {e}"
                ) from e

            # Discover all methods
            discovered = tk_class.discover_tools()

            for defn in discovered.values():
                if defn.name in exclude:
                    continue

                # Prepare the flat global name
                global_tool_name = defn.name

                # Apply overrides natively to the definition if present
                override = overrides.get(defn.name)
                if override:
                    # Update config fields
                    cfg_update = override.model_dump(exclude_none=True)
                    if cfg_update:
                        defn.config = defn.config.model_copy(update=cfg_update)
                        # We use a graph-specific name to store overridden variants to prevent global scope pollution
                        global_tool_name = f"{defn.name}_{graph_key}"

                resolved_graph_tools[defn.name] = (global_tool_name, tk_name)

                # Register in the global ToolRegistry using the (possibly graph-specific) name
                try:
                    from contextunity.core.sdk.tools import FunctionTool, ToolRegistry

                    # Inject configuration overrides dynamically to the execution
                    # To strictly respect the override at execution time, we attach the modified config
                    setattr(defn.fn, "tool_config", defn.config)
                    ToolRegistry.register(FunctionTool(global_tool_name, defn.fn))
                    logger.debug("Registered federated tool '%s' from toolkit '%s'", global_tool_name, tk_name)
                except ValueError:
                    # If it's already registered globally, we can silently skip since the handler is reused
                    pass

        if resolved_graph_tools:
            tool_map = {
                logical_name: resolved_name
                for logical_name, (resolved_name, _toolkit_name) in resolved_graph_tools.items()
            }
            graph.set_federated_tool_map(tool_map)

        # Inject resolver metadata into graph nodes that bind toolkit tools.
        for node in graph.nodes or []:
            if not isinstance(node.tool_binding, str):
                continue
            kind, tool_name = _parse_tool_binding(node.tool_binding)
            if kind != "federated":
                continue
            resolved = resolved_graph_tools.get(tool_name)
            if not resolved:
                continue
            handler_name, toolkit_name = resolved
            existing_meta = node.meta.model_dump(exclude_none=True) if node.meta else {}
            if "handler" not in existing_meta:
                existing_meta["handler"] = handler_name
            if "source" not in existing_meta:
                existing_meta["source"] = "toolkit"
            if "toolkit" not in existing_meta:
                existing_meta["toolkit"] = toolkit_name
            node.meta = RouterNodeMeta.model_validate(existing_meta)


def _extract_stream_tool_names(bundle: object) -> list[str]:
    """Return project-side BiDi tool names from graph-scoped bundle config."""
    names: set[str] = set()
    graph_raw: object = getattr(bundle, "graph", {})
    if not is_json_dict(graph_raw):
        return []

    for graph_entry in graph_raw.values():
        if not is_json_dict(graph_entry):
            continue
        config = graph_entry.get("config")
        if not is_json_dict(config):
            continue
        federated_tools = config.get("federated_tools")
        if not is_object_list(federated_tools):
            continue
        for raw_tool in federated_tools:
            if not is_json_dict(raw_tool):
                continue
            name = raw_tool.get("name")
            if isinstance(name, str) and name:
                names.add(name)

    return sorted(names)


def _strip_resolved_prompt_text(bundle: object) -> None:
    """Remove Shield-backed prompt text from the Router registration bundle."""
    graph_raw: object = getattr(bundle, "graph", {})
    if not is_object_dict(graph_raw):
        return

    for graph_entry in graph_raw.values():
        if not is_object_dict(graph_entry):
            continue
        config = graph_entry.get("config")
        nodes = graph_entry.get("nodes")
        if not is_object_dict(config) or not is_object_list(nodes):
            continue
        for node_raw in nodes:
            if not is_object_dict(node_raw):
                continue
            node_name = node_raw.get("name")
            prompt_ref = node_raw.get("prompt_ref")
            if isinstance(node_name, str) and isinstance(prompt_ref, str) and prompt_ref.strip():
                config.pop(f"{node_name}_prompt", None)
