from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any, Callable

from contextcore.logging import get_context_unit_logger

from .loop import _bootstrap_loop
from .manifest import _auto_resolve_prompt_refs, _load_manifest, _resolve_prompt_refs, _sign_prompt_integrity

if TYPE_CHECKING:
    from contextcore.sdk.config import ProjectBootstrapConfig
    from contextcore.sdk.streaming.bidi import FederatedToolCallContext

logger = get_context_unit_logger(__name__)


def register_and_start(
    *,
    config: ProjectBootstrapConfig | None = None,
    prompt_map: dict[str, Any] | None = None,
    tool_handler: Callable[[str, dict[str, Any], FederatedToolCallContext], dict[str, Any]] | None = None,
    background: bool = True,
    graceful_fallback: bool = True,
    manifest_path: str = "",
    router_url: str = "",
    project_id: str = "",
) -> threading.Thread | None:
    """Register project manifest with Router and start BiDi stream executor.

    This is the single entry point for ContextUnity project bootstrap.
    """
    try:
        return _register_and_start_impl(
            config=config,
            prompt_map=prompt_map,
            tool_handler=tool_handler,
            background=background,
            manifest_path=manifest_path,
            router_url=router_url,
            project_id=project_id,
        )
    except Exception as e:
        if graceful_fallback:
            logger.error("ContextUnity Bootstrap Failed: %s", str(e))
            return None
        raise


def _register_and_start_impl(
    *,
    config: ProjectBootstrapConfig | None = None,
    prompt_map: dict[str, Any] | None = None,
    tool_handler: Callable[[str, dict[str, Any], FederatedToolCallContext], dict[str, Any]] | None = None,
    background: bool = True,
    manifest_path: str = "",
    router_url: str = "",
    project_id: str = "",
) -> threading.Thread | None:
    """Internal registry logic."""
    # Auto-wire ToolRegistry if no explicit handler given
    if tool_handler is None:
        from contextcore.sdk.tools import ToolRegistry

        tool_handler = ToolRegistry.build_handler()
    if config is None:
        from contextcore.sdk.config import ProjectBootstrapConfig

        config = ProjectBootstrapConfig.from_env(
            project_id=project_id,
            manifest_path=manifest_path or "contextunity.project.yaml",
        )
        if router_url:
            config.router_url = router_url

    if not config.router_url:
        logger.warning("router_url not set — skipping ContextUnity registration")
        return None

    manifest_dict = _load_manifest(config.manifest_path)
    if manifest_dict is None:
        from contextcore.exceptions import ConfigurationError

        raise ConfigurationError(f"Failed to load manifest at {config.manifest_path}")

    project_section = manifest_dict.get("project")
    if not project_section or not isinstance(project_section, dict) or "id" not in project_section:
        from contextcore.exceptions import ConfigurationError

        raise ConfigurationError("Manifest missing required 'project.id' field")
    config.project_id = project_section["id"]

    from contextcore.sdk.identity import set_project_identity

    set_project_identity(
        project_id=project_section["id"],
        tenant_id=project_section.get("tenant", project_section["id"]),
    )

    if not prompt_map:
        # Auto-resolve prompt_ref values from project Python modules / YAML files
        prompt_map = _auto_resolve_prompt_refs(manifest_dict, config.manifest_path)

    if prompt_map:
        _resolve_prompt_refs(manifest_dict, prompt_map, config.project_id)

    _sign_prompt_integrity(manifest_dict, config.project_id)

    try:
        from contextcore.manifest import ArtifactGenerator, ContextUnityProject

        manifest = ContextUnityProject.model_validate(manifest_dict)
    except Exception as e:
        from contextcore.exceptions import ConfigurationError

        raise ConfigurationError(f"Manifest validation failed: {str(e)}") from e

    try:
        config.validate_service_urls(manifest)
    except ValueError as e:
        from contextcore.exceptions import ConfigurationError

        raise ConfigurationError(f"Config validation failed: {str(e)}") from e

    resolved_secrets = config.resolve_secrets(manifest)

    if manifest.router and manifest.router.policy and manifest.router.policy.langfuse_tracing_enabled is not None:
        from contextcore.config import get_core_config

        get_core_config().langfuse_enabled = manifest.router.policy.langfuse_tracing_enabled

    generator = ArtifactGenerator(manifest)
    bundle = generator.generate_router_registration_bundle()
    worker_bindings = generator.generate_worker_bindings()

    from contextcore.sdk.identity import set_worker_bindings

    set_worker_bindings(worker_bindings)

    if not bundle:
        from contextcore.exceptions import ConfigurationError

        raise ConfigurationError("Empty bundle — manifest has no router config")

    shield_enabled = bool(manifest.services and manifest.services.shield and manifest.services.shield.enabled)

    if resolved_secrets and not shield_enabled:
        bundle["secrets"] = resolved_secrets
        logger.warning(
            "Shield disabled — %d API key(s) included inline in bundle (insecure). "
            "Enable Shield in manifest for production use.",
            len(resolved_secrets),
        )

    payload = {"bundle": bundle}

    tool_names = []
    if manifest.router and manifest.router.tools:
        from contextcore.manifest.models import RouterTool, RouterToolGroup

        for item in manifest.router.tools:
            if isinstance(item, RouterToolGroup):
                for t in item.tools:
                    if t.execution == "federated" or item.execution == "federated":
                        tool_names.append(t.name)
            elif isinstance(item, RouterTool):
                if item.execution == "federated":
                    tool_names.append(item.name)

    backend = config.get_auth_backend(shield_enabled=shield_enabled)

    from contextcore.signing import set_signing_backend

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
    )

    if background:
        thread = threading.Thread(
            target=_bootstrap_loop,
            args=bootstrap_args,
            daemon=True,
            name=f"cu-bootstrap-{config.project_id}",
        )
        thread.start()
        logger.info("Bootstrap started | project=%s router=%s", config.project_id, config.router_url)
        return thread
    else:
        _bootstrap_loop(*bootstrap_args)
        return None
