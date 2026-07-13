"""ContextUnity Manifest — ArtifactGenerator.
Projection Layer Builder: transforms a validated ContextUnityProject
into runtime bundles for individual services (Router, Worker, etc.).
Lives in Core because:
  - Zero Router dependencies (only uses contextunity.core.manifest models)
  - Project needs to compile bundles locally
  - Router receives ready bundles — doesn't need to compile
Secret resolution is NOT done here — use ProjectBootstrapConfig.resolve_secrets()
and pass the result via resolved_secrets parameter.
"""

from __future__ import annotations

from contextunity.core.logging import get_contextunit_logger
from contextunity.core.types import WireValue, is_json_dict, is_object_dict

from .helpers import parse_tool_ref
from .models import ContextUnityProject, RouterRegistrationBundle, WorkerBindingsBundle
from .router import RouterConfigSection, RouterGraphConfig
from .tenants import apply_allowed_tenants_to_bundle, resolve_project_allowed_tenants, validate_tenant_subset

logger = get_contextunit_logger(__name__)


def _deep_merge_wire(base: dict[str, WireValue], override: dict[str, WireValue]) -> dict[str, WireValue]:
    """Deep-merge JSON-like manifest dicts; ``override`` wins."""
    merged: dict[str, WireValue] = dict(base)
    for key, value in override.items():
        existing = merged.get(key)
        if is_object_dict(existing) and is_object_dict(value):
            merged[key] = _deep_merge_wire(dict(existing), dict(value))
        else:
            merged[key] = value
    return merged


def _router_service_config(router_config: RouterConfigSection) -> dict[str, WireValue]:
    """Return Router project-wide runtime domains projected into each graph config."""
    data: dict[str, object] = router_config.model_dump(exclude_none=True)
    memory = data.get("memory")
    return {"memory": memory} if is_json_dict(memory) else {}


def _graph_typed_config(graph_config: RouterGraphConfig | None) -> dict[str, WireValue]:
    if not graph_config:
        return {}
    data: dict[str, object] = graph_config.model_dump(exclude_none=True)
    return dict(data) if is_json_dict(data) else {}


def _graph_runtime_config(runtime: object) -> dict[str, WireValue]:
    return dict(runtime) if is_object_dict(runtime) else {}


def _iter_bindings(value: str | list[str] | None):
    """iter bindings.

    Args:
        value (str | list[str] | None): The value to store or update.
    """
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield item


class ArtifactGenerator:
    """Compiles a ContextUnityProject manifest into service-specific bundles."""

    manifest: ContextUnityProject

    def __init__(self, project_manifest: ContextUnityProject):
        """Initialize the ArtifactGenerator with a validated ContextUnityProject manifest.

        Args:
            project_manifest (ContextUnityProject): The project manifest parameter.
        """
        self.manifest = project_manifest

    def generate_router_registration_bundle(
        self,
        resolved_secrets: dict[str, str] | None = None,
    ) -> RouterRegistrationBundle:
        """Create the Router registration bundle.

        Compiles declarative per-node manifest data (model, prompt_ref,
        pii_masking) into the flat config dict that graph builders expect.

        Args:
            resolved_secrets: Deprecated. Registration bundles no longer carry
                inline secrets; Shield/env are the runtime secret sources.

        Returns:
            RouterRegistrationBundle: Compiled router registration payload.
        """
        router = self.manifest.router
        if not router:
            return RouterRegistrationBundle()

        project_tenants = resolve_project_allowed_tenants(self.manifest.project)

        router_config = _router_service_config(router.config)

        graphs_dict: dict[str, WireValue] = {}
        for graph_key, graph_model in router.graph.items():
            # Typed config only here. Opaque ``runtime`` stays a sibling field on
            # the graph entry (alpha8: do not re-mix into the config bag).
            graph_config = _deep_merge_wire(router_config, _graph_typed_config(graph_model.config))
            graph_scope = project_tenants
            if graph_model.allowed_tenants:
                validate_tenant_subset(
                    graph_model.allowed_tenants,
                    project_scope=project_tenants,
                    context=f"Graph '{graph_key}'",
                )
                graph_scope = graph_model.allowed_tenants

            node_tool_bindings: dict[str, dict[str, str]] = {}
            graph_federated_tools: list[dict[str, WireValue]] = []
            federated_tool_names: set[str] = set()
            if graph_model.goal is not None:
                graph_config["goal"] = graph_model.goal
            if graph_model.persona is not None:
                graph_config["persona"] = graph_model.persona
            if self.manifest.services:
                graph_config["services"] = self.manifest.services.model_dump(exclude_none=True)

            if graph_model.nodes:
                for node in graph_model.nodes:
                    node_name = node.name
                    if node.allowed_tenants:
                        validate_tenant_subset(
                            node.allowed_tenants,
                            project_scope=graph_scope,
                            context=f"Node '{node_name}' in graph '{graph_key}'",
                        )

                    # PII masking — if ANY node enables it, graph gets pii_masking=True
                    if node.pii_masking:
                        graph_config["pii_masking"] = True

                    # Tool binding for tool nodes. Bare bindings normalize to platform.
                    # Only explicit federated:* bindings become project BiDi tools.
                    if node.tool_binding:
                        for binding in _iter_bindings(node.tool_binding):
                            kind, tool_name = parse_tool_ref(binding)
                            if kind == "federated" and tool_name:
                                if node_name not in node_tool_bindings:
                                    node_tool_bindings[node_name] = {}
                                node_tool_bindings[node_name][tool_name] = "execute"
                                federated_tool_names.add(tool_name)

                    if node.tools:
                        for binding in node.tools:
                            kind, tool_name = parse_tool_ref(binding)
                            if kind == "federated" and tool_name:
                                federated_tool_names.add(tool_name)

            for mapped_name in graph_model.federated_tool_map.values():
                if mapped_name:
                    federated_tool_names.add(mapped_name)

            for tool_name in sorted(federated_tool_names):
                graph_federated_tools.append(
                    {
                        "name": tool_name,
                        "type": "bidi",
                        "description": f"Federated tool '{tool_name}' for graph '{graph_key}'",
                        "config": {"graph_key": graph_key},
                    }
                )
            # If no model_key set explicitly, use default from policy
            if "model_key" not in graph_config and router.policy and router.policy.models:
                graph_config["model_key"] = router.policy.models.llm.default
            if "fallback_keys" not in graph_config and router.policy and router.policy.models:
                graph_config["fallback_keys"] = router.policy.models.llm.fallback or []

            if node_tool_bindings:
                graph_config["node_tool_bindings"] = node_tool_bindings
            if graph_federated_tools:
                graph_config["federated_tools"] = graph_federated_tools
            if graph_model.federated_tool_map:
                graph_config["federated_tool_map"] = graph_model.federated_tool_map

            # Serialize via Pydantic — strict, no None leaks
            entry = graph_model.model_dump(exclude_none=True, by_alias=True)
            # Replace raw config with the enriched version (model_key, fallback, PII, bindings)
            entry["config"] = graph_config
            # Keep runtime as wire JSON sibling (never folded into config above).
            runtime_blob = _graph_runtime_config(graph_model.runtime)
            if runtime_blob:
                entry["runtime"] = runtime_blob
            elif "runtime" in entry:
                del entry["runtime"]

            graphs_dict[graph_key] = entry

        policy: dict[str, WireValue] = {
            "allowed_tools": (router.policy.allowed_tools or [] if router.policy else []),
            "models_ref": (router.policy.models_ref if router.policy else None),
            "prompts_ref": (router.policy.prompts_ref if router.policy else None),
            "langfuse": (
                router.policy.langfuse.model_dump(exclude_none=True)
                if router.policy and router.policy.langfuse
                else None
            ),
        }

        if router.policy and router.policy.models:
            policy["models"] = router.policy.models.model_dump(exclude_none=True)

        conductor: dict[str, WireValue] = {}
        if router.config.conductor is not None:
            conductor = router.config.conductor.model_dump(exclude_none=True)

        bundle = RouterRegistrationBundle(
            project_id=self.manifest.project.id,
            default_graph=router.default_graph,
            graph=graphs_dict,
            services=self.manifest.services.model_dump(exclude_none=True),
            policy=policy,
            conductor=conductor,
            secrets=None,
        )
        apply_allowed_tenants_to_bundle(bundle, self.manifest.project)
        return bundle

    def generate_worker_bindings(self) -> WorkerBindingsBundle:
        """Create Worker schedule/workflow bindings."""
        worker = self.manifest.worker
        if not worker or worker.mode == "disabled":
            return WorkerBindingsBundle()

        return WorkerBindingsBundle(
            mode=worker.mode,
            workflows=[wf.model_dump(exclude_none=True) for wf in (worker.workflows or [])],
            schedules=[sc.model_dump(exclude_none=True) for sc in (worker.schedules or [])],
            execution_policy=(
                worker.execution_policy.model_dump(exclude_none=True) if worker.execution_policy else None
            ),
        )
