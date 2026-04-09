"""ContextUnity Manifest — ArtifactGenerator.

Projection Layer Builder: transforms a validated ContextUnityProject
into runtime bundles for individual services (Router, Worker, etc.).

Lives in Core because:
  - Zero Router dependencies (only uses contextcore.manifest models)
  - Project needs to compile bundles locally
  - Router receives ready bundles — doesn't need to compile

Secret resolution is NOT done here — use ProjectBootstrapConfig.resolve_secrets()
and pass the result via resolved_secrets parameter.
"""

from __future__ import annotations

from typing import Any

from contextcore.logging import get_context_unit_logger

from .models import ContextUnityProject

logger = get_context_unit_logger(__name__)


class ArtifactGenerator:
    """Compiles a ContextUnityProject manifest into service-specific bundles."""

    def __init__(self, project_manifest: ContextUnityProject):
        self.manifest = project_manifest

    def generate_router_registration_bundle(
        self,
        resolved_secrets: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Create the Router registration bundle.

        Compiles declarative per-node manifest data (model, prompt_ref,
        pii_masking) into the flat config dict that graph builders expect.

        Args:
            resolved_secrets: Pre-resolved {provider: api_key} from
                ProjectBootstrapConfig.resolve_secrets(). If provided,
                included in the bundle under "secrets" key.

        Returns:
            dict with keys: project_id, tenant_id, graph, tools, policy[, secrets]
        """
        router = self.manifest.router
        if not router:
            return {}

        # Start with any explicit config from the manifest
        graph_config = dict(router.graph.config or {})

        if router.graph.nodes:
            for node in router.graph.nodes:
                node_name = node.name

                # PII masking — if ANY node enables it, graph gets pii_masking=True
                if node.pii_masking:
                    graph_config["pii_masking"] = True

                # Tool binding for tool nodes
                if node.tool_binding:
                    if "node_tool_bindings" not in graph_config:
                        graph_config["node_tool_bindings"] = {}

                    # Ensure node key exists
                    if node_name not in graph_config["node_tool_bindings"]:
                        graph_config["node_tool_bindings"][node_name] = {}

                    bindings = node.tool_binding if isinstance(node.tool_binding, list) else [node.tool_binding]
                    for binding in bindings:
                        if ":" in binding:
                            tool_name, mode = binding.split(":", 1)
                        else:
                            tool_name, mode = binding, "execute"  # default to execute if unspecified

                        graph_config["node_tool_bindings"][node_name][tool_name] = mode

        # If no model_key set explicitly, use default from policy
        if "model_key" not in graph_config and router.policy and router.policy.ai_model_policy:
            graph_config["model_key"] = router.policy.ai_model_policy.default_ai_model
        if "fallback_keys" not in graph_config and router.policy and router.policy.ai_model_policy:
            graph_config["fallback_keys"] = router.policy.ai_model_policy.fallback_ai_models or []

        bundle: dict[str, Any] = {
            "project_id": self.manifest.project.id,
            "tenant_id": self.manifest.project.tenant,
            "graph": {
                "id": router.graph.id,
                "template": router.graph.template,
                "nodes": [n.model_dump(exclude_none=True) for n in router.graph.nodes] if router.graph.nodes else None,
                "edges": [e.model_dump(by_alias=True, exclude_none=True) for e in router.graph.edges]
                if router.graph.edges
                else None,
                "config_ref": router.graph.config_ref,
                "config": graph_config,
            },
            "tools": [],
            "policy": {
                "allowed_tools": (router.policy.allowed_tools or [] if router.policy else []),
                "ai_model_policy_ref": (router.policy.ai_model_policy_ref if router.policy else None),
                "prompts_ref": (router.policy.prompts_ref if router.policy else None),
                "langfuse_tracing_enabled": (
                    router.policy.langfuse_tracing_enabled or False if router.policy else False
                ),
            },
        }

        # Pre-resolved secrets from config — caller decides Shield vs inline
        if resolved_secrets:
            bundle["secrets"] = dict(resolved_secrets)

        # Resolve AiModelPolicy if defined inline
        if router.policy and router.policy.ai_model_policy:
            bundle["policy"]["ai_model_policy"] = router.policy.ai_model_policy.model_dump(exclude_none=True)

        # Compile authorization policy from manifest
        if router.policy and router.policy.authz:
            bundle["policy"]["authz"] = router.policy.authz.model_dump(exclude_none=True)

        # Flatten tools
        if router.tools:
            from contextcore.manifest.models import RouterTool, RouterToolGroup

            for item in router.tools:
                if isinstance(item, RouterToolGroup):
                    for subtool in item.tools:
                        bundle["tools"].append(
                            self._dump_tool(
                                subtool,
                                group=item.group,
                                source=item.source,
                            )
                        )
                elif isinstance(item, RouterTool):
                    bundle["tools"].append(self._dump_tool(item))

        return bundle

    def generate_worker_bindings(self) -> dict[str, Any]:
        """Create Worker schedule/workflow bindings."""
        worker = self.manifest.worker
        if not worker or worker.mode == "disabled":
            return {}

        return {
            "mode": worker.mode,
            "workflows": [wf.model_dump(exclude_none=True) for wf in (worker.workflows or [])],
            "schedules": [sc.model_dump(exclude_none=True) for sc in (worker.schedules or [])],
            "execution_policy": (
                worker.execution_policy.model_dump(exclude_none=True) if worker.execution_policy else None
            ),
        }

    def _dump_tool(
        self,
        tool,
        group: str | None = None,
        source: str | None = None,
    ) -> dict[str, Any]:
        data = tool.model_dump(exclude_none=True)
        if group:
            data["group"] = group
        if source:
            data["source"] = source
        return data
