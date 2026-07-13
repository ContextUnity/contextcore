import pytest
from contextunity.core.manifest import ContextUnityMigrationOverlay, ContextUnityProject
from contextunity.core.manifest.generators import ArtifactGenerator
from contextunity.core.sdk.bootstrap.api import _extract_stream_tool_names
from pydantic import ValidationError


@pytest.fixture
def minimal_sample_project_payload() -> dict:
    return {
        "apiVersion": "contextunity/v1alpha8",
        "kind": "ContextUnityProject",
        "project": {
            "id": "tenant_a",
            "name": "TenantA",
        },
        "services": {
            "router": {"enabled": True},
            "brain": {"enabled": True},
            "worker": {"enabled": False},
            "shield": {"enabled": True},
        },
        "router": {
            "default_graph": "main",
            "graph": {
                "main": {
                    "id": "tenant_a",
                    "template": "yaml:retrieval_augmented",
                    "config_ref": "router/sql_analytics.yaml",
                }
            },
            "config": {
                "policy": {
                    "allowed_tools": ["execute_test_sql"],
                    "models_ref": "router/models.yaml",
                    "prompts_ref": "router/prompts/",
                    "langfuse": {"tracing_enabled": True},
                },
            },
        },
        "brain": {
            "tenant_scope": "single",
            "capabilities": ["search", "memory_write", "trace_write"],
            "knowledge_domains": ["medical_reports"],
        },
        "shield": {"secret_resolution": True, "compliance_mode": "strict"},
        "integration": {
            "registration": {"mode": "generated_bundle", "output": "build/router-registration.json"},
            "env": {"output": "build/.env.example"},
        },
        "secrets": [{"keys": ["openai_api_key"], "owner": "contextunity", "resolver": "env"}],
    }


def test_positive_sample_project_validates(minimal_sample_project_payload):
    """Positive test for remote router archetype (tenant_a-style)."""
    project = ContextUnityProject(**minimal_sample_project_payload)
    assert project.project.id == "tenant_a"
    assert project.services.worker.enabled is False
    assert getattr(project, "worker", None) is None


def test_reject_extra_fields(minimal_sample_project_payload):
    """Negative: Ensure we strictly forbid extra fields."""
    minimal_sample_project_payload["legacy_bridge"] = True  # forbidden in stable schema
    with pytest.raises(ValidationError) as exc:
        ContextUnityProject(**minimal_sample_project_payload)
    assert "Extra inputs are not permitted" in str(exc.value)


def test_reject_project_embedding_override(minimal_sample_project_payload):
    """The current Brain owns one deployment-wide embedding space."""
    minimal_sample_project_payload["brain"]["embedding"] = {"model": "openai/text-embedding-3-small"}

    with pytest.raises(ValidationError) as exc:
        ContextUnityProject(**minimal_sample_project_payload)

    assert "Extra inputs are not permitted" in str(exc.value)


def test_secret_group_accepts_project_owner(minimal_sample_project_payload):
    """``owner`` on ``secrets`` groups is metadata; project-scoped groups validate."""
    minimal_sample_project_payload["secrets"] = [
        {"keys": ["DATABASE_URL"], "owner": "project", "resolver": "env"},
    ]
    project = ContextUnityProject(**minimal_sample_project_payload)
    assert project.secrets is not None
    assert project.secrets[0].owner == "project"


def test_secret_group_defaults_resolver_to_env(minimal_sample_project_payload):
    """``secrets`` may omit resolver — defaults to ``env``."""
    minimal_sample_project_payload["secrets"] = [
        {"keys": ["openai_api_key"], "owner": "contextunity"},
    ]
    project = ContextUnityProject(**minimal_sample_project_payload)
    assert project.secrets is not None
    assert project.secrets[0].resolver == "env"


def test_reject_unqualified_ai_model(minimal_sample_project_payload):
    """Negative: Ensure ai_models must be provider/model."""
    # Build a policy payload with an unqualified AI model
    minimal_sample_project_payload["router"]["config"]["policy"].pop("models_ref")
    minimal_sample_project_payload["router"]["config"]["policy"]["models"] = {
        "llm": {"default": "gpt-5-mini"}  # Invalid! Must be e.g. openai/gpt-5-mini
    }

    with pytest.raises(ValidationError) as exc:
        ContextUnityProject(**minimal_sample_project_payload)
    assert "must be an executable 'provider/model' reference" in str(exc.value)


def test_rejects_unqualified_auto_extract_model(minimal_sample_project_payload):
    minimal_sample_project_payload["router"]["config"]["memory"] = {
        "auto_extract": {"enabled": True, "extraction_model": "logical-alias"}
    }

    with pytest.raises(ValidationError) as exc:
        ContextUnityProject(**minimal_sample_project_payload)

    assert "auto_extract.extraction_model" in str(exc.value)
    assert "provider/model" in str(exc.value)


def test_mutually_exclusive_policy_refs(minimal_sample_project_payload):
    """Negative: models_ref and inline models are mutually exclusive."""
    minimal_sample_project_payload["router"]["config"]["policy"]["models"] = {"llm": {"default": "openai/gpt-5-mini"}}
    # Payload now has both models_ref (from fixture) and models
    with pytest.raises(ValidationError) as exc:
        ContextUnityProject(**minimal_sample_project_payload)
    assert "mutually exclusive" in str(exc.value)


def test_reject_declarative_router_graph_mode(minimal_sample_project_payload):
    """Negative: v1alpha runtime no longer accepts declarative graph mode."""
    minimal_sample_project_payload["router"]["graph"]["main"] = {
        "id": "tenant_a",
        "mode": "declarative",
        "nodes": [{"name": "planner", "type": "llm", "model": "openai/gpt-5-mini"}],
        "edges": [{"from_node": "planner", "to_node": "planner"}],
    }

    with pytest.raises(ValidationError) as exc:
        ContextUnityProject(**minimal_sample_project_payload)

    assert "Extra inputs are not permitted" in str(exc.value)


def test_reject_worker_trigger_without_workflows(minimal_sample_project_payload):
    """Negative: worker mode trigger-only requires workflows to be declared."""
    minimal_sample_project_payload["services"]["worker"]["enabled"] = True
    # We set mode but omit 'workflows'
    minimal_sample_project_payload["worker"] = {
        "mode": "trigger-only"
        # workflows explicitly omitted
    }

    with pytest.raises(ValidationError) as exc:
        ContextUnityProject(**minimal_sample_project_payload)

    assert "trigger-only worker mode requires workflows" in str(exc.value)


# Removed test_reject_commerce_overlay_missing_section as constraint was updated


def test_reject_removed_graph_federated_tools(minimal_sample_project_payload):
    """Breaking change: graph-level federated_tools is no longer accepted."""
    minimal_sample_project_payload["router"]["graph"]["main"]["federated_tools"] = {
        "medical_sql": {"handler": "sample_project.chat.tools.execute_safe_query"}
    }

    with pytest.raises(ValidationError) as exc:
        ContextUnityProject(**minimal_sample_project_payload)

    assert "Extra inputs are not permitted" in str(exc.value)


def test_router_node_type_rejects_platform(minimal_sample_project_payload):
    """Canonical router node types are llm, agent, and tool only."""
    minimal_sample_project_payload["router"]["graph"]["main"].pop("template", None)
    minimal_sample_project_payload["router"]["graph"]["main"]["nodes"] = [
        {"name": "tool_exec", "type": "platform", "tool_binding": "router_extract_query"}
    ]
    minimal_sample_project_payload["router"]["graph"]["main"]["edges"] = [
        {"from_node": "__start__", "to_node": "tool_exec"},
        {"from_node": "tool_exec", "to_node": "__end__"},
    ]

    with pytest.raises(ValidationError):
        ContextUnityProject(**minimal_sample_project_payload)


def test_router_node_type_inferred_from_tool_binding(minimal_sample_project_payload):
    """Node type defaults to 'tool' when tool_binding is present."""
    minimal_sample_project_payload["router"]["graph"]["main"].pop("template", None)
    minimal_sample_project_payload["router"]["graph"]["main"]["nodes"] = [
        {"name": "tool_exec", "tool_binding": "federated:medical_sql"}
    ]
    minimal_sample_project_payload["router"]["graph"]["main"]["edges"] = [
        {"from_node": "__start__", "to_node": "tool_exec"},
        {"from_node": "tool_exec", "to_node": "__end__"},
    ]

    project = ContextUnityProject(**minimal_sample_project_payload)
    assert project.router.graph["main"].nodes[0].type == "tool"


def test_graph_bare_tool_binding_is_accepted_as_platform_shorthand(minimal_sample_project_payload):
    """Bare node tool_binding is accepted as platform shorthand."""
    minimal_sample_project_payload["router"]["graph"]["main"].pop("template", None)
    minimal_sample_project_payload["router"]["graph"]["main"]["nodes"] = [
        {"name": "tool_exec", "tool_binding": "router_extract_query"}
    ]
    minimal_sample_project_payload["router"]["graph"]["main"]["edges"] = [
        {"from_node": "__start__", "to_node": "tool_exec"},
        {"from_node": "tool_exec", "to_node": "__end__"},
    ]

    project = ContextUnityProject(**minimal_sample_project_payload)
    assert project.router.graph["main"].nodes[0].tool_binding == "router_extract_query"


def test_graph_federated_bindings_strip_known_prefixes(minimal_sample_project_payload):
    """Node tool_binding keeps explicit namespaces."""
    minimal_sample_project_payload["router"]["graph"]["main"].pop("template", None)
    minimal_sample_project_payload["router"]["graph"]["main"]["nodes"] = [
        {"name": "tool_exec", "tool_binding": "federated:medical_sql"}
    ]
    minimal_sample_project_payload["router"]["graph"]["main"]["edges"] = [
        {"from_node": "__start__", "to_node": "tool_exec"},
        {"from_node": "tool_exec", "to_node": "__end__"},
    ]

    project = ContextUnityProject(**minimal_sample_project_payload)
    assert project.router.graph["main"].nodes[0].tool_binding == "federated:medical_sql"


def test_graph_config_rejects_opaque_runtime_keys(minimal_sample_project_payload):
    """v1alpha8 graph.config is typed; template/runtime keys belong in graph.runtime."""
    minimal_sample_project_payload["router"]["graph"]["main"]["config"] = {"max_retries": 2}

    with pytest.raises(ValidationError) as exc:
        ContextUnityProject(**minimal_sample_project_payload)

    assert "Extra inputs are not permitted" in str(exc.value)


def test_router_config_conductor_block_accepted(minimal_sample_project_payload):
    """Phase 3 M05: router.config.conductor is a typed project-level block."""
    minimal_sample_project_payload["router"]["config"]["conductor"] = {
        "cost_aware_enabled": True,
        "quality_threshold": 0.75,
        "max_cost_usd": 0.01,
        "default_safe_model": "mock/balanced",
    }
    project = ContextUnityProject(**minimal_sample_project_payload)
    assert project.router is not None
    assert project.router.config.conductor is not None
    assert project.router.config.conductor.cost_aware_enabled is True
    assert project.router.config.conductor.default_safe_model == "mock/balanced"
    assert project.router.config.conductor.quality_threshold == 0.75


def test_router_config_conductor_rejects_l1_catalog_path(minimal_sample_project_payload):
    """Catalog path is L0-only; L1 manifest must not carry models_catalog_path."""
    from pydantic import ValidationError

    minimal_sample_project_payload["router"]["config"]["conductor"] = {
        "cost_aware_enabled": True,
        "models_catalog_path": "tests/fixtures/phase3/models.yml",
    }
    with pytest.raises(ValidationError) as exc:
        ContextUnityProject(**minimal_sample_project_payload)
    assert "models_catalog_path" in str(exc.value)


def test_artifact_generator_projects_router_memory_and_graph_runtime(minimal_sample_project_payload):
    """Layer-1 router.config.memory merges into typed graph config; runtime stays separate."""
    minimal_sample_project_payload["router"]["config"]["memory"] = {
        "inject": True,
        "depth": "deep",
        "synapse_lookup": {"enabled": True},
    }
    minimal_sample_project_payload["router"]["graph"]["main"]["config"] = {
        "memory": {"depth": "research", "synapse_lookup": {"enabled": False}},
    }
    minimal_sample_project_payload["router"]["graph"]["main"]["runtime"] = {"max_retries": 2}

    project = ContextUnityProject(**minimal_sample_project_payload)
    bundle = ArtifactGenerator(project).generate_router_registration_bundle()

    config = bundle.graph["main"]["config"]
    assert config["memory"] == {
        "inject": True,
        "depth": "research",
        "synapse_lookup": {"enabled": False},
    }
    # Opaque runtime must NOT be re-mixed into typed config (alpha8).
    assert "max_retries" not in config
    assert bundle.graph["main"]["runtime"] == {"max_retries": 2}


def test_graph_runtime_rejects_non_json_values(minimal_sample_project_payload):
    """graph.runtime is wire JSON only — non-serializable values fail validation."""
    minimal_sample_project_payload["router"]["graph"]["main"]["runtime"] = {"bad": object()}

    with pytest.raises(ValidationError) as exc:
        ContextUnityProject(**minimal_sample_project_payload)

    assert "runtime" in str(exc.value).lower() or "JSON" in str(exc.value)


def test_artifact_generator_registers_only_explicit_federated_tools(minimal_sample_project_payload):
    """Bare/platform tool bindings do not become project-side BiDi tools."""
    minimal_sample_project_payload["router"]["graph"]["main"].pop("template", None)
    minimal_sample_project_payload["router"]["graph"]["main"]["nodes"] = [
        {"name": "extract", "type": "tool", "tool_binding": "router_extract_query"},
        {"name": "search", "type": "tool", "tool_binding": "platform:brain_search"},
        {"name": "custom", "type": "tool", "tool_binding": "federated:medical_sql"},
    ]
    minimal_sample_project_payload["router"]["graph"]["main"]["edges"] = [
        {"from_node": "__start__", "to_node": "extract"},
        {"from_node": "extract", "to_node": "search"},
        {"from_node": "search", "to_node": "custom"},
        {"from_node": "custom", "to_node": "__end__"},
    ]

    project = ContextUnityProject(**minimal_sample_project_payload)
    bundle = ArtifactGenerator(project).generate_router_registration_bundle()

    assert "tools" not in bundle.model_dump(exclude_none=True)
    assert [tool["name"] for tool in bundle.graph["main"]["config"]["federated_tools"]] == ["medical_sql"]
    node_bindings = bundle.graph["main"]["config"]["node_tool_bindings"]
    assert node_bindings == {"custom": {"medical_sql": "execute"}}


def test_sdk_stream_tools_use_graph_scoped_federated_tools(minimal_sample_project_payload):
    """SDK stream ready must announce v1alpha7 graph-scoped federated tools."""
    minimal_sample_project_payload["router"]["graph"]["main"].pop("template", None)
    minimal_sample_project_payload["router"]["graph"]["main"]["nodes"] = [
        {"name": "custom", "type": "tool", "tool_binding": "federated:medical_sql"},
    ]
    minimal_sample_project_payload["router"]["graph"]["main"]["edges"] = [
        {"from_node": "__start__", "to_node": "custom"},
        {"from_node": "custom", "to_node": "__end__"},
    ]

    project = ContextUnityProject(**minimal_sample_project_payload)
    bundle = ArtifactGenerator(project).generate_router_registration_bundle()

    assert "tools" not in bundle.model_dump(exclude_none=True)
    assert _extract_stream_tool_names(bundle) == ["medical_sql"]


def test_router_agent_node_accepts_tools(minimal_sample_project_payload):
    """Agent node is separate from simple llm and carries a tool allowlist."""
    minimal_sample_project_payload["router"]["graph"]["main"].pop("template", None)
    minimal_sample_project_payload["router"]["graph"]["main"]["nodes"] = [
        {
            "name": "medical_agent",
            "type": "agent",
            "model": "openai/gpt-5-mini",
            "tools": ["federated:medical_sql"],
        }
    ]
    minimal_sample_project_payload["router"]["graph"]["main"]["edges"] = [
        {"from_node": "__start__", "to_node": "medical_agent"},
        {"from_node": "medical_agent", "to_node": "__end__"},
    ]

    project = ContextUnityProject(**minimal_sample_project_payload)
    node = project.router.graph["main"].nodes[0]
    assert node.type == "agent"
    assert node.tools == ["federated:medical_sql"]


def test_yaml_template_accepts_overrides_not_nodes(minimal_sample_project_payload):
    """YAML templates are fixed topology; projects customize via overrides."""
    minimal_sample_project_payload["router"]["graph"]["main"] = {
        "template": "yaml:retrieval_augmented",
        "overrides": {"generate": {"config": {"temperature": 0.1}}},
    }

    project = ContextUnityProject(**minimal_sample_project_payload)
    assert project.router.graph["main"].overrides["generate"]["config"]["temperature"] == 0.1


def test_yaml_template_rejects_nodes(minimal_sample_project_payload):
    """YAML templates must not accept project-authored nodes."""
    minimal_sample_project_payload["router"]["graph"]["main"] = {
        "template": "yaml:retrieval_augmented",
        "nodes": [{"name": "extra", "type": "llm"}],
        "edges": [{"from_node": "__start__", "to_node": "extra"}],
    }

    with pytest.raises(ValidationError) as exc:
        ContextUnityProject(**minimal_sample_project_payload)

    assert "exactly one graph source" in str(exc.value)


def test_router_node_meta_fields(minimal_sample_project_payload):
    """Node meta supports handler/source/toolkit contract."""
    minimal_sample_project_payload["router"]["graph"]["main"].pop("template", None)
    minimal_sample_project_payload["router"]["graph"]["main"]["nodes"] = [
        {
            "name": "tool_exec",
            "tool_binding": "federated:medical_sql",
            "meta": {
                "handler": "sample_project.chat.tools.execute_safe_query",
                "source": "toolkit",
                "toolkit": "MedSqlToolkit",
            },
        }
    ]
    minimal_sample_project_payload["router"]["graph"]["main"]["edges"] = [
        {"from_node": "__start__", "to_node": "tool_exec"},
        {"from_node": "tool_exec", "to_node": "__end__"},
    ]

    project = ContextUnityProject(**minimal_sample_project_payload)
    node_meta = project.router.graph["main"].nodes[0].meta
    assert node_meta is not None
    assert node_meta.handler == "sample_project.chat.tools.execute_safe_query"
    assert node_meta.source == "toolkit"
    assert node_meta.toolkit == "MedSqlToolkit"


def test_overlay_reference_coupling():
    """Positive: valid migration overlay."""
    payload = {
        "apiVersion": "contextunity/v1alpha8",
        "kind": "ContextUnityMigrationOverlay",
        "target_ref": "contextunity.project.yaml",
        "project": {"id": "tagrai"},
        "as_is": {
            "integration_style": "embedded-router",
            "runtime_mode": "embedded-legacy",
            "graph_embedding": "embedded-graph-module",
            "model_config_style": "inline-code",
        },
        "gaps": [
            {
                "id": "gap-1",
                "severity": "high",
                "owner": "project",
                "current_state": "Embedded code",
                "target_state": "Remote integration",
            }
        ],
        "migration_path": {"phases": [{"id": "phase-1", "goal": "Migrate", "changes": ["Change import"]}]},
        "acceptance": {"done_when": ["Code is removed"]},
    }
    overlay = ContextUnityMigrationOverlay(**payload)
    assert overlay.target_ref == "contextunity.project.yaml"
    assert overlay.project.id == "tagrai"


def test_reject_unaddressed_legacy_bridges(minimal_sample_project_payload):
    """Negative: If a legacy bridge is true, there must be gaps documenting it."""
    payload = {
        "apiVersion": "contextunity/v1alpha8",
        "kind": "ContextUnityMigrationOverlay",
        "target_ref": "contextunity.project.yaml",
        "project": {"id": "tagrai"},
        "as_is": {
            "integration_style": "embedded-router",
            "runtime_mode": "embedded-legacy",
        },
        "legacy_bridges": {"direct_temporal_bypass": True},
        "gaps": [],  # Empty gaps!
        "migration_path": {"phases": []},
        "acceptance": {"done_when": []},
    }
    with pytest.raises(ValidationError) as exc:
        ContextUnityMigrationOverlay(**payload)

    assert "associated gaps must be documented" in str(exc.value)


def test_reject_blocking_gap_no_phases():
    """Negative: Blocking gaps must have at least one migration phase defined."""
    payload = {
        "apiVersion": "contextunity/v1alpha8",
        "kind": "ContextUnityMigrationOverlay",
        "target_ref": "contextunity.project.yaml",
        "project": {"id": "tagrai"},
        "as_is": {
            "integration_style": "embedded-router",
            "runtime_mode": "embedded-legacy",
        },
        "legacy_bridges": {},
        "gaps": [
            {
                "id": "gap-2",
                "severity": "high",
                "owner": "project",
                "current_state": "Bad state",
                "target_state": "Good state",
                "blocking": True,
            }
        ],
        "migration_path": {"phases": []},  # Empty phases!
        "acceptance": {"done_when": []},
    }
    with pytest.raises(ValidationError) as exc:
        ContextUnityMigrationOverlay(**payload)

    assert "but no migration phases are defined" in str(exc.value)


pytestmark = pytest.mark.unit
