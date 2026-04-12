import pytest
from contextunity.core.manifest import ContextUnityMigrationOverlay, ContextUnityProject
from pydantic import ValidationError


@pytest.fixture
def minimal_nszu_payload() -> dict:
    return {
        "apiVersion": "contextunity/v1alpha1",
        "kind": "ContextUnityProject",
        "project": {
            "id": "tenant_a",
            "name": "TenantA",
            "tenant": "tenant_a",
        },
        "services": {
            "router": {"enabled": True},
            "brain": {"enabled": True},
            "worker": {"enabled": False},
            "commerce": {"enabled": False},
            "shield": {"enabled": True},
            "zero": {"enabled": True},
        },
        "router": {
            "graph": {
                "id": "tenant_a",
                "template": "sql_analytics",
                "config_ref": "router/sql_analytics.yaml",
            },
            "tools": [
                {
                    "name": "execute_test_sql",
                    "type": "sql",
                    "execution": "federated",
                    "description": "SQL Tool",
                    "config_ref": "router/tools/execute_test_sql.yaml",
                }
            ],
            "policy": {
                "allowed_tools": ["execute_test_sql"],
                "ai_model_policy_ref": "router/ai_models.yaml",
                "prompts_ref": "router/prompts/",
                "langfuse_tracing_enabled": True,
            },
        },
        "brain": {
            "tenant_scope": "single",
            "capabilities": ["search", "memory_write", "trace_write"],
            "knowledge_domains": ["medical_reports"],
        },
        "shield": {"secret_resolution": True, "compliance_mode": "strict"},
        "zero": {"pii_pipeline": True},
        "integration": {
            "registration": {"mode": "generated_bundle", "output": "build/router-registration.json"},
            "env": {"output": "build/.env.example"},
        },
        "secrets": [{"keys": ["openai_api_key"], "owner": "project", "resolver": "shield"}],
    }


def test_positive_nszu_validates(minimal_nszu_payload):
    """Positive test for remote router archetype (tenant_a-style)."""
    project = ContextUnityProject(**minimal_nszu_payload)
    assert project.project.id == "tenant_a"
    assert project.services.worker.enabled is False
    assert getattr(project, "worker", None) is None


def test_reject_extra_fields(minimal_nszu_payload):
    """Negative: Ensure we strictly forbid extra fields."""
    minimal_nszu_payload["legacy_bridge"] = True  # forbidden in stable schema
    with pytest.raises(ValidationError) as exc:
        ContextUnityProject(**minimal_nszu_payload)
    assert "Extra inputs are not permitted" in str(exc.value)


def test_reject_unqualified_ai_model(minimal_nszu_payload):
    """Negative: Ensure ai_models must be provider/model."""
    # Build a policy payload with an unqualified AI model
    minimal_nszu_payload["router"]["policy"].pop("ai_model_policy_ref")
    minimal_nszu_payload["router"]["policy"]["ai_model_policy"] = {
        "default_ai_model": "gpt-5-mini"  # Invalid! Must be e.g. openai/gpt-5-mini
    }

    with pytest.raises(ValidationError) as exc:
        ContextUnityProject(**minimal_nszu_payload)
    assert "must be provider-qualified (e.g. provider/model)" in str(exc.value)


def test_mutually_exclusive_policy_refs(minimal_nszu_payload):
    """Negative: ai_model_policy_ref and inline policy are mutually exclusive."""
    minimal_nszu_payload["router"]["policy"]["ai_model_policy"] = {"default_ai_model": "openai/gpt-5-mini"}
    # Payload now has both ai_model_policy_ref (from fixture) and ai_model_policy
    with pytest.raises(ValidationError) as exc:
        ContextUnityProject(**minimal_nszu_payload)
    assert "mutually exclusive" in str(exc.value)


def test_reject_declarative_router_graph_mode(minimal_nszu_payload):
    """Negative: v1alpha runtime no longer accepts declarative graph mode."""
    minimal_nszu_payload["router"]["graph"] = {
        "id": "tenant_a",
        "mode": "declarative",
        "nodes": [{"name": "planner", "type": "llm", "model": "openai/gpt-5-mini"}],
        "edges": [{"from": "planner", "to": "planner"}],
    }

    with pytest.raises(ValidationError) as exc:
        ContextUnityProject(**minimal_nszu_payload)

    assert "Extra inputs are not permitted" in str(exc.value)


def test_reject_worker_trigger_without_workflows(minimal_nszu_payload):
    """Negative: worker mode trigger-only requires workflows to be declared."""
    minimal_nszu_payload["services"]["worker"]["enabled"] = True
    # We set mode but omit 'workflows'
    minimal_nszu_payload["worker"] = {
        "mode": "trigger-only"
        # workflows explicitly omitted
    }

    with pytest.raises(ValidationError) as exc:
        ContextUnityProject(**minimal_nszu_payload)

    assert "trigger-only worker mode requires workflows" in str(exc.value)


# Removed test_reject_commerce_overlay_missing_section as constraint was updated


def test_valid_commerce_tool_group(minimal_nszu_payload):
    """Positive: Test replacing tools with grouped definitions."""
    minimal_nszu_payload["router"]["tools"] = [
        {
            "group": "commerce-matcher",
            "source": "commerce",
            "execution": "federated",
            "tools": [{"name": "bulk_link_products", "execution": "federated"}],
        }
    ]

    project = ContextUnityProject(**minimal_nszu_payload)
    assert project.router.tools[0].group == "commerce-matcher"
    assert project.router.tools[0].tools[0].name == "bulk_link_products"


def test_overlay_reference_coupling():
    """Positive: valid migration overlay."""
    payload = {
        "apiVersion": "contextunity/v1alpha1",
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


def test_reject_unaddressed_legacy_bridges(minimal_nszu_payload):
    """Negative: If a legacy bridge is true, there must be gaps documenting it."""
    payload = {
        "apiVersion": "contextunity/v1alpha1",
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
        "apiVersion": "contextunity/v1alpha1",
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
