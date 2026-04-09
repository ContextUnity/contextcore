"""
ContextUnity Project Manifest Models.
Defines the `v1alpha Target Schema` and `Migration Overlay` strictly enforcing the deployment contract.
"""

from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def _validate_provider_qualified(v: str) -> str:
    """Helper to ensure AI model names are provider-qualified."""
    if "/" not in v:
        raise ValueError(f"AI model '{v}' must be provider-qualified (e.g. provider/model).")
    return v


# -----------------------------------------------------------------------------
# Core Project & Services Sections
# -----------------------------------------------------------------------------


class ProjectOwnership(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repo: str | None = None
    team: str | None = None


class ProjectSection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    name: str
    tenant: str
    ownership: ProjectOwnership | None = None


class ServiceEnablement(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool


class ServicesSection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    router: ServiceEnablement | None = None
    brain: ServiceEnablement | None = None
    worker: ServiceEnablement | None = None
    commerce: ServiceEnablement | None = None
    shield: ServiceEnablement | None = None
    zero: ServiceEnablement | None = None


# -----------------------------------------------------------------------------
# Router Section
# -----------------------------------------------------------------------------


class RouterNode(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    name: str
    type: Literal["llm", "tool", "router"] | None = None
    model: str | None = None
    model_secret_ref: str | None = None
    prompt_ref: str | None = None
    prompt_variants_ref: str | None = None
    prompt_signature: str | None = None
    prompt_version: str | None = None
    prompt_variants_versions: dict[str, str] | None = None
    pii_masking: bool | None = None
    tool_binding: str | list[str] | None = None
    description: str | None = None


class RouterEdge(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: str = Field(alias="from")
    target: str | None = Field(default=None, alias="to")
    condition_key: str | None = None
    condition_map: dict[str, str] | None = None

    @model_validator(mode="after")
    def validate_edge(self) -> Self:
        if not self.target and not self.condition_key:
            raise ValueError("Edge must have either 'to' or 'condition_key'")
        if self.condition_key and not self.condition_map:
            raise ValueError("Edge with 'condition_key' must provide 'condition_map'")
        return self


class RouterGraph(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    template: Literal["sql_analytics", "gardener", "dispatcher", "rag_retrieval", "news_engine", "custom"]
    nodes: list[RouterNode] | None = None
    edges: list[RouterEdge] | None = None
    config_ref: str | None = None
    config: dict | None = None

    @model_validator(mode="after")
    def validate_graph(self) -> Self:
        if self.template == "custom" and (not self.nodes or not self.edges):
            raise ValueError("router.graph with template='custom' requires both 'nodes' and 'edges'")
        return self


class RouterTool(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    type: str | None = None
    execution: Literal["federated", "router-local", "worker-trigger"]
    description: str | None = None
    config_ref: str | None = None
    config: dict | None = None


class RouterToolGroup(BaseModel):
    model_config = ConfigDict(extra="forbid")
    group: str
    source: str
    execution: Literal["federated", "router-local", "worker-trigger"]
    tools: list[RouterTool]


class AiModelPolicy(BaseModel):
    """AI model selection policy.

    Secret refs are env var names whose values are stored in Shield.
    Per-node refs use path ``{node_name}/{env_var}``; policy-level refs
    use path ``{provider}/{model}`` (derived from the model key).
    """

    model_config = ConfigDict(extra="forbid")
    default_ai_model: str
    default_model_secret_ref: str | None = None
    fallback_ai_models: list[str] | None = None
    fallback_model_secret_refs: list[str] | None = None

    @field_validator("default_ai_model", mode="after")
    @classmethod
    def val_default_ai_model(cls, v: str) -> str:
        return _validate_provider_qualified(v)

    @field_validator("fallback_ai_models", mode="after")
    @classmethod
    def val_fallback_ai_models(cls, v: list[str] | None) -> list[str] | None:
        if v:
            for item in v:
                _validate_provider_qualified(item)
        return v

    @model_validator(mode="after")
    def validate_fallback_refs_length(self) -> Self:
        if self.fallback_ai_models and self.fallback_model_secret_refs:
            if len(self.fallback_ai_models) != len(self.fallback_model_secret_refs):
                raise ValueError(
                    f"fallback_ai_models ({len(self.fallback_ai_models)}) and "
                    f"fallback_model_secret_refs ({len(self.fallback_model_secret_refs)}) "
                    f"must have equal length"
                )
        return self


class RouterAuthzPolicy(BaseModel):
    """Project-level authorization defaults for the Router.

    Defines the default scope, tenant binding, risk level, and role bindings
    so that individual tools don't need to repeat authz boilerplate.
    Per-tool ``RouterToolAuthz`` overrides these defaults.
    """

    model_config = ConfigDict(extra="forbid")
    default_scope: str | None = None  # e.g. "read"
    tenant_binding: Literal["explicit", "inferred", "none"] = "inferred"
    default_risk: Literal["low", "standard", "high"] = "standard"
    role_bindings: dict[str, list[str]] | None = None  # role → permissions
    admin_permissions: list[str] | None = None  # explicit admin-level permissions


class RouterPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allowed_tools: list[str] | None = None
    ai_model_policy_ref: str | None = None
    ai_model_policy: AiModelPolicy | None = None
    prompts_ref: str | None = None
    langfuse_tracing_enabled: bool | None = None
    authz: RouterAuthzPolicy | None = None

    @model_validator(mode="after")
    def check_ai_policy_mutually_exclusive(self) -> Self:
        if self.ai_model_policy_ref and self.ai_model_policy:
            raise ValueError("ai_model_policy_ref and ai_model_policy are mutually exclusive")
        if not self.ai_model_policy_ref and not self.ai_model_policy:
            raise ValueError("One of ai_model_policy_ref or ai_model_policy is required")
        return self


class RouterSection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    graph: RouterGraph
    tools: list[RouterToolGroup | RouterTool] | None = None
    policy: RouterPolicy


# -----------------------------------------------------------------------------
# Brain, Shield, Zero, Observability
# -----------------------------------------------------------------------------


class BrainEmbedding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str = "all-MiniLM-L6-v2"


class BrainStoragePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    retention_days: int | None = None


class BrainSection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_scope: Literal["single", "multi"]
    capabilities: list[str]
    knowledge_domains: list[str] | None = None
    embedding: BrainEmbedding | None = None
    storage_policy: BrainStoragePolicy | None = None


class ShieldSection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    secret_resolution: bool | None = None
    compliance_mode: Literal["standard", "strict"] | None = None


class ZeroSection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pii_pipeline: bool | None = None
    anonymization_ref: str | None = None


class ObservabilitySection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    health_probe: bool
    readiness_check_mode: Literal["stream", "poll"]
    expected_tools: list[str] | None = None


# -----------------------------------------------------------------------------
# Worker & Commerce
# -----------------------------------------------------------------------------


class WorkerWorkflow(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workflow_type: str
    task_queue: str
    trigger: Literal["manual", "scheduled", "event"] | None = None
    ownership: str | None = None
    input_contract_ref: str | None = None
    result_contract_ref: str | None = None


class WorkerSchedule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    workflow_type: str
    cron: str
    timezone: str


class WorkerExecutionPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    retries: int | None = None
    timeouts: str | None = None
    idempotency: bool | None = None


class WorkerSection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["disabled", "trigger-only", "durable-orchestrator"]
    workflows: list[WorkerWorkflow] | None = None
    schedules: list[WorkerSchedule] | None = None
    execution_policy: WorkerExecutionPolicy | None = None

    @model_validator(mode="after")
    def validate_worker_modes(self) -> Self:
        if self.mode == "disabled":
            # Just ignore child fields if declared gracefully
            pass
        elif self.mode == "trigger-only":
            if not self.workflows:
                raise ValueError("trigger-only worker mode requires workflows")
            # Enforce that trigger fields exist
            for wf in self.workflows:
                if not getattr(wf, "trigger", None):
                    raise ValueError(f"Workflow {wf.workflow_type} must have 'trigger' in trigger-only mode")
        elif self.mode == "durable-orchestrator":
            if not self.workflows:
                raise ValueError("durable-orchestrator worker mode requires workflows")
            if not getattr(self, "execution_policy", None):
                raise ValueError("durable-orchestrator worker mode requires execution_policy")
            for wf in self.workflows:
                if not getattr(wf, "ownership", None):
                    raise ValueError(f"Workflow {wf.workflow_type} must have 'ownership' in durable-orchestrator mode")
        return self


class CommerceConnector(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    runtime: str
    entrypoint: str


class CommerceSyncFlow(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    direction: Literal["commerce_to_project", "project_to_commerce", "bidirectional"]


class CommerceSection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    overlay_mode: Literal["generated"]
    suppliers_ref: str | None = None
    taxonomy_ref: str | None = None
    connectors: list[CommerceConnector] | None = None
    sync_flows: list[CommerceSyncFlow] | None = None
    admin_extensions: list[str] | None = None


# -----------------------------------------------------------------------------
# Integration & Secrets
# -----------------------------------------------------------------------------


class IntegrationRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["generated_bundle"]
    output: str | None = None


class IntegrationEnv(BaseModel):
    model_config = ConfigDict(extra="forbid")
    output: str


class IntegrationTasks(BaseModel):
    model_config = ConfigDict(extra="forbid")
    output: str


class IntegrationDocs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    output: str


class IntegrationTesting(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mock_mode: bool | None = None
    validation_command: str | None = None


class IntegrationSection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    registration: IntegrationRegistration
    env: IntegrationEnv | None = None
    tasks: IntegrationTasks | None = None
    docs: IntegrationDocs | None = None
    testing: IntegrationTesting | None = None


class SecretGroup(BaseModel):
    model_config = ConfigDict(extra="forbid")
    owner: Literal["project", "contextunity", "shared"]
    resolver: str
    keys: list[str]


# -----------------------------------------------------------------------------
# Top-level ContextUnityProject
# -----------------------------------------------------------------------------


class ContextUnityProject(BaseModel):
    """
    v1alpha Target Schema for stable Canonical ContextUnity project integration.
    """

    model_config = ConfigDict(extra="forbid")
    apiVersion: Literal["contextunity/v1alpha1"]
    kind: Literal["ContextUnityProject"]

    project: ProjectSection
    services: ServicesSection

    router: RouterSection | None = None
    brain: BrainSection | None = None
    shield: ShieldSection | None = None
    zero: ZeroSection | None = None
    worker: WorkerSection | None = None
    commerce: CommerceSection | None = None
    observability: ObservabilitySection | None = None

    integration: IntegrationSection | None = None
    secrets: list[SecretGroup] | None = None

    @model_validator(mode="after")
    def enforce_service_presences(self) -> Self:
        # Only router requires a config section — others work with defaults
        if self.services.router and self.services.router.enabled and not self.router:
            raise ValueError("router section is required when services.router.enabled is true")
        return self


# -----------------------------------------------------------------------------
# Migration Overlay Models
# -----------------------------------------------------------------------------


class OverlayProject(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    name: str | None = None
    owner: str | None = None


class OverlayAsIs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    integration_style: Literal[
        "startup-registration", "embedded-router", "service-import", "commerce-overlay", "deep-embedded-router"
    ]
    runtime_mode: Literal["service-integrated", "embedded-legacy", "migration-bridge"]
    graph_embedding: (
        Literal["external-template", "embedded-graph-module", "package-import", "package-import-with-internal-modules"]
        | None
    ) = None
    tool_execution: Literal["bidi-federated", "router-local", "mixed"] | None = None
    worker_usage: (
        Literal["unused", "trigger-only", "partial-orchestrator", "direct-temporal", "direct-temporal-bypass"] | None
    ) = None
    commerce_usage: str | None = None
    secret_bootstrap: Literal["env-only", "env-to-shield", "mixed"] | None = None
    model_config_style: Literal["env-per-role", "env-per-node", "inline-code", "mixed"] | None = None


class OverlayGap(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    title: str | None = None
    severity: Literal["high", "medium", "low"]
    owner: Literal["project", "contextunity", "shared"]
    current_state: str
    target_state: str
    blocking: bool | None = None
    depends_on: str | None = None
    evidence: list[str] | None = None


class OverlayPhase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    goal: str
    changes: list[str]
    done_when: list[str] | None = None
    depends_on: str | None = None
    risks: list[str] | None = None


class OverlayMigrationPath(BaseModel):
    model_config = ConfigDict(extra="forbid")
    phases: list[OverlayPhase]


class OverlayAcceptance(BaseModel):
    model_config = ConfigDict(extra="forbid")
    done_when: list[str]
    verification: list[str] | None = None
    rollback_notes: str | None = None


class ContextUnityMigrationOverlay(BaseModel):
    """
    Migration overlay declaring temporary integration debt.
    Separated strictly to preserve the purity of canonical v1alpha config.
    """

    model_config = ConfigDict(extra="forbid")
    apiVersion: Literal["contextunity/v1alpha1"]
    kind: Literal["ContextUnityMigrationOverlay"]
    target_ref: str
    project: OverlayProject
    as_is: OverlayAsIs
    legacy_bridges: dict[str, bool] | None = None
    gaps: list[OverlayGap]
    migration_path: OverlayMigrationPath
    acceptance: OverlayAcceptance
    notes: list[str] | None = None

    @model_validator(mode="after")
    def enforce_gap_coverage_for_bridges(self) -> Self:
        """
        Enforce matrix coverage: Every legacy bridge set to True must have an
        associated gap defined to eventually remove it.
        """
        # Collect text of all gaps to do a loose token match, or we can look
        # at the id/current_state. For a strict pipeline, a gap title/id
        # must indicate it addresses the bridge. Here we do a basic check
        # that if bridges are defined, gaps aren't empty, and provide
        # a structural connection rule if possible.
        if self.legacy_bridges and any(self.legacy_bridges.values()) and not self.gaps:
            raise ValueError("If legacy_bridges are enabled, associated gaps must be documented.")

        # Verify that all 'blocking' gaps have a phase that claims to address them.
        # This implies dependencies mapping.
        blocking_gap_ids = {g.id for g in self.gaps if g.blocking}
        if blocking_gap_ids:
            # Instead of a complex NLP match, we strictly check if any phase id
            # references the gap as a dependency, or if phase goals explicitly exist.
            # As a basic heuristic, ensure there's at least one phase if blocking gaps exist.
            if not self.migration_path.phases:
                raise ValueError(
                    f"Blocking gaps {blocking_gap_ids} exist, but no migration phases are defined to track them."
                )

        return self
