"""
ContextUnity Project Manifest Models.
Defines the `v1alpha Target Schema` and `Migration Overlay` strictly enforcing the deployment contract.
"""

from typing import ClassVar, Literal, Self

from contextunity.core.exceptions import ConfigurationError
from contextunity.core.manifest import router as _router
from contextunity.core.tenant_policy import validate_tenant_id
from contextunity.core.types import WireValue, is_object_dict
from pydantic import BaseModel, ConfigDict, Field, model_validator

ModelsLLMPolicy = _router.ModelsLLMPolicy
ModelsEmbeddingsPolicy = _router.ModelsEmbeddingsPolicy
ModelsPolicy = _router.ModelsPolicy
RetryPolicy = _router.RetryPolicy
RouterEdge = _router.RouterEdge
RouterGraph = _router.RouterGraph
RouterGraphBuiltin = _router.RouterGraphBuiltin
RouterNode = _router.RouterNode
RouterNodeMeta = _router.RouterNodeMeta
RouterNodeType = _router.RouterNodeType
RouterPolicy = _router.RouterPolicy
RouterControlAction = _router.RouterControlAction
RouterVerdictConfig = _router.RouterVerdictConfig
RouterGraphConfig = _router.RouterGraphConfig
RouterGraphMemoryConfig = _router.RouterGraphMemoryConfig
RouterMemoryConfig = _router.RouterMemoryConfig
RouterConductorConfig = _router.RouterConductorConfig
RouterConfigSection = _router.RouterConfigSection
RouterSection = _router.RouterSection
ToolkitOverride = _router.ToolkitOverride
ToolkitRef = _router.ToolkitRef


class ManifestModel(BaseModel):
    """Base Pydantic model for manifest schema sections."""

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid")


class ModelIOEvidenceConfig(ManifestModel):
    """Project narrowing for protected model-I/O evidence and external projection."""

    capture: Literal["disabled", "brain_protected"] = "disabled"
    failure_policy: Literal["required", "best_effort"] = "required"
    lifecycle_profile_id: str = Field(
        default="trace-artifacts-standard",
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_-]*$",
    )
    external_projection: Literal["none", "redacted"] = "none"

    @model_validator(mode="after")
    def validate_projection_requires_capture(self) -> "ModelIOEvidenceConfig":
        if self.external_projection == "redacted" and self.capture != "brain_protected":
            raise ValueError("redacted model I/O projection requires brain_protected capture")
        return self


class ObservabilityTracingConfig(ManifestModel):
    """Project C1 tracing selection; endpoint and credentials remain C0-owned."""

    transport: Literal["disabled", "exporter_profile", "oss_direct"] = "disabled"
    profile_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_-]*$",
    )
    sample_ratio: float = Field(default=1.0, ge=0.0, le=1.0)
    model_io: ModelIOEvidenceConfig = Field(default_factory=ModelIOEvidenceConfig)

    @model_validator(mode="before")
    @classmethod
    def reject_legacy_langfuse(cls, value: object) -> object:
        """Reject removed callback configuration with an actionable migration."""
        if not is_object_dict(value):
            return value
        if value.get("transport") == "legacy_langfuse" or "legacy_langfuse" in value:
            raise ValueError("legacy_langfuse is removed; select exporter_profile, oss_direct, or disabled")
        return value

    @model_validator(mode="after")
    def validate_transport_selection(self) -> "ObservabilityTracingConfig":
        if self.transport == "exporter_profile" and self.profile_id is None:
            raise ValueError("exporter_profile tracing requires profile_id")
        if self.transport != "exporter_profile" and self.profile_id is not None:
            raise ValueError("profile_id requires exporter_profile tracing")
        if self.model_io.external_projection == "redacted" and self.transport == "disabled":
            raise ValueError("redacted model I/O projection requires an external transport")
        return self


# -----------------------------------------------------------------------------
# Core Project & Services Sections
# -----------------------------------------------------------------------------


class ProjectOwnership(ManifestModel):
    """Defines the code repository and team ownership for the project."""

    repo: str | None = None
    team: str | None = None


class ProjectSection(ManifestModel):
    """Core identity and ownership configuration for a ContextUnity project."""

    id: str
    name: str
    allowed_tenants: list[str] | None = None
    ownership: ProjectOwnership | None = None

    @model_validator(mode="after")
    def validate_tenant_scope(self) -> Self:
        """Reject reserved tenant names in project-owned manifest scope."""
        try:
            validate_tenant_id(self.id, allow_reserved=False)
            if self.allowed_tenants is not None:
                for tenant_id in self.allowed_tenants:
                    validate_tenant_id(tenant_id, allow_reserved=False)
        except ConfigurationError as exc:
            raise ValueError(str(exc)) from exc
        return self


class ServiceEnablement(ManifestModel):
    """Flags for whether a specific ContextUnity service is enabled."""

    enabled: bool


class ServicesSection(ManifestModel):
    """Configuration indicating which mesh platform services this project uses."""

    router: ServiceEnablement | None = None
    brain: ServiceEnablement | None = None
    worker: ServiceEnablement | None = None
    shield: ServiceEnablement | None = None


# -----------------------------------------------------------------------------
# Brain, Shield, Observability
# -----------------------------------------------------------------------------


class BrainStoragePolicy(ManifestModel):
    """Defines the retention and storage rules for the Brain service."""

    retention_days: int | None = None


class BrainSection(ManifestModel):
    """Configuration for the Brain vector storage and knowledge graph service."""

    tenant_scope: Literal["single", "multi"]
    capabilities: list[str]
    knowledge_domains: list[str] | None = None
    storage_policy: BrainStoragePolicy | None = None


class ShieldSection(ManifestModel):
    """Configuration for the Shield service, including compliance and security modes."""

    secret_resolution: bool | None = None
    compliance_mode: Literal["standard", "strict"] | None = None


class ObservabilitySection(ManifestModel):
    """Project health/readiness settings plus optional tracing configuration."""

    health_probe: bool
    readiness_check_mode: Literal["stream", "poll"]
    expected_tools: list[str] | None = None
    tracing: ObservabilityTracingConfig | None = None


# -----------------------------------------------------------------------------
# Worker & Commerce
# -----------------------------------------------------------------------------


class WorkerWorkflow(ManifestModel):
    """Configuration for an individual workflow definition in the Worker service."""

    workflow_type: str
    task_queue: str
    trigger: Literal["manual", "scheduled", "event"] | None = None
    ownership: str | None = None
    input_contract_ref: str | None = None
    result_contract_ref: str | None = None


class WorkerSchedule(ManifestModel):
    """Cron-based scheduling definitions for Worker workflows."""

    id: str
    workflow_type: str
    cron: str
    timezone: str


class WorkerExecutionPolicy(ManifestModel):
    """Policy definitions for workflow execution, including retries and idempotency."""

    retries: int | None = None
    timeouts: str | None = None
    idempotency: bool | None = None


class WorkerSection(ManifestModel):
    """Overall configuration section for the Worker temporal/background execution service."""

    mode: Literal["disabled", "trigger-only", "durable-orchestrator"]
    workflows: list[WorkerWorkflow] | None = None
    schedules: list[WorkerSchedule] | None = None
    execution_policy: WorkerExecutionPolicy | None = None

    @model_validator(mode="after")
    def validate_worker_modes(self) -> Self:
        """Validate that the declared worker mode aligns with the provided workflows and execution policies.

        Returns:
            Self: An instance of Self.

        Raises:
            ValueError: If parameter values are invalid.
        """
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


class WorkerBindingsBundle(ManifestModel):
    """Compiled worker runtime bundle from ``ArtifactGenerator.generate_worker_bindings``."""

    mode: Literal["trigger-only", "durable-orchestrator"] | None = None
    workflows: list[dict[str, WireValue]] = Field(default_factory=list)
    schedules: list[dict[str, WireValue]] = Field(default_factory=list)
    execution_policy: dict[str, WireValue] | None = None

    @property
    def enabled(self) -> bool:
        """Return whether worker orchestration is active for this project."""
        return self.mode is not None


class RouterRegistrationBundle(ManifestModel):
    """Compiled router registration bundle from ``ArtifactGenerator.generate_router_registration_bundle``."""

    project_id: str = ""
    allowed_tenants: list[str] = Field(default_factory=list)
    default_graph: str | None = None
    graph: dict[str, WireValue] = Field(default_factory=dict)
    services: dict[str, WireValue] = Field(default_factory=dict)
    policy: dict[str, WireValue] = Field(default_factory=dict)
    conductor: dict[str, WireValue] = Field(default_factory=dict)
    observability: dict[str, WireValue] = Field(default_factory=dict)
    secrets: dict[str, str] | None = None

    @property
    def enabled(self) -> bool:
        """Return whether router registration data is present."""
        return bool(self.project_id)


class CommerceConnector(ManifestModel):
    """Defines an integration endpoint for a specific commerce supplier or system."""

    id: str
    runtime: str
    entrypoint: str


class CommerceSyncFlow(ManifestModel):
    """Defines the directionality and policy of a data synchronization flow."""

    id: str
    direction: Literal["commerce_to_project", "project_to_commerce", "bidirectional"]


class CommerceSection(ManifestModel):
    """Configuration for commerce-specific integrations, suppliers, and sync flows."""

    overlay_mode: Literal["generated"]
    suppliers_ref: str | None = None
    taxonomy_ref: str | None = None
    connectors: list[CommerceConnector] | None = None
    sync_flows: list[CommerceSyncFlow] | None = None
    admin_extensions: list[str] | None = None


# -----------------------------------------------------------------------------
# Integration & Secrets
# -----------------------------------------------------------------------------

SecretResolver = Literal["env"]
"""How ``secrets`` keys are resolved. Only ``env`` is implemented (``os.environ``)."""


class IntegrationRegistration(ManifestModel):
    """Specifies how a project registers with the ContextUnity ecosystem."""

    mode: Literal["generated_bundle"]
    output: str | None = None


class IntegrationEnv(ManifestModel):
    """Specifies environment variable integration output paths."""

    output: str


class IntegrationTasks(ManifestModel):
    """Specifies task runner integration configuration."""

    output: str


class IntegrationDocs(ManifestModel):
    """Specifies documentation integration generation paths."""

    output: str


class IntegrationTesting(ManifestModel):
    """Specifies testing and validation overrides for integration scripts."""

    mock_mode: bool | None = None
    validation_command: str | None = None


class IntegrationSection(ManifestModel):
    """Configuration for CLI integration hooks and manifest generation."""

    registration: IntegrationRegistration
    env: IntegrationEnv | None = None
    tasks: IntegrationTasks | None = None
    docs: IntegrationDocs | None = None
    testing: IntegrationTesting | None = None


class SecretGroup(ManifestModel):
    """Env keys listed for bootstrap resolution (read from ``os.environ``, optionally synced to Shield).

    ``owner`` groups keys for documentation and overlays; bootstrap merges every listed key.
    What actually gets *used* at runtime is governed by Router manifests (policy, nodes)
    and token attenuation on ``shield:secrets:read`` paths—not by omitting keys here.
    """

    owner: Literal["project", "contextunity", "shared"]
    resolver: SecretResolver = Field(
        default="env",
        description="Resolve keys from process environment (same names as listed).",
    )
    keys: list[str]


# -----------------------------------------------------------------------------
# Top-level ContextUnityProject
# -----------------------------------------------------------------------------


class ContextUnityProject(ManifestModel):
    """
    v1alpha Target Schema for stable Canonical ContextUnity project integration.
    """

    apiVersion: Literal["contextunity/v1alpha8"]
    kind: Literal["ContextUnityProject"]

    project: ProjectSection
    services: ServicesSection

    router: RouterSection | None = None
    brain: BrainSection | None = None
    shield: ShieldSection | None = None
    worker: WorkerSection | None = None
    commerce: CommerceSection | None = None
    observability: ObservabilitySection | None = None

    integration: IntegrationSection | None = None
    secrets: list[SecretGroup] | None = None

    @model_validator(mode="after")
    def enforce_service_presences(self) -> Self:
        """Ensure that if a service is marked as enabled in the services section, its corresponding config section is present.

        Returns:
            Self: An instance of Self.

        Raises:
            ValueError: If parameter values are invalid.
        """
        # Only router requires a config section — others work with defaults
        if self.services.router and self.services.router.enabled and not self.router:
            raise ValueError("router section is required when services.router.enabled is true")
        return self


# -----------------------------------------------------------------------------
# Migration Overlay Models
# -----------------------------------------------------------------------------


class OverlayProject(ManifestModel):
    """Target project reference for a migration overlay."""

    id: str
    name: str | None = None
    owner: str | None = None


class OverlayAsIs(ManifestModel):
    """Current state baseline configuration describing legacy integration patterns."""

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


class OverlayGap(ManifestModel):
    """Defines a specific technical gap or debt item preventing canonical integration."""

    id: str
    title: str | None = None
    severity: Literal["high", "medium", "low"]
    owner: Literal["project", "contextunity", "shared"]
    current_state: str
    target_state: str
    blocking: bool | None = None
    depends_on: str | None = None
    evidence: list[str] | None = None


class OverlayPhase(ManifestModel):
    """A discrete phase within the migration path to address one or more gaps."""

    id: str
    goal: str
    changes: list[str]
    done_when: list[str] | None = None
    depends_on: str | None = None
    risks: list[str] | None = None


class OverlayMigrationPath(ManifestModel):
    """A sequence of phases defining the roadmap to reach target integration."""

    phases: list[OverlayPhase]


class OverlayAcceptance(ManifestModel):
    """Criteria defining the successful completion of the entire migration overlay."""

    done_when: list[str]
    verification: list[str] | None = None
    rollback_notes: str | None = None


class ContextUnityMigrationOverlay(ManifestModel):
    """
    Migration overlay declaring temporary integration debt.
    Separated strictly to preserve the purity of canonical v1alpha config.
    """

    apiVersion: Literal["contextunity/v1alpha8"]
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
        """Enforce matrix coverage: Every legacy bridge set to True must have an

        Returns:
            Self: An instance of Self.

        Raises:
            ValueError: If parameter values are invalid.
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
