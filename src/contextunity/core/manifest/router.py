"""Router section models for ContextUnity project manifests."""

from __future__ import annotations

from typing import ClassVar, Literal, Self

from contextunity.core.types import JsonDict, is_json_value, is_object_dict
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator, model_validator


class RouterManifestModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid")


class RouterStrictModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", strict=True)


def _validate_provider_qualified(value: str) -> str:
    """Ensure AI model names are provider-qualified.

    Args:
        value (str): The value to store or update.

    Returns:
        str: The resulting string value.

    Raises:
        ValueError: If parameter values are invalid.
    """
    from contextunity.core.model_reference import validate_model_reference

    return validate_model_reference(value, field_name="AI model")


class ToolkitOverride(RouterManifestModel):
    """Per-tool config override within a toolkit reference."""

    timeout: int | None = Field(None, ge=1, le=300, description="Tool timeout in seconds")
    retries: int | None = Field(None, ge=0, le=10, description="Max retry attempts")
    retry_policy: Literal["exponential", "linear", "none"] | None = None


class ToolkitRef(RouterManifestModel):
    """Reference to a FederatedToolkit class with optional overrides."""

    name: str = Field(..., min_length=1, max_length=128)
    exclude: list[str] | None = None
    overrides: dict[str, ToolkitOverride] | None = None


class RouterNodeMeta(RouterStrictModel):
    """Optional resolver metadata for tool-bound nodes."""

    handler: str | None = Field(
        default=None,
        min_length=1,
        max_length=512,
        description="Resolved handler identifier/path used for tool dispatch.",
    )
    source: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        description="Resolver source identifier (e.g. toolkit, registry).",
    )
    toolkit: str | None = Field(
        default=None,
        min_length=1,
        max_length=256,
        description="Toolkit class or logical toolkit identifier for federated tools.",
    )


RouterNodeType = Literal["llm", "embeddings", "agent", "tool"]
RouterNodeMode = Literal["default", "sql_visualizer", "parallel"]
RouterGraphBuiltin = Literal["dispatcher"]


class RouterNode(RouterManifestModel):
    """Configuration for an individual node within a Router graph."""

    name: str
    type: RouterNodeType | None = None
    model: str | None = None
    goal: str | None = Field(
        default=None,
        min_length=1,
        description="Node-level agent goal. Overrides graph.goal for agent nodes.",
    )
    persona: str | None = Field(
        default=None,
        min_length=1,
        description="Node-level LLM persona. Overrides graph.persona for LLM nodes.",
    )
    model_secret_ref: str | None = None
    prompt_ref: str | None = None
    prompt_variants_ref: str | None = None
    prompt_signature: str | None = None
    prompt_version: str | None = None
    prompt_variants_versions: dict[str, str] | None = None
    pii_masking: bool | None = None
    mode: RouterNodeMode | None = Field(
        default=None,
        description=(
            "Execution mode for LLM nodes. "
            "'sql_visualizer': SQL-specific visualization with parallel sub-prompts. "
            "'parallel': generic parallel sub-prompt execution (reserved)."
        ),
    )
    tool_binding: str | list[str] | None = None
    tools: list[str] | None = Field(
        None,
        description=(
            "Tool references available to this node. Explicit namespaces are required: "
            "'platform:my_tool' (platform tool), "
            "'federated:my_tool' (project-registered tool, resolved via manifest mapping)."
        ),
    )
    toolkits: list[str | ToolkitRef] | None = None
    meta: RouterNodeMeta | None = None
    config: dict[str, object] | None = None
    description: str | None = None
    allowed_tenants: list[str] | None = Field(
        default=None,
        description="Optional tenant scope override for this node (must be ⊆ graph/project scope).",
    )

    @field_validator("tool_binding", mode="before")
    @classmethod
    def validate_tool_binding(cls, v: str | list[str] | None) -> str | list[str] | None:
        """Validate tool_binding format.

        Args:
            v (str | list[str] | None): The v parameter.

        Returns:
            str | list[str] | None: A list of str | list[str] | None.

        Raises:
            ValueError: If parameter values are invalid.
        """
        if v is None:
            return v
        from contextunity.core.manifest.helpers import TOOL_BINDING_RE

        values = v if isinstance(v, list) else [v]
        for ref in values:
            if not TOOL_BINDING_RE.match(ref.strip()):
                raise ValueError(
                    "Invalid tool_binding "
                    + f"'{ref}'. Expected '<platform_tool>', "
                    + "'platform:<tool_name>', or 'federated:<tool_name>'."
                )
        return v

    @field_validator("tools", mode="before")
    @classmethod
    def validate_tool_refs(cls, v: list[str] | None) -> list[str] | None:
        """Validate tool ref format: required namespace prefix + identifier.

        Args:
            v (list[str] | None): The v parameter.

        Returns:
            list[str] | None: A list of list[str] | None.

        Raises:
            ValueError: If parameter values are invalid.
        """
        if v is None:
            return v
        from contextunity.core.manifest.helpers import TOOL_REF_RE

        for ref in v:
            if not TOOL_REF_RE.match(ref):
                raise ValueError(f"Invalid tool ref '{ref}'. Expected format: [platform:|federated:]<snake_case_name>")
        return v

    @model_validator(mode="after")
    def infer_node_type(self) -> Self:
        """Infer node type when omitted in manifest for better DX.

        Returns:
            Self: An instance of Self.
        """
        if self.type is not None:
            return self
        if self.tool_binding:
            self.type = "tool"
            return self
        self.type = "llm"
        return self


class RouterEdge(RouterManifestModel):
    """Configuration for a routing edge between nodes in a Router graph."""

    from_node: str
    to_node: str | None = None
    condition_key: str | None = None
    condition_map: dict[str, str] | None = None

    @model_validator(mode="after")
    def validate_edge(self) -> Self:
        """Validate that the edge has a valid destination or condition.

        Returns:
            Self: An instance of Self.

        Raises:
            ValueError: If parameter values are invalid.
        """
        if not self.to_node and not self.condition_key:
            raise ValueError(
                "Edge must specify either 'to_node' (for static routing) or 'condition_key' (for dynamic routing)"
            )
        if self.condition_key and not self.condition_map:
            raise ValueError("Edge specifying 'condition_key' must also provide a 'condition_map' dict")
        return self


class RouterGraph(RouterManifestModel):
    """Configuration for a complete Router execution graph."""

    _federated_tool_map: dict[str, str] = PrivateAttr(default_factory=dict)

    id: str | None = None
    goal: str | None = Field(
        default=None,
        min_length=1,
        description="Graph-wide default goal for agent nodes.",
    )
    persona: str | None = Field(
        default=None,
        min_length=1,
        description="Graph-wide default persona for LLM nodes.",
    )
    template: str | None = Field(
        None,
        min_length=1,
        max_length=128,
        description="YAML template source, e.g. yaml:retrieval_augmented.",
    )
    builtin: RouterGraphBuiltin | None = Field(
        None,
        description="Platform-owned graph source, e.g. dispatcher.",
    )
    overrides: dict[str, dict[str, object]] | None = Field(
        None,
        description="Per-node override map for yaml templates. Keys must reference template nodes.",
    )
    nodes: list[RouterNode] | None = None
    edges: list[RouterEdge] | None = None
    config_ref: str | None = None
    config: RouterGraphConfig | None = None
    runtime: JsonDict | None = Field(
        default=None,
        description=(
            "Opaque graph/template executor keys (wire JSON only). Kept separate "
            "from typed ``config``; ArtifactGenerator must not fold these into config."
        ),
    )
    toolkits: list[str | ToolkitRef] | None = Field(
        None, description="List of Toolkit class names attached to this graph"
    )
    router_callbacks: list[str] | None = Field(
        None, description="List of nodes allowed to be executed externally via ExecuteNode RPC"
    )
    allowed_tenants: list[str] | None = Field(
        default=None,
        description="Optional tenant scope override for this graph (must be ⊆ project scope).",
    )

    def set_federated_tool_map(self, tool_map: dict[str, str]) -> None:
        """Store bootstrap-resolved tool names without exposing a manifest field."""
        self._federated_tool_map = dict(tool_map)

    @property
    def federated_tool_map(self) -> dict[str, str]:
        """Return bootstrap-resolved tool names for registration projection only."""
        return dict(self._federated_tool_map)

    @field_validator("runtime", mode="before")
    @classmethod
    def _runtime_must_be_json_object(cls, value: object) -> object:
        """Reject non-wire values in the opaque runtime bag (JSON object only)."""
        if value is None:
            return value
        if not is_object_dict(value):
            raise ValueError("router.graph.*.runtime must be a JSON object")
        for key, item in value.items():
            if not is_json_value(item):
                raise ValueError(f"router.graph.*.runtime[{key!r}] must be a JSON-serializable value")
        return value

    @model_validator(mode="after")
    def validate_graph(self) -> Self:
        """Validate the structural shape and source configuration of the graph.

        Returns:
            Self: An instance of Self.
        """
        from contextunity.core.manifest.helpers import validate_graph_source_shape

        validate_graph_source_shape(
            has_inline=self.nodes is not None or self.edges is not None,
            has_template=self.template is not None,
            has_builtin=self.builtin is not None,
            template=self.template,
            overrides=self.overrides,
            nodes=self.nodes,
            edges=self.edges,
            label="router.graph",
        )
        return self


# ---- Retry Policy ----

RetryTrigger = Literal["rate_limit", "timeout", "network", "response_format"]
"""Error categories eligible for retry.

- ``rate_limit``  — ``ModelRateLimitError`` (429 from provider)
- ``timeout``     — ``ModelTimeoutError``
- ``network``     — ``ConnectionError``, 5xx from provider
- ``response_format`` — ``ModelResponseFormatError`` (invalid JSON etc.)
"""

_DEFAULT_RETRY_TRIGGERS: list[RetryTrigger] = ["rate_limit", "timeout", "network"]


class RetryPolicy(RouterManifestModel):
    """Retry policy for model generation.

    Controls how many times and how long a single model candidate
    is retried before handing off to the next fallback candidate.

    Example YAML::

        retry:
          max_attempts: 3
          backoff: exponential
          retry_on: [rate_limit, timeout, network, response_format]
          timeout_sec: 30
    """

    max_attempts: int = Field(
        default=2,
        ge=1,
        le=10,
        description="Total attempts including the first call (1 = no retry).",
    )
    backoff: Literal["none", "fixed", "exponential"] = Field(
        default="exponential",
        description="Delay strategy between retry attempts.",
    )
    base_delay_ms: int = Field(
        default=500,
        ge=0,
        le=30000,
        description="Initial delay in milliseconds (for fixed/exponential).",
    )
    max_delay_ms: int = Field(
        default=8000,
        ge=0,
        le=60000,
        description="Cap on backoff delay (exponential only).",
    )
    retry_on: list[RetryTrigger] = Field(
        default_factory=lambda: list(_DEFAULT_RETRY_TRIGGERS),
        description="Error categories that trigger a retry.",
    )
    timeout_sec: float = Field(
        default=30.0,
        ge=1.0,
        le=300.0,
        description="Hard time limit for all retry attempts of a single candidate.",
    )

    @model_validator(mode="after")
    def validate_delay_bounds(self) -> Self:
        """Ensure max_delay_ms is greater than or equal to base_delay_ms.

        Returns:
            Self: An instance of Self.

        Raises:
            ValueError: If parameter values are invalid.
        """
        if self.max_delay_ms < self.base_delay_ms:
            raise ValueError(f"max_delay_ms ({self.max_delay_ms}) must be >= base_delay_ms ({self.base_delay_ms})")
        return self


class ModelsLLMPolicy(RouterManifestModel):
    """LLM model selection policy."""

    default: str
    pinned_model: str | None = Field(
        default=None,
        min_length=1,
        description=(
            "Explicit RouterConductor catalog model pin. It remains authoritative "
            "unless catalog policy, context, or budget rejects it."
        ),
    )
    secret_ref: str | None = None
    fallback: list[str] | None = None
    fallback_secret_refs: list[str] | None = None
    retry: RetryPolicy | None = None

    @field_validator("default", mode="after")
    @classmethod
    def val_default(cls, value: str) -> str:
        """Validate that the default model is provider-qualified.

        Args:
            value (str): The value to store or update.

        Returns:
            str: The resulting string value.
        """
        return _validate_provider_qualified(value)

    @field_validator("pinned_model", mode="after")
    @classmethod
    def val_pinned_model(cls, value: str | None) -> str | None:
        """Require an executable catalog/model-registry key for explicit pins."""
        return _validate_provider_qualified(value) if value is not None else None

    @field_validator("fallback", mode="after")
    @classmethod
    def val_fallback(cls, value: list[str] | None) -> list[str] | None:
        """Validate that all fallback models are provider-qualified.

        Args:
            value (list[str] | None): The value to store or update.

        Returns:
            list[str] | None: A list of list[str] | None.
        """
        if value:
            for item in value:
                _ = _validate_provider_qualified(item)
        return value

    @model_validator(mode="after")
    def validate_fallback_refs_length(self) -> Self:
        """Ensure fallback and fallback_secret_refs have the same length if both are provided.

        Returns:
            Self: An instance of Self.

        Raises:
            ValueError: If parameter values are invalid.
        """
        if self.fallback and self.fallback_secret_refs:
            if len(self.fallback) != len(self.fallback_secret_refs):
                raise ValueError(
                    "fallback "
                    + f"({len(self.fallback)}) and fallback_secret_refs "
                    + f"({len(self.fallback_secret_refs)}) must have equal length"
                )
        return self


class ModelsEmbeddingsPolicy(RouterManifestModel):
    """Embeddings model selection policy."""

    default: str
    secret_ref: str | None = None
    retry: RetryPolicy | None = None

    @field_validator("default", mode="after")
    @classmethod
    def val_default(cls, value: str) -> str:
        """Validate that the default embeddings model is provider-qualified.

        Args:
            value (str): The value to store or update.

        Returns:
            str: The resulting string value.
        """
        return _validate_provider_qualified(value)


class ModelsPolicy(RouterManifestModel):
    """Per-type model selection policy.

    Groups model configuration by type (``llm``, ``embeddings``)
    with node-level cost budget and global retry defaults.

    Example YAML::

        models:
          budget_usd: 0.50        # Per-node cost cap (hard stop)
          retry:                  # Global defaults for all model types
            max_attempts: 2
            backoff: exponential
          llm:
            default: openai/gpt-5-mini
            fallback: [vertex/gemini-2.5-flash]
            retry:                # Per-type override (extends global)
              retry_on: [rate_limit, timeout, network, response_format]
          embeddings:
            default: vertex/text-embedding-005
    """

    budget_usd: float | None = Field(
        default=None,
        ge=0.0,
        description=(
            "Per-node cost cap in USD.  Cumulative total_cost is tracked "
            "across ALL model candidates (primary + fallbacks + retries).  "
            "When exceeded, generation stops completely with "
            "ModelBudgetExceededError — no further fallback is attempted."
        ),
    )
    retry: RetryPolicy | None = None
    llm: ModelsLLMPolicy
    embeddings: ModelsEmbeddingsPolicy | None = None


class RouterLangfusePolicy(RouterManifestModel):
    """Langfuse observability toggle and secret refs."""

    tracing_enabled: bool | None = None
    public_key_ref: str | None = None
    secret_key_ref: str | None = None
    host_ref: str | None = None


class RouterPolicy(RouterManifestModel):
    """Global execution policies for the Router, including allowed tools and model selection."""

    allowed_tools: list[str] | None = None
    models_ref: str | None = None
    models: ModelsPolicy | None = None
    prompts_ref: str | None = None
    langfuse: RouterLangfusePolicy | None = None

    @model_validator(mode="after")
    def check_models_policy_mutually_exclusive(self) -> Self:
        """Ensure only one of models_ref or models is specified.

        Returns:
            Self: An instance of Self.

        Raises:
            ValueError: If parameter values are invalid.
        """
        if self.models_ref and self.models:
            raise ValueError("models_ref and models are mutually exclusive")
        if not self.models_ref and not self.models:
            raise ValueError("One of models_ref or models is required")
        return self


class RouterSynapseLookupConfig(RouterManifestModel):
    """Per-project or per-graph BrainSynapse lookup gate (``config.memory.synapse_lookup``)."""

    enabled: bool | None = None


class RouterAutoExtractGraphCompletionConfig(RouterManifestModel):
    """Graph-completion auto-extract overrides."""

    enabled: bool | None = None
    hash_dedup: bool | None = None


class RouterAutoExtractUserMessageConfig(RouterManifestModel):
    """User-message auto-extract overrides."""

    enabled: bool | None = None
    cooldown_seconds: int | None = Field(default=None, ge=0)


class RouterAutoExtractConfig(RouterManifestModel):
    """``router.config.memory.auto_extract`` / graph override block (v1alpha8)."""

    enabled: bool | None = None
    graph_completion: RouterAutoExtractGraphCompletionConfig | None = None
    user_message: RouterAutoExtractUserMessageConfig | None = None
    min_messages: int | None = Field(default=None, ge=1)
    max_facts_per_extraction: int | None = Field(default=None, ge=1, le=50)
    max_cost_usd: float | None = Field(default=None, gt=0)
    confidence_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    extraction_model: str | None = None

    @field_validator("extraction_model")
    @classmethod
    def _validate_extraction_model(cls, value: str | None) -> str | None:
        if value is None:
            return None
        from contextunity.core.model_reference import validate_model_reference

        return validate_model_reference(value, field_name="auto_extract.extraction_model")


class RouterMemoryConfig(RouterManifestModel):
    """``router.config.memory`` — public v1alpha8 memory domain (Phase 3).

    Canonical keys only: ``inject``, ``depth``, ``synapse_*``, ``auto_extract``.
    No ``pipeline.*`` fields.
    """

    inject: bool = False
    depth: Literal["shallow", "standard", "deep", "research"] = "standard"
    scope_path: str | None = None
    synapse_min_q: float | None = Field(default=None, ge=0.0, le=1.0)
    synapse_node_role: str | None = None
    synapse_action_type: str | None = None
    synapse_scope_path: str | None = None
    synapse_lookup: RouterSynapseLookupConfig | None = None
    auto_extract: RouterAutoExtractConfig | None = None


class RouterGraphMemoryConfig(RouterManifestModel):
    """Partial graph-level ``router.graph.*.config.memory`` override (v1alpha8)."""

    inject: bool | None = None
    depth: Literal["shallow", "standard", "deep", "research"] | None = None
    scope_path: str | None = None
    synapse_min_q: float | None = Field(default=None, ge=0.0, le=1.0)
    synapse_node_role: str | None = None
    synapse_action_type: str | None = None
    synapse_scope_path: str | None = None
    synapse_lookup: RouterSynapseLookupConfig | None = None
    auto_extract: RouterAutoExtractConfig | None = None


class RouterGraphConfig(RouterManifestModel):
    """Typed graph ``config`` block; opaque executor keys belong in ``runtime``.

    Registry scope: ``router.graph.*.config.memory`` is Phase 3 M04;
    ``router.graph.*.config.policy`` is Phase 8+; no graph-level conductor
    block is registered for v1alpha8 (M05 owns project-level
    ``router.config.conductor`` only).
    """

    memory: RouterGraphMemoryConfig | None = None


class RouterConductorConfig(RouterManifestModel):
    """``router.config.conductor`` — cost-aware model selection (Phase 3 M05).

    Explicit model pins stay under ``router.config.policy.models``; this block
    owns CheapestViable gates, budget/quality floors, and token estimates.
    Catalog path is **L0-only** (``router.yml`` / ``CU_ROUTER_CONDUCTOR_MODELS_CATALOG_PATH``);
    it must not appear on project manifests (``extra=forbid`` rejects it).
    Phase 5 may extend with Engram/Dream signals without moving pins here.
    """

    cost_aware_enabled: bool = False
    quality_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    max_cost_usd: float | None = Field(default=None, gt=0)
    default_safe_model: str | None = None
    input_tokens_estimate: int = Field(default=500, ge=1)
    output_tokens_estimate: int = Field(default=200, ge=1)

    @field_validator("default_safe_model", mode="after")
    @classmethod
    def val_default_safe_model(cls, value: str | None) -> str | None:
        """Require an executable catalog/model-registry key for the safe model."""
        return _validate_provider_qualified(value) if value is not None else None


class RouterConfigSection(RouterManifestModel):
    """Typed ``router.config`` block (v1alpha8): policy + memory + conductor."""

    policy: RouterPolicy
    memory: RouterMemoryConfig | None = None
    conductor: RouterConductorConfig | None = None


class RouterSection(RouterManifestModel):
    """The root configuration section for the Router service (v1alpha8).

    Public shape::

        router:
          config:
            policy: { ... }
            memory: { inject: false, depth: standard }
            conductor: { cost_aware_enabled: false }
          graph: { ... }
    """

    default_graph: str | None = None
    toolkits: list[str | ToolkitRef] | None = Field(
        None, description="Global Toolkit class names attached to all graphs"
    )
    graph: dict[str, RouterGraph]
    config: RouterConfigSection

    @property
    def policy(self) -> RouterPolicy:
        """Convenience accessor for ``config.policy`` (generators / runtime)."""
        return self.config.policy

    @model_validator(mode="after")
    def auto_populate_graph_ids(self) -> Self:
        """Auto-set RouterGraph.id from its map key if omitted.

        Returns:
            Self: An instance of Self.
        """
        for key, graph in self.graph.items():
            if graph.id is None:
                self.graph[key] = graph.model_copy(update={"id": key})
        return self
