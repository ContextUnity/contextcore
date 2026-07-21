"""ContextUnity SDK — Project Bootstrap Configuration.

Validated Pydantic config for project ↔ ContextUnity integration.
Single entry point for os.environ access — replaces scattered os.getenv() calls.

Service URLs are required based on what's enabled in the manifest:
  - manifest says shield: { enabled: true } → shield_url is required
  - manifest says brain: { enabled: true }  → brain_url is required

Model secret refs (model_secret_ref in manifest nodes) are resolved and
validated here — not in ArtifactGenerator.

Usage:

    from contextunity.core.sdk.config import ProjectBootstrapConfig

    # From environment (after .env is loaded):
    config = ProjectBootstrapConfig.from_env()

    # Or with explicit values:
    config = ProjectBootstrapConfig(
        project_id="my-project",
        router_url="localhost:50050",
    )
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from contextunity.core.manifest.models import ContextUnityProject
    from contextunity.core.signing import AuthBackend

from contextunity.core.config import get_env
from contextunity.core.logging import get_contextunit_logger
from pydantic import BaseModel, ConfigDict, Field

logger = get_contextunit_logger(__name__)


# Service → (canonical_env_var, default_url)
# Canonical: CU_ROUTER_GRPC_URL, CU_BRAIN_GRPC_URL, etc. (uniform *_GRPC_URL suffix)
_SERVICE_ENV: dict[str, tuple[str, str]] = {
    "router": ("CU_ROUTER_GRPC_URL", "localhost:50050"),
    "brain": ("CU_BRAIN_GRPC_URL", "localhost:50051"),
    "worker": ("CU_WORKER_GRPC_URL", "localhost:50052"),
    "shield": ("CU_SHIELD_GRPC_URL", ""),
}


class ProjectBootstrapConfig(BaseModel):
    """Validated configuration for SDK bootstrap.

    Contains everything register_and_start() needs:
    - Project identity
    - Service URLs (with defaults)

    Projects can subclass to add project-specific required env vars.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore")

    # ── Project identity ──
    project_id: str = Field(
        default="",
        description="Project identifier (populated automatically from manifest during bootstrap).",
    )

    # ── Manifest ──
    manifest_path: str = Field(
        default="contextunity.project.yaml",
        description="Path to project manifest (relative or absolute)",
    )

    # ── Service URLs ──
    # Required when corresponding service is enabled in manifest.
    # Defaults are localhost dev ports.
    router_url: str = Field(default="", description="contextunity.router gRPC URL")
    brain_url: str = Field(default="", description="contextunity.brain gRPC URL")
    worker_url: str = Field(default="", description="contextunity.worker gRPC URL")
    shield_url: str = Field(default="", description="contextunity.shield gRPC URL")

    # Mandatory closed ToolExecutorStream protocol bounds (project-side C0).
    delivery_resume_window_seconds: int = Field(default=300, ge=1, le=86_400)
    delivery_max_cache_entries: int = Field(default=1024, ge=1, le=100_000)
    delivery_max_message_bytes: int = Field(default=256 * 1024, ge=1024, le=4 * 1024 * 1024)

    def get_auth_backend(self, shield_enabled: bool = False) -> AuthBackend:
        """Get the authentication backend based on config.

        Enterprise mode (Shield Session Tokens) is activated ONLY when
        shield_enabled=True — controlled by the project manifest.
        Having CU_SHIELD_GRPC_URL in env is just a connection detail.

        Args:
            shield_enabled: Whether to enable Shield-based authentication.

        Returns:
            AuthBackend: The resolved authentication backend.
        """
        from contextunity.core.signing import get_signing_backend

        return get_signing_backend(
            project_id=self.project_id,
            shield_url=self.shield_url,
            shield_enabled=shield_enabled,
        )

    @classmethod
    def from_env(cls, **overrides: str) -> ProjectBootstrapConfig:
        """Load config from os.environ with optional overrides.

        Reads standard ContextUnity env vars and fills in defaults.
        Call this AFTER .env is loaded (by Django, dotenv, infrastructure, etc.).

        Args:
            **overrides: Explicit values that take precedence over env.

        Returns:
            ProjectBootstrapConfig: Validated ProjectBootstrapConfig instance.

        Raises:
            ConfigurationError: If the bootstrap configuration is invalid.
        """
        env_values: dict[str, str] = {}

        # Manifest path
        manifest = get_env("CU_MANIFEST_PATH", "")
        if manifest:
            env_values["manifest_path"] = manifest

        # Service URLs: env var → default
        for service, (env_var, default) in _SERVICE_ENV.items():
            field = f"{service}_url"
            url = get_env(env_var, "")
            env_values[field] = url or default

        delivery_env = {
            "delivery_resume_window_seconds": get_env("CU_FEDERATED_DELIVERY_RESUME_WINDOW_SECONDS", ""),
            "delivery_max_cache_entries": get_env("CU_FEDERATED_DELIVERY_MAX_CACHE_ENTRIES", ""),
            "delivery_max_message_bytes": get_env("CU_FEDERATED_DELIVERY_MAX_MESSAGE_BYTES", ""),
        }
        for field, value in delivery_env.items():
            if value:
                env_values[field] = value

        # Apply overrides last (explicit > env > defaults)
        env_values.update(overrides)

        try:
            return cls.model_validate(env_values)
        except Exception as e:
            from contextunity.core.exceptions import ConfigurationError

            raise ConfigurationError(f"Bootstrap config invalid: {str(e)}") from e

    def resolve_secrets(self, manifest: ContextUnityProject) -> dict[str, str]:
        """Resolve API key secrets from manifest into Shield path suffixes.

        Path convention:
          - Top-level (``manifest.secrets``):                         ``{env_var_name}``
                - Per-node (``model_secret_ref``):                         ``{node_name}/model_secret_ref``
          - Default model (policy):                                   ``{provider}/{model}``
          - Fallback models (policy):                                 ``{provider}/{model}``

        Bootstrap may sync listed values to Shield; runtime use is still gated by
        ``ContextToken`` scopes and path attenuation.

        Note:
          Per-node secrets are keyed only by ``node_name`` today because Router's
          secure-node runtime expects ``{tenant}/api_keys/{node_name}/model_secret_ref``.
          If multiple graphs reuse the same node name, the later secret wins and we log it.

        Args:
            manifest: The loaded ContextUnityProject manifest.

        Returns:
            dict[str, str]: A dictionary mapping path suffixes (appended to
                ``{tenant}/api_keys/`` to form the full Shield storage path)
                to their resolved API key values.
        """
        secrets: dict[str, str] = {}
        missing: list[str] = []

        # 1. Top-level manifest secrets (env resolver) → Shield path suffix = env var name
        if manifest.secrets:
            for group in manifest.secrets:
                if group.resolver != "env":
                    continue
                for key in group.keys:
                    value = get_env(key, "")
                    if not value:
                        missing.append(f"{key} (group {group.owner})")
                    else:
                        secrets[key] = value

        if manifest.router:
            # 2. Per-node secrets: path = {node_name}/model_secret_ref
            #    router.graph is dict[str, RouterGraph] — iterate all graphs
            if manifest.router.graph:
                for graph_name, graph_def in manifest.router.graph.items():
                    if not graph_def.nodes:
                        continue
                    for node in graph_def.nodes:
                        secret_ref = getattr(node, "model_secret_ref", None)
                        if not isinstance(secret_ref, str) or not secret_ref:
                            continue
                        value = get_env(secret_ref, "")
                        if not value:
                            missing.append(f"{secret_ref} (graph={graph_name}, node={node.name})")
                        else:
                            key = f"{node.name}/model_secret_ref"
                            previous = secrets.get(key)
                            if previous and previous != value:
                                logger.warning(
                                    "Per-node secret collision at %s; graph=%s node=%s overrides earlier value",
                                    key,
                                    graph_name,
                                    node.name,
                                )
                            secrets[key] = value

            # 3. Default model secret: path = {provider}/{model} (= models.llm.default)
            policy = manifest.router.policy
            models_pol = policy.models if policy else None
            llm = models_pol.llm if models_pol else None
            if llm and llm.secret_ref:
                value = get_env(llm.secret_ref, "")
                if not value:
                    missing.append(f"{llm.secret_ref} (policy default)")
                else:
                    secrets[llm.default] = value

            # 4. Fallback model secrets: path = {provider}/{model} (= models.llm.fallback[i])
            if llm and llm.fallback and llm.fallback_secret_refs:
                for model, ref in zip(llm.fallback, llm.fallback_secret_refs):
                    value = get_env(ref, "")
                    if not value:
                        missing.append(f"{ref} (fallback {model})")
                    else:
                        secrets[model] = value

        if missing:
            logger.warning(
                "Missing %d secret env var(s): %s",
                len(missing),
                "; ".join(missing),
            )

        return secrets

    def validate_service_urls(self, manifest: ContextUnityProject) -> None:
        """Validate that URLs are set for all services enabled in manifest.

        Call this after loading the manifest to get actionable error messages.

        Args:
            manifest: The loaded ContextUnityProject manifest.

        Raises:
            ConfigurationError: If any enabled service is missing its URL configuration.
        """
        if not manifest.services:
            return

        missing: list[str] = []
        services = manifest.services

        url_map = {
            "router": self.router_url,
            "brain": self.brain_url,
            "worker": self.worker_url,
            "shield": self.shield_url,
        }
        service_flags = {
            "router": services.router,
            "brain": services.brain,
            "worker": services.worker,
            "shield": services.shield,
        }

        for service_name, url_value in url_map.items():
            svc = service_flags.get(service_name)
            if svc is not None and svc.enabled and not url_value:
                env_var = _SERVICE_ENV.get(service_name, ("", ""))[0]
                missing.append(f"{service_name} (set {env_var})")

        if missing:
            from contextunity.core.exceptions import ConfigurationError

            raise ConfigurationError(
                message="Services enabled in manifest but missing URL config: " + ", ".join(missing),
                code="MISSING_SERVICE_URL",
            )


__all__ = ["ProjectBootstrapConfig"]
