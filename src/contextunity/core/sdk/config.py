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

import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from contextunity.core.manifest.models import ContextUnityProject
    from contextunity.core.signing import AuthBackend

from contextunity.core.logging import get_contextunit_logger
from pydantic import BaseModel, Field

logger = get_contextunit_logger(__name__)


# Service → (canonical_env_var, default_url)
# Canonical: CU_ROUTER_GRPC_URL, CU_BRAIN_GRPC_URL, etc. (uniform *_GRPC_URL suffix)
_SERVICE_ENV: dict[str, tuple[str, str]] = {
    "router": ("CU_ROUTER_GRPC_URL", "localhost:50051"),
    "brain": ("CU_BRAIN_GRPC_URL", "localhost:50052"),
    "worker": ("CU_WORKER_GRPC_URL", "localhost:50053"),
    "shield": ("CU_SHIELD_GRPC_URL", "localhost:50054"),
    "zero": ("CU_ZERO_GRPC_URL", "localhost:50055"),
    "commerce": ("CU_COMMERCE_GRPC_URL", "localhost:50056"),
}


class ProjectBootstrapConfig(BaseModel):
    """Validated configuration for SDK bootstrap.

    Contains everything register_and_start() needs:
    - Project identity
    - Service URLs (with defaults)

    Projects can subclass to add project-specific required env vars.
    """

    model_config = {"extra": "ignore"}

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
    zero_url: str = Field(default="", description="contextunity.zero gRPC URL")
    commerce_url: str = Field(default="", description="contextunity.commerce gRPC URL")

    def get_auth_backend(self, shield_enabled: bool = True) -> AuthBackend:
        """Get the authentication backend based on config.

        Uses Shield if shield_url is set AND shield_enabled is True.
        Otherwise falls back to HMAC.
        project_id comes from manifest (via this config), CU_PROJECT_SECRET from env.
        """
        from contextunity.core.signing import get_signing_backend

        return get_signing_backend(
            project_id=self.project_id,
            shield_url=self.shield_url if shield_enabled else "",
        )

    @classmethod
    def from_env(cls, **overrides: Any) -> ProjectBootstrapConfig:
        """Load config from os.environ with optional overrides.

        Reads standard ContextUnity env vars and fills in defaults.
        Call this AFTER .env is loaded (by Django, dotenv, infrastructure, etc.).

        Args:
            **overrides: Explicit values that take precedence over env.

        Returns:
            Validated ProjectBootstrapConfig instance.
        """
        env_values: dict[str, Any] = {}

        # Manifest path
        manifest = os.environ.get("CU_MANIFEST_PATH", "")
        if manifest:
            env_values["manifest_path"] = manifest

        # Service URLs: env var → default
        for service, (env_var, default) in _SERVICE_ENV.items():
            field = f"{service}_url"
            url = os.environ.get(env_var, "")
            env_values[field] = url or default

        # Apply overrides last (explicit > env > defaults)
        env_values.update(overrides)

        try:
            return cls(**env_values)
        except Exception as e:
            from contextunity.core.exceptions import ConfigurationError

            raise ConfigurationError(f"Bootstrap config invalid: {str(e)}") from e

    def resolve_secrets(self, manifest: "ContextUnityProject") -> dict[str, str]:
        """Resolve API key secrets from manifest into Shield path suffixes.

        Returns ``{path_suffix: api_key}`` where path_suffix is appended to
        ``{tenant}/api_keys/`` to form the full Shield storage path.

        Path convention:
          - Per-node (has ``model_secret_ref``):  ``{node_name}/{env_var_name}``
          - Default model (policy):               ``{provider}/{model}`` (= model key)
          - Fallback models (policy):             ``{provider}/{model}`` (= model key)
        """
        if not manifest.router or not manifest.router.graph.nodes:
            return {}

        secrets: dict[str, str] = {}
        missing: list[str] = []

        # 1. Per-node secrets: path = {node_name}/model_secret_ref
        for node in manifest.router.graph.nodes:
            if not node.model_secret_ref:
                continue
            value = os.environ.get(node.model_secret_ref, "")
            if not value:
                missing.append(f"{node.model_secret_ref} (node={node.name})")
            else:
                secrets[f"{node.name}/model_secret_ref"] = value

        # 2. Default model secret: path = {provider}/{model} (= default_ai_model)
        policy = manifest.router.policy
        ai = policy.ai_model_policy if policy else None
        if ai and ai.default_model_secret_ref:
            value = os.environ.get(ai.default_model_secret_ref, "")
            if not value:
                missing.append(f"{ai.default_model_secret_ref} (policy default)")
            else:
                secrets[ai.default_ai_model] = value

        # 3. Fallback model secrets: path = {provider}/{model} (= fallback_ai_models[i])
        if ai and ai.fallback_ai_models and ai.fallback_model_secret_refs:
            for model, ref in zip(ai.fallback_ai_models, ai.fallback_model_secret_refs):
                value = os.environ.get(ref, "")
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

    def validate_service_urls(self, manifest: "ContextUnityProject") -> None:
        """Validate that URLs are set for all services enabled in manifest.

        Call this after loading the manifest to get actionable error messages.

        Raises:
            ValueError with list of missing URLs.
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
            "zero": self.zero_url,
            "commerce": self.commerce_url,
        }

        for service_name, url_value in url_map.items():
            svc = getattr(services, service_name, None)
            if svc and getattr(svc, "enabled", False) and not url_value:
                env_var = _SERVICE_ENV.get(service_name, ("", ""))[0]
                missing.append(f"{service_name} (set {env_var})")

        if missing:
            raise ValueError("Services enabled in manifest but missing URL config: " + ", ".join(missing))


__all__ = ["ProjectBootstrapConfig"]
