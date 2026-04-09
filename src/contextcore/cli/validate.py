"""CLI script to validate ContextUnity Project manifests."""

import argparse
import sys

from contextcore.logging import get_context_unit_logger
from contextcore.manifest import ArtifactGenerator, ContextUnityProject
from contextcore.sdk.bootstrap.manifest import _load_manifest
from contextcore.sdk.config import ProjectBootstrapConfig

logger = get_context_unit_logger(__name__)


def cmd_validate(args: argparse.Namespace) -> int:
    manifest_path = getattr(args, "manifest_path", "contextunity.project.yaml")
    print(f"🔍 Validating manifest: {manifest_path}")
    print("=" * 50)

    try:
        config = ProjectBootstrapConfig.from_env(
            project_id="",
            manifest_path=manifest_path,
        )
    except Exception as e:
        print(f"❌ Fail: Environment/config loading failed: {e}", file=sys.stderr)
        return 1

    manifest_dict = _load_manifest(manifest_path)
    if not manifest_dict:
        print(f"❌ Fail: file not found or invalid YAML -> {manifest_path}", file=sys.stderr)
        return 1

    project_section = manifest_dict.get("project")
    if not project_section or not isinstance(project_section, dict) or "id" not in project_section:
        print("❌ Fail: missing required 'project.id' field", file=sys.stderr)
        return 1

    try:
        manifest = ContextUnityProject.model_validate(manifest_dict)
        print("✅ 1. Schema Validation (Pydantic): PASS")
    except Exception as e:
        print(f"❌ 1. Schema Validation (Pydantic): FAIL\n{e}", file=sys.stderr)
        return 1

    try:
        config.validate_service_urls(manifest)
        print("✅ 2. Service URLs validation: PASS")
    except ValueError as e:
        print(f"⚠️ 2. Service URLs validation WARNING: {e}")

    try:
        resolved_secrets = config.resolve_secrets(manifest)
        print(f"✅ 3. Secrets resolver: PASS ({len(resolved_secrets)} resolved)")
    except Exception as e:
        print(f"❌ 3. Secrets resolver: FAIL\n{e}", file=sys.stderr)
        return 1

    try:
        generator = ArtifactGenerator(manifest)
        bundle = generator.generate_router_registration_bundle(resolved_secrets=resolved_secrets)
        # Using string representation length as a proxy for size so we don't crash on un-serializable objects too early
        print(f"✅ 4. Router Artifact Generator: PASS (Payload proxy size: {len(str(bundle))} bytes)")

        worker_bindings = generator.generate_worker_bindings()
        print(f"✅ 5. Worker Bindings Generator: PASS ({len(worker_bindings)} bindings)")
    except Exception as e:
        print(f"❌ 4. Artifact Generator compilation: FAIL\n{e}", file=sys.stderr)
        return 1

    print("=" * 50)
    print(f"🚀 Manifest '{manifest_path}' is perfectly valid and ready for Router!")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m contextcore.cli.validate",
        description="Validate a contextunity.project.yaml manifest strictly against v1alpha schema.",
    )

    parser.add_argument(
        "manifest_path",
        nargs="?",
        default="contextunity.project.yaml",
        help="Path to the manifest file (default: contextunity.project.yaml)",
    )

    args = parser.parse_args(argv)
    return cmd_validate(args)


if __name__ == "__main__":
    sys.exit(main())
