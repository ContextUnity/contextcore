"""CLI script to validate ContextUnity Project manifests."""

import argparse
import sys

from contextunity.core.logging import get_contextunit_logger
from contextunity.core.manifest import ArtifactGenerator, ContextUnityProject
from contextunity.core.sdk.bootstrap.manifest import _load_manifest
from contextunity.core.sdk.config import ProjectBootstrapConfig

logger = get_contextunit_logger(__name__)


def _derive_permissions(manifest_dict: dict) -> list[str]:
    """Derive Shield permissions from manifest dict. Returns sorted list."""
    SERVICE_PERMISSIONS_MAP = {
        "brain": ["brain:read", "brain:write", "trace:read", "trace:write", "memory:read", "memory:write"],
        "router": ["router:execute", "tools:register"],
        "worker": ["worker:execute", "worker:schedule"],
        "zero": ["zero:*"],
        "shield": ["shield:secrets:read", "shield:secrets:write"],
    }

    permissions = set()
    services_dict = manifest_dict.get("services", {})

    for service, perms in SERVICE_PERMISSIONS_MAP.items():
        if service == "shield":
            permissions.update(perms)
        elif services_dict.get(service, {}).get("enabled"):
            permissions.update(perms)

    router = manifest_dict.get("router", {})
    graph = router.get("graph", {})
    template = graph.get("template")
    if template:
        permissions.add(f"graph:{template}")

    for tool_group in router.get("tools", []):
        tools_list = tool_group.get("tools", [tool_group]) if "tools" in tool_group else [tool_group]
        for tool in tools_list:
            tool_name = tool.get("name")
            if tool_name:
                permissions.add(f"tool:{tool_name}")
                permissions.add(f"tool:{tool_name}_validate")

    for node in graph.get("nodes", []):
        if node.get("type") == "tool":
            tool_binding = node.get("tool_binding")
            if tool_binding:
                if isinstance(tool_binding, list):
                    for tb in tool_binding:
                        tool_name = tb.split(":")[0] if ":" in tb else tb
                        permissions.add(f"tool:{tool_name}")
                        permissions.add(f"tool:{tool_name}_validate")
                else:
                    tool_name = tool_binding.split(":")[0] if ":" in tool_binding else tool_binding
                    permissions.add(f"tool:{tool_name}")
                    permissions.add(f"tool:{tool_name}_validate")

    return sorted(permissions)


def cmd_validate(args: argparse.Namespace) -> int:
    manifest_path = getattr(args, "manifest_path", "contextunity.project.yaml")
    quiet = getattr(args, "quiet", False)

    if not quiet:
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
        if not quiet:
            print("✅ 1. Schema Validation (Pydantic): PASS")
    except Exception as e:
        print(f"❌ 1. Schema Validation (Pydantic): FAIL\n{e}", file=sys.stderr)
        return 1

    # --quiet mode: just output the comma-separated permissions string and exit
    if quiet:
        permissions = _derive_permissions(manifest_dict)
        print(",".join(permissions))
        return 0

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
        print(f"✅ 4. Router Artifact Generator: PASS (Payload proxy size: {len(str(bundle))} bytes)")

        worker_bindings = generator.generate_worker_bindings()
        print(f"✅ 5. Worker Bindings Generator: PASS ({len(worker_bindings)} bindings)")
    except Exception as e:
        print(f"❌ 4. Artifact Generator compilation: FAIL\n{e}", file=sys.stderr)
        return 1

    print("=" * 50)
    print(f"🚀 Manifest '{manifest_path}' is perfectly valid and ready for Router!")

    # Print Shield command hint
    project_id = project_section["id"]
    permissions = _derive_permissions(manifest_dict)
    perms_str = ",".join(permissions)

    print("\n" + "=" * 50)
    print("🛡️  Shield Policy Command (using Admin Token):")
    print(f"   contextshield project-policy {project_id} --set {perms_str} --admin-token $ADMIN_TOKEN")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="contextunity-core validate",
        description="Validate a contextunity.project.yaml manifest strictly against v1alpha schema.",
    )

    parser.add_argument(
        "manifest_path",
        nargs="?",
        default="contextunity.project.yaml",
        help="Path to the manifest file (default: contextunity.project.yaml)",
    )

    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        default=False,
        help="Output only the comma-separated permissions string (for scripting).",
    )

    args = parser.parse_args(argv)
    return cmd_validate(args)


if __name__ == "__main__":
    sys.exit(main())
