"""CLI script to validate ContextUnity Project manifests."""

import argparse
import sys
from collections.abc import Mapping

from contextunity.core.logging import get_contextunit_logger
from contextunity.core.manifest import ArtifactGenerator, ContextUnityProject
from contextunity.core.permissions import service_session_permissions
from contextunity.core.sdk.bootstrap.manifest import load_manifest
from contextunity.core.sdk.config import ProjectBootstrapConfig
from contextunity.core.types import JsonDict, is_json_dict, is_object_list

logger = get_contextunit_logger(__name__)


def _json_dict(value: object) -> JsonDict | None:
    return value if is_json_dict(value) else None


def _service_enabled(services: JsonDict, service: str) -> bool:
    service_cfg = _json_dict(services.get(service))
    return service_cfg is not None and service_cfg.get("enabled") is True


def _tool_name_from_binding(tool_binding: object) -> str | None:
    if isinstance(tool_binding, str):
        return tool_binding.split(":")[0] if ":" in tool_binding else tool_binding
    if is_object_list(tool_binding):
        for item in tool_binding:
            if isinstance(item, str):
                return item.split(":")[0] if ":" in item else item
    return None


def _derive_permissions(manifest_dict: Mapping[str, object]) -> list[str]:
    """Derive Shield permissions from manifest dict. Returns sorted list."""
    if not is_json_dict(manifest_dict):
        return []

    permissions: set[str] = set()
    services = _json_dict(manifest_dict.get("services")) or {}

    for service in ("brain", "router", "worker", "shield"):
        if service == "shield":
            permissions.update(service_session_permissions(service))
        elif _service_enabled(services, service):
            permissions.update(service_session_permissions(service))

    router = _json_dict(manifest_dict.get("router")) or {}
    graph = _json_dict(router.get("graph")) or {}
    template = graph.get("template")
    if isinstance(template, str):
        permissions.add(f"graph:{template}")

    tools_raw = router.get("tools")
    if not is_object_list(tools_raw):
        tool_groups: list[object] = []
    else:
        tool_groups = tools_raw
    for tool_group_raw in tool_groups:
        if not is_json_dict(tool_group_raw):
            continue
        tool_group = tool_group_raw
        if "tools" in tool_group:
            nested_tools = tool_group.get("tools")
            if is_object_list(nested_tools):
                tools_list: list[object] = nested_tools
            else:
                tools_list = [tool_group]
        else:
            tools_list = [tool_group]

        for tool_raw in tools_list:
            if not is_json_dict(tool_raw):
                continue
            tool_name_raw = tool_raw.get("name")
            if isinstance(tool_name_raw, str) and tool_name_raw:
                permissions.add(f"tool:{tool_name_raw}")
                permissions.add(f"tool:{tool_name_raw}_validate")

    nodes_raw = graph.get("nodes")
    if not is_object_list(nodes_raw):
        nodes: list[object] = []
    else:
        nodes = nodes_raw
    for node_raw in nodes:
        if not is_json_dict(node_raw):
            continue
        if node_raw.get("type") != "tool":
            continue
        tool_name = _tool_name_from_binding(node_raw.get("tool_binding"))
        if tool_name:
            permissions.add(f"tool:{tool_name}")
            permissions.add(f"tool:{tool_name}_validate")

    return sorted(permissions)


def cmd_validate(args: argparse.Namespace) -> int:
    """Execute the manifest validation routine.

    Args:
        args (argparse.Namespace): Positional arguments.

    Returns:
        int: The resulting integer value.
    """
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

    manifest_dict = load_manifest(manifest_path)
    if not manifest_dict:
        print(f"❌ Fail: file not found or invalid YAML -> {manifest_path}", file=sys.stderr)
        return 1

    project_section = _json_dict(manifest_dict.get("project"))
    if project_section is None or "id" not in project_section:
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
        resolved_secrets = config.resolve_secrets(manifest)
        print(f"✅ 2. Secrets resolver: PASS ({len(resolved_secrets)} resolved)")
    except Exception as e:
        print(f"❌ 2. Secrets resolver: FAIL\n{e}", file=sys.stderr)
        return 1

    try:
        generator = ArtifactGenerator(manifest)
        bundle = generator.generate_router_registration_bundle()
        print(f"✅ 3. Router Artifact Generator: PASS (Payload proxy size: {len(str(bundle))} bytes)")

        worker_bindings = generator.generate_worker_bindings()
        print(f"✅ 4. Worker Bindings Generator: PASS ({len(worker_bindings.schedules)} schedules)")
    except Exception as e:
        print(f"❌ 3. Artifact Generator compilation: FAIL\n{e}", file=sys.stderr)
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
    """Entry point for the manifest validation CLI script.

    Args:
        argv (list[str] | None): The argv parameter.

    Returns:
        int: The resulting integer value.
    """
    parser = argparse.ArgumentParser(
        prog="contextunity-core validate",
        description="Validate a contextunity.project.yaml manifest strictly against v1alpha schema.",
    )

    _ = parser.add_argument(
        "manifest_path",
        nargs="?",
        default="contextunity.project.yaml",
        help="Path to the manifest file (default: contextunity.project.yaml)",
    )

    _ = parser.add_argument(
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
