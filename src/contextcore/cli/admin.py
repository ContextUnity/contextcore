"""contextcore.cli.admin — Administrative operations via gRPC.

Usage:
    python -m contextcore.cli.admin sync-policy <path/to/contextunity.project.yaml>
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from contextcore import ContextUnit, get_context_unit_logger
from contextcore.config import get_core_config
from contextcore.permissions import Permissions

logger = get_context_unit_logger(__name__)


class AdminClient:
    """Temporary client to execute Admin RPCs against Shield."""

    def __init__(self, address: str, project_token: str):
        self.address = address
        self.project_token = project_token
        self.channel = None

    async def connect(self):
        from contextcore.grpc_utils import create_channel

        self.channel = create_channel(self.address)

    async def close(self):
        if self.channel:
            await self.channel.close()

    def _get_auth_metadata(self):
        return (("authorization", f"Bearer {self.project_token}"),)

    async def sync_project_policy(self, project_id: str, manifest_yaml: str) -> dict:
        """Call Shield SyncProjectPolicy RPC."""
        from contextcore import shield_pb2_grpc

        stub = shield_pb2_grpc.ShieldServiceStub(self.channel)

        req = ContextUnit(
            payload={
                "project_id": project_id,
                "manifest_yaml": manifest_yaml,
            },
            provenance=["admin:sync_policy"],
        )
        from contextcore import context_unit_pb2

        resp = await stub.SyncProjectPolicy(req.to_protobuf(context_unit_pb2), metadata=self._get_auth_metadata())

        from google.protobuf.json_format import MessageToDict

        return MessageToDict(resp.payload)


def _mint_admin_token() -> str:
    """Mint an admin token to authenticate with Shield.

    Requires SHIELD_MASTER_KEY to be available in the environment to mint
    a self-signed token that Shield will trust.
    Valid for 5 minutes.
    """
    import time

    from contextcore.config import get_core_config
    from contextcore.signing import HmacBackend
    from contextcore.token_utils import serialize_token
    from contextcore.tokens import ContextToken

    config = get_core_config()
    master_key = config.security.shield_master_key
    if not master_key:
        print("❌ Error: SHIELD_MASTER_KEY environment variable is required for admin CLI.")
        sys.exit(1)

    backend = HmacBackend(project_id="system", project_secret=master_key)

    token = ContextToken(
        token_id="admin-sync",
        user_id="system",
        permissions=(Permissions.SHIELD_POLICY_WRITE,),
        allowed_tenants=("*",),
        exp_unix=time.time() + 300,
        agent_id="ansible-deploy",
    )

    return serialize_token(token, backend=backend)


async def _async_sync_policy(manifest_path: Path):
    if manifest_path.is_dir():
        manifest_path = manifest_path / "contextunity.project.yaml"

    if not manifest_path.exists():
        print(f"❌ Manifest not found at {manifest_path}")
        sys.exit(1)

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest_yaml = f.read()

    try:
        manifest_dict = yaml.safe_load(manifest_yaml)
    except yaml.YAMLError as e:
        print(f"❌ Invalid YAML in manifest: {e}")
        sys.exit(1)

    project_id = manifest_dict.get("project", {}).get("id")
    if not project_id:
        print("❌ Invalid manifest: missing project.id")
        sys.exit(1)

    # Get Shield URL
    config = get_core_config()
    shield_url = config.shield_url
    if not shield_url:
        print("❌ CONTEXTSHIELD_GRPC_URL not set.")
        sys.exit(1)

    admin_token = _mint_admin_token()

    print(f"🔄 Syncing policy for '{project_id}' via gRPC to {shield_url}...")

    client = AdminClient(address=shield_url, project_token=admin_token)
    await client.connect()

    try:
        response = await client.sync_project_policy(project_id, manifest_yaml)
        if response.get("error"):
            print(f"❌ Error from Shield: {response.get('message')}")
            sys.exit(1)

        print(f"✅ Policy updated for '{project_id}'")
        allowed = response.get("allowedPermissions") or response.get("allowed_permissions") or []
        if allowed:
            print(f"   Allowed: {', '.join(str(p) for p in allowed)}")
        else:
            print("   (permissions list not returned in response — verify with Shield CLI)")
    except Exception as e:
        print(f"❌ gRPC connection failed: {e}")
        sys.exit(1)
    finally:
        await client.close()


def cmd_sync_policy(args: argparse.Namespace) -> None:
    path = Path(args.manifest_path)
    import asyncio

    asyncio.run(_async_sync_policy(path))


def main():
    parser = argparse.ArgumentParser(description="ContextUnity Admin CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    sp_sync = subparsers.add_parser("sync-policy", help="Sync project policy via gRPC")
    sp_sync.add_argument("manifest_path", help="Path to contextunity.project.yaml")

    args = parser.parse_args()

    if args.command == "sync-policy":
        cmd_sync_policy(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
