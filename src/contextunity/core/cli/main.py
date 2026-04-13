"""ContextUnity Core CLI.

Unified CLI for administrative, security, and validation tasks.
"""

import sys

import typer

# Import cleaned logic from existing command scripts
from contextunity.core.cli.mint import mint_hmac as _mint_hmac
from contextunity.core.cli.mint import mint_redis as _mint_redis
from contextunity.core.cli.mint import mint_rotate as _mint_rotate
from contextunity.core.cli.mint import mint_rotate_redis_key as _mint_rotate_redis_key
from contextunity.core.cli.mint import mint_shield as _mint_shield
from contextunity.core.cli.validate import main as validate_main
from rich.console import Console

app = typer.Typer(
    name="contextunity-core",
    help="ContextUnity Ecosystem CLI",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()


@app.command("hmac")
def mint_hmac():
    """Generate a new CU_PROJECT_SECRET for project integration."""
    _mint_hmac()


@app.command("shield")
def mint_shield():
    """Generate a new SHIELD_MASTER_KEY for contextunity.shield Enterprise."""
    _mint_shield()


@app.command("redis")
def mint_redis():
    """Generate a new REDIS_SECRET_KEY to encrypt project tokens in Redis."""
    _mint_redis()


@app.command("rotate")
def mint_rotate(project_id: str, redis_url: str = typer.Option("", help="Redis connection URL")):
    """Rotate the active key for a project in Redis (admin operation)."""
    _mint_rotate(project_id, redis_url)


@app.command("rotate-redis-key")
def mint_rotate_redis_key(redis_url: str = typer.Option("", help="Redis connection URL")):
    """Re-encrypt the Redis DB with a new REDIS_SECRET_KEY."""
    _mint_rotate_redis_key(redis_url)


@app.command("validate")
def validate_manifest(manifest_path: str):
    """Validate a contextunity.project.yaml File against the core Pydantic schemas."""
    # validate.main takes sys.argv, so we'll just mock it
    sys.argv = ["contextcore validate", manifest_path]
    sys.exit(validate_main())


def main(argv: list[str] | None = None) -> None:
    if argv is not None:
        sys.argv = [sys.argv[0]] + argv
    app()


if __name__ == "__main__":
    main()
