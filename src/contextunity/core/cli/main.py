"""ContextUnity Core CLI.

Unified CLI for administrative, security, and validation tasks.
"""

import sys

import typer

# Import cleaned logic from existing command scripts
from contextunity.core.cli.mint import mint_hmac as _mint_hmac
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


@app.command("validate")
def validate_manifest(manifest_path: str):
    """Validate a contextunity.project.yaml File against the core Pydantic schemas.

    Args:
        manifest_path (str): The manifest path parameter.
    """
    # validate.main takes sys.argv, so we'll just mock it
    sys.argv = ["contextcore validate", manifest_path]
    sys.exit(validate_main())


def main(argv: list[str] | None = None) -> None:
    """Entry point for the contextunity-core CLI application.

    Args:
        argv (list[str] | None): The argv parameter.
    """
    if argv is not None:
        sys.argv = [sys.argv[0]] + argv
    app()


if __name__ == "__main__":
    main()
