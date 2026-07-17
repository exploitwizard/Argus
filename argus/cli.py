"""ARGUS command-line entrypoint.

Commands:
    argus config        pick a provider, paste an API key, choose a default model
    argus models        list configured providers and liveness-ping each
    argus scan          run the six-phase recon pipeline against a target
    argus resume        continue a checkpointed run
    argus report        (re)render a finished run's report
    argus check-tools   dependency doctor: verify recon binaries, print install hints

This module is intentionally thin. Each command delegates into ``argus.core``
and ``argus.phases``; the CLI's job is argument parsing, the banner, and the
authorization gate. Command bodies are stubbed during scaffolding (build step 1)
and filled in as later build steps land.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

import typer

from argus import __version__
from argus.ui import console as ui

app = typer.Typer(
    name="argus",
    help="ARGUS — Autonomous Recon & Guided Unified Scanner (authorized testing only).",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)


class Intensity(str, Enum):
    low = "low"
    med = "med"
    high = "high"


class ReportFormat(str, Enum):
    md = "md"
    json = "json"
    docx = "docx"


def _version_callback(value: bool) -> None:
    if value:
        ui.console.print(f"ARGUS v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", "-V", callback=_version_callback, is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """ARGUS root. See ``argus <command> --help`` for details."""


# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #
@app.command()
def config() -> None:
    """Interactive setup: pick a provider, paste an API key, choose a default model.

    Keys are stored in the OS keyring (never in the repo, never printed back).
    """
    ui.print_banner()
    ui.warn("`argus config` is not implemented yet (arrives in build step 2 — LLM layer).")
    raise typer.Exit(code=1)


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #
@app.command()
def models() -> None:
    """List configured providers and do a 1-token liveness ping to each."""
    ui.print_banner()
    ui.warn("`argus models` is not implemented yet (arrives in build step 2 — LLM layer).")
    raise typer.Exit(code=1)


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #
@app.command()
def scan(
    target: str = typer.Argument(..., help="Primary target domain (must be in scope)."),
    scope: Optional[str] = typer.Option(
        None, "--scope", "-s", help="Path to scope.yaml. Required before any live traffic."
    ),
    model: Optional[str] = typer.Option(
        None, "--model", "-m", help="Override the default LLM for this run (e.g. gemini/gemini-2.5-pro)."
    ),
    intensity: Intensity = typer.Option(
        Intensity.med, "--intensity", "-i", help="How aggressive the pipeline may be."
    ),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Non-interactively accept the authorized-use notice."
    ),
) -> None:
    """Run the six-phase recon pipeline against TARGET (authorized scope only)."""
    ui.print_banner()
    if not ui.require_authorization(assume_yes=i_am_authorized):
        raise typer.Exit(code=2)
    ui.warn("`argus scan` pipeline is not implemented yet (arrives in build steps 4–5).")
    ui.info(f"Would scan: target={target} scope={scope} model={model} intensity={intensity.value}")
    raise typer.Exit(code=1)


# --------------------------------------------------------------------------- #
# resume
# --------------------------------------------------------------------------- #
@app.command()
def resume(
    run_id: str = typer.Argument(..., help="The run_id of a checkpointed run to continue."),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Non-interactively accept the authorized-use notice."
    ),
) -> None:
    """Continue a checkpointed run from where it was interrupted."""
    ui.print_banner()
    if not ui.require_authorization(assume_yes=i_am_authorized):
        raise typer.Exit(code=2)
    ui.warn("`argus resume` is not implemented yet (arrives in build step 4 — graph/checkpointing).")
    ui.info(f"Would resume run_id={run_id}")
    raise typer.Exit(code=1)


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #
@app.command()
def report(
    run_id: str = typer.Argument(..., help="The run_id whose report to (re)render."),
    fmt: ReportFormat = typer.Option(
        ReportFormat.md, "--format", "-f", help="Output format."
    ),
) -> None:
    """(Re)render a finished run's report as Markdown, JSON, or DOCX."""
    ui.warn("`argus report` is not implemented yet (arrives in build step 6 — reporting).")
    ui.info(f"Would render run_id={run_id} as {fmt.value}")
    raise typer.Exit(code=1)


# --------------------------------------------------------------------------- #
# check-tools
# --------------------------------------------------------------------------- #
@app.command(name="check-tools")
def check_tools() -> None:
    """Dependency doctor: verify each recon binary and print install hints for missing ones."""
    ui.warn("`argus check-tools` is not implemented yet (arrives in build step 3 — tools layer).")
    raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
