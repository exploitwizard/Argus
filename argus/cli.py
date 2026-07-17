"""ARGUS command-line entrypoint.

Commands:
    argus config        pick a provider, paste an API key, choose a default model
    argus models        list configured providers and liveness-ping each
    argus run           run a recipe (YAML playbook) against a target
    argus scan          run the six-phase pipeline against a target (ad-hoc recipe)
    argus resume        continue a checkpointed run
    argus sessions      list checkpointed runs
    argus report        (re)render a finished run's report
    argus check-tools   dependency doctor: verify recon binaries, print install hints

The CLI stays thin: argument parsing, the banner, the authorization + live-traffic
gates, and pretty output. All real work lives in ``argus.core`` and ``argus.phases``.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Optional

import typer
from rich.table import Table

from argus import __version__
from argus.ui import console as ui

if TYPE_CHECKING:
    from argus.core.recipe import Recipe
    from argus.core.state import RunState

app = typer.Typer(
    name="argus",
    help="ARGUS — Autonomous Recon & Guided Unified Scanner (authorized testing only).",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)

sessions_app = typer.Typer(help="Manage checkpointed runs (sessions).", no_args_is_help=True)
app.add_typer(sessions_app, name="sessions")


class Intensity(str, Enum):
    low = "low"
    med = "med"
    high = "high"


class ReportFormat(str, Enum):
    md = "md"
    json = "json"


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
def config(
    provider: Optional[str] = typer.Option(
        None, "--provider", "-p", help="Provider to configure (skips the interactive picker)."
    ),
) -> None:
    """Interactive setup: pick a provider, paste an API key, choose a default model.

    The API key is read with hidden input and stored in your OS keyring. It is
    never taken as a CLI argument, never printed back, and never written to disk.
    """
    from argus.core import config as cfg

    ui.print_banner()

    names = list(cfg.PROVIDERS.keys())
    if provider is None:
        ui.info("Providers: " + ", ".join(names))
        provider = typer.prompt("Choose a provider", default="anthropic").strip().lower()
    provider = provider.lower()
    if provider not in cfg.PROVIDERS:
        ui.error(f"Unknown provider {provider!r}. Choose one of: {', '.join(names)}")
        raise typer.Exit(code=2)

    spec = cfg.PROVIDERS[provider]
    if spec.needs_key:
        # Hidden input — never echoed, never a positional arg (no shell-history leak).
        key = typer.prompt(f"Paste {provider} API key", hide_input=True)
        if not key.strip():
            ui.error("Empty key — nothing stored.")
            raise typer.Exit(code=2)
        cfg.set_api_key(provider, key.strip())
        ui.success(f"Stored {provider} API key in the OS keyring (not shown, not logged).")
    else:
        ui.info(f"{provider} needs no API key (fully-local).")

    model = typer.prompt("Default model", default=spec.default_model).strip()
    settings = cfg.load_settings()
    settings.default_model = model
    settings.provider_defaults[provider] = model
    cfg.save_settings(settings)
    ui.success(f"Default model set to {model}.")


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #
@app.command()
def models() -> None:
    """List configured providers and do a 1-token liveness ping to each."""
    from argus.core import config as cfg
    from argus.core import llm

    ui.print_banner()
    configured = cfg.configured_providers()
    if not configured:
        ui.warn("No providers configured. Run `argus config` first.")
        raise typer.Exit(code=1)

    settings = cfg.load_settings()
    table = Table(title="Configured providers", header_style="bold red")
    table.add_column("Provider")
    table.add_column("Model")
    table.add_column("Liveness")
    table.add_column("Detail")

    for provider in configured:
        model = settings.provider_defaults.get(provider) or cfg.default_model_for(provider)
        ui.info(f"Pinging {provider} ({model})…")
        res = llm.ping(model)
        status = "[green]✔ ok[/]" if res.ok else "[red]✖ fail[/]"
        table.add_row(provider, model, status, "" if res.ok else res.detail)

    ui.console.print(table)


# --------------------------------------------------------------------------- #
# check-tools
# --------------------------------------------------------------------------- #
@app.command(name="check-tools")
def check_tools() -> None:
    """Dependency doctor: verify each recon binary and print install hints for missing ones."""
    from argus.install import check_tools as doctor

    ui.print_banner()
    statuses = doctor.check_all()
    grouped = doctor.group_by_phase(statuses)
    for phase, items in grouped.items():
        table = Table(title=f"Phase {phase} — {doctor.phase_label(phase)}", header_style="bold red")
        table.add_column("Tool")
        table.add_column("Binary")
        table.add_column("Status")
        table.add_column("Install hint")
        for s in items:
            status = "[green]✔ found[/]" if s.available else "[yellow]✖ missing[/]"
            table.add_row(s.name, s.binary, status, "" if s.available else s.install_hint)
        ui.console.print(table)

    have, total = doctor.summary(statuses)
    ui.info(f"{have}/{total} tools available. Missing tools are skipped gracefully at run time.")


# --------------------------------------------------------------------------- #
# run (recipe)
# --------------------------------------------------------------------------- #
@app.command()
def run(
    recipe: str = typer.Argument(..., help="Path to a recipe YAML playbook."),
    target: str = typer.Option(..., "--target", "-t", help="Primary target domain."),
    scope: Optional[str] = typer.Option(None, "--scope", "-s", help="Path to scope.yaml."),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Override the run's LLM."),
    param: list[str] = typer.Option(
        [], "--param", help="Recipe parameter override: key=value (repeatable)."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Plan only — build commands, send NO live traffic."
    ),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Non-interactively accept authorization + live gate."
    ),
) -> None:
    """Run a recipe (YAML playbook) against TARGET."""
    from argus.core.recipe import load_recipe, parse_param_args

    ui.print_banner()
    if not Path(recipe).is_file():
        ui.error(f"Recipe not found: {recipe}")
        raise typer.Exit(code=2)
    try:
        overrides = parse_param_args(param)
        loaded = load_recipe(recipe, overrides=overrides)
    except ValueError as exc:
        ui.error(str(exc))
        raise typer.Exit(code=2)

    _execute_run(
        recipe=loaded,
        target=target,
        scope_path=scope or loaded.scope,
        model=model,
        dry_run=dry_run,
        assume_yes=i_am_authorized,
    )


# --------------------------------------------------------------------------- #
# scan (ad-hoc recipe)
# --------------------------------------------------------------------------- #
@app.command()
def scan(
    target: str = typer.Argument(..., help="Primary target domain (must be in scope)."),
    scope: Optional[str] = typer.Option(None, "--scope", "-s", help="Path to scope.yaml."),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Override the default LLM."),
    intensity: Intensity = typer.Option(Intensity.med, "--intensity", "-i", help="Recon depth."),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Plan only — build commands, send NO live traffic."
    ),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Non-interactively accept authorization + live gate."
    ),
) -> None:
    """Run the full six-phase pipeline against TARGET using an ad-hoc recipe."""
    from argus.core.recipe import Recipe

    ui.print_banner()
    recipe = Recipe(name="single-target", intensity=intensity.value)
    _execute_run(
        recipe=recipe,
        target=target,
        scope_path=scope,
        model=model,
        dry_run=dry_run,
        assume_yes=i_am_authorized,
    )


# --------------------------------------------------------------------------- #
# resume
# --------------------------------------------------------------------------- #
@app.command()
def resume(
    run_id: str = typer.Argument(..., help="The run_id of a checkpointed run to continue."),
) -> None:
    """Continue a checkpointed run from where it was interrupted."""
    from argus.core import agent

    ui.print_banner()
    try:
        final = agent.resume(run_id)
    except ValueError as exc:
        ui.error(str(exc))
        raise typer.Exit(code=2)
    ui.success(f"Run {run_id} resumed and {'aborted' if final.get('aborted') else 'completed'}.")
    for line in final.get("phase_log", []):
        ui.info(line)


# --------------------------------------------------------------------------- #
# sessions
# --------------------------------------------------------------------------- #
@sessions_app.command("list")
def sessions_list() -> None:
    """List all checkpointed runs (sessions)."""
    from argus.core import sessions

    rows = sessions.list_sessions()
    if not rows:
        ui.info("No sessions yet.")
        return
    table = Table(title="ARGUS sessions", header_style="bold red")
    table.add_column("Run ID")
    table.add_column("Target")
    table.add_column("Model")
    table.add_column("Status")
    table.add_column("Updated")
    for m in rows:
        table.add_row(m.run_id, m.target, m.model, m.status, m.updated_at)
    ui.console.print(table)


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #
@app.command()
def report(
    run_id: str = typer.Argument(..., help="The run_id whose report to (re)render."),
    fmt: ReportFormat = typer.Option(ReportFormat.md, "--format", "-f", help="Output format."),
) -> None:
    """(Re)render a finished run's report as Markdown or JSON."""
    from argus.core import agent

    try:
        content = agent.render_existing_report(run_id, fmt.value)
    except FileNotFoundError as exc:
        ui.error(str(exc))
        raise typer.Exit(code=2)
    ui.console.print(content)


# --------------------------------------------------------------------------- #
# shared run execution
# --------------------------------------------------------------------------- #
def _execute_run(
    *,
    recipe: "Recipe",
    target: str,
    scope_path: Optional[str],
    model: Optional[str],
    dry_run: bool,
    assume_yes: bool,
) -> None:
    from argus.core import agent, llm
    from argus.core.scope import Scope
    from argus.extensions import available_for_phase

    # --- scope resolution ------------------------------------------------- #
    if scope_path:
        if not Path(scope_path).is_file():
            ui.error(f"Scope file not found: {scope_path}")
            raise typer.Exit(code=2)
        scope = Scope.from_yaml(scope_path)
    elif dry_run:
        # Dry-run sends no traffic; synthesize a target-only scope for planning.
        scope = Scope(
            engagement="dry-run (synthesized scope)",
            in_scope_domains=[target.lower(), f"*.{target.lower()}"],
        )
        ui.warn("No --scope given; using a synthesized target-only scope for dry-run planning.")
    else:
        ui.error("A --scope file is required for live runs. Use --dry-run to plan without one.")
        raise typer.Exit(code=2)

    if not scope.is_in_scope(target):
        ui.error(f"Target {target!r} is not in scope per {scope_path or 'synthesized scope'}.")
        raise typer.Exit(code=2)

    resolved_model = llm.resolve_model(model)

    # --- authorization + live-traffic gate (skipped for dry-run) ---------- #
    if not dry_run:
        if not ui.require_authorization(assume_yes=assume_yes):
            raise typer.Exit(code=2)
        tools = [e.name for p in recipe.phases if p in (2, 3, 4, 5)
                 for e in available_for_phase(p)]
        if not ui.live_run_gate(
            target=target,
            in_scope_hosts=1,
            phases=recipe.phases,
            tool_names=sorted(set(tools)),
            assume_yes=assume_yes,
        ):
            raise typer.Exit(code=2)

    # --- build config + execute ------------------------------------------ #
    cfg = agent.build_run_config(
        recipe=recipe,
        target=target,
        model=resolved_model,
        scope=scope,
        dry_run=dry_run,
        assume_yes=assume_yes or dry_run,
    )
    ui.info(f"Run ID: {cfg.run_id}  model={resolved_model}  dry_run={dry_run}")

    final = agent.execute(cfg, scope)

    for line in final.get("phase_log", []):
        ui.info(line)
    if final.get("aborted"):
        ui.warn("Run aborted at the live-traffic gate.")
    else:
        ui.success(f"Run {cfg.run_id} complete. Artifacts in {cfg.run_dir}")
        if dry_run:
            _print_dry_run_plan(final)


def _print_dry_run_plan(final: "RunState") -> None:
    """Show the exact commands each extension WOULD run (no traffic was sent)."""
    from argus.core.state import results_from_state

    table = Table(title="Dry-run plan (no traffic sent)", header_style="bold red")
    table.add_column("Phase")
    table.add_column("Tool")
    table.add_column("Would run")
    any_rows = False
    for res in results_from_state(final):
        if res.dry_run and res.command:
            any_rows = True
            table.add_row(str(int(res.phase)), res.extension, " ".join(res.command))
    if any_rows:
        ui.console.print(table)
    else:
        ui.info("No tools were available to plan (install recon binaries; see `argus check-tools`).")


if __name__ == "__main__":
    app()
