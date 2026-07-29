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
from types import ModuleType
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
    html = "html"
    both = "both"


class MultiMode(str, Enum):
    ensemble = "ensemble"
    per_phase = "per-phase"


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
    table.add_column("Multi-model")
    table.add_column("Detail")

    for provider in configured:
        model = settings.provider_defaults.get(provider) or cfg.default_model_for(provider)
        ui.info(f"Pinging {provider} ({model})…")
        res = llm.ping(model)
        status = "[green]✔ ok[/]" if res.ok else "[red]✖ fail[/]"
        # Ready for concurrent multi-model use if the provider has a usable key.
        mm = "[green]✔ ready[/]" if llm.multi_model_ready(model) else "[yellow]✖ no key[/]"
        table.add_row(provider, model, status, mm, "" if res.ok else res.detail)

    ui.console.print(table)

    ready = [p for p in configured if cfg.has_api_key(p)]
    if len(ready) >= 2:
        ui.info(
            f"{len(ready)} providers ready for multi-model. Use e.g. "
            "`argus scan T --models m1,m2 --multi-mode ensemble`."
        )
    else:
        ui.info("Configure 2+ providers to enable multi-model (ensemble / per-phase) runs.")


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
# install-tools
# --------------------------------------------------------------------------- #
@app.command(name="install-tools")
def install_tools_cmd(
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show the exact install commands but run nothing."
    ),
    all_tools: bool = typer.Option(
        False, "--all", help="Reinstall all tools, not only the missing ones."
    ),
) -> None:
    """Install missing recon tools (apt / go / pipx / LinkFinder venv-shim).

    Shows the exact commands first (sudo surfaced) and asks before running.
    Idempotent: already-present tools are skipped. One failure never aborts the
    rest — it ends with an updated availability summary.
    """
    from argus.install import installer

    ui.print_banner()
    _run_installer(installer, assume_yes=yes, dry_run=dry_run, only_missing=not all_tools)


def _run_installer(
    installer: ModuleType, *, assume_yes: bool, dry_run: bool, only_missing: bool
) -> list:
    """Shared install driver: PATH check, plan, confirm, execute (used by scan too)."""
    ok, guidance = installer.go_bin_on_path()
    if not ok:
        ui.warn(guidance)

    def _confirm() -> bool:
        try:
            return ui.console.input(
                "[bold]Proceed with the commands above? Type [red]yes[/red]: [/]"
            ).strip().lower() == "yes"
        except (EOFError, KeyboardInterrupt):
            ui.console.print()
            return False

    # markup=False so command text like "[needs sudo]" or bracketed flags is
    # printed verbatim rather than parsed as Rich markup.
    def _emit(msg: str) -> None:
        ui.console.print(msg, markup=False, highlight=False)

    return installer.install_tools(
        assume_yes=assume_yes,
        dry_run=dry_run,
        only_missing=only_missing,
        confirm=_confirm,
        emit=_emit,
    )


# --------------------------------------------------------------------------- #
# run (recipe)
# --------------------------------------------------------------------------- #
@app.command()
def run(
    recipe: str = typer.Argument(..., help="Path to a recipe YAML playbook."),
    target: str = typer.Option(..., "--target", "-t", help="Primary target domain."),
    scope: Optional[str] = typer.Option(None, "--scope", "-s", help="Path to scope.yaml."),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Override the run's LLM."),
    models: Optional[str] = typer.Option(
        None, "--models", help="Comma-separated model ids to run concurrently (multi-model)."
    ),
    multi_mode: MultiMode = typer.Option(
        MultiMode.ensemble, "--multi-mode",
        help="With --models: ensemble (consensus triage) or per-phase assignment.",
    ),
    param: list[str] = typer.Option(
        [], "--param", help="Recipe parameter override: key=value (repeatable)."
    ),
    skills: Optional[str] = typer.Option(
        None, "--skills",
        help="Your own methodology (skills.md, a folder, or skills.zip) to guide triage.",
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
        models=models,
        multi_mode=multi_mode.value,
        dry_run=dry_run,
        assume_yes=i_am_authorized,
        skills_path=skills,
    )


# --------------------------------------------------------------------------- #
# scan (ad-hoc recipe)
# --------------------------------------------------------------------------- #
@app.command()
def scan(
    target: str = typer.Argument(..., help="Primary target domain (must be in scope)."),
    scope: Optional[str] = typer.Option(None, "--scope", "-s", help="Path to scope.yaml."),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Override the default LLM."),
    models: Optional[str] = typer.Option(
        None, "--models", help="Comma-separated model ids to run concurrently (multi-model)."
    ),
    multi_mode: MultiMode = typer.Option(
        MultiMode.ensemble, "--multi-mode",
        help="With --models: ensemble (consensus triage) or per-phase assignment.",
    ),
    intensity: Intensity = typer.Option(Intensity.med, "--intensity", "-i", help="Recon depth."),
    skills: Optional[str] = typer.Option(
        None, "--skills",
        help="Your own methodology (skills.md, a folder, or skills.zip) to guide triage.",
    ),
    auto_install: bool = typer.Option(
        False, "--auto-install", help="Install any missing recon tools before running."
    ),
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
    if auto_install:
        from argus.install import installer
        _run_installer(installer, assume_yes=i_am_authorized, dry_run=False, only_missing=True)
    recipe = Recipe(name="single-target", intensity=intensity.value)
    _execute_run(
        recipe=recipe,
        target=target,
        scope_path=scope,
        model=model,
        models=models,
        multi_mode=multi_mode.value,
        dry_run=dry_run,
        assume_yes=i_am_authorized,
        skills_path=skills,
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
    fmt: ReportFormat = typer.Option(
        ReportFormat.both, "--format", "-f", help="Output format: md | html | both."
    ),
) -> None:
    """(Re)render a finished run's report to `.md` and/or `.html` and print the paths."""
    from argus.core import agent

    try:
        written = agent.write_reports(run_id, fmt.value)
    except FileNotFoundError as exc:
        ui.error(str(exc))
        raise typer.Exit(code=2)
    ui.success(f"Wrote {len(written)} report file(s):")
    for p in written:
        ui.info(str(p))


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
    models: Optional[str] = None,
    multi_mode: str = "ensemble",
    skills_path: Optional[str] = None,
) -> None:
    from argus.core import agent, config as cfg_mod, llm
    from argus.core.modelplan import resolve_plan
    from argus.core.scope import Scope
    from argus.extensions import available_for_phase

    # --- scope resolution ------------------------------------------------- #
    # A full scope.yaml always takes precedence. With no scope file we fall back
    # to IMPLICIT-SCOPE mode: the target's registrable domain (+ its subdomains)
    # becomes the scope. Anything discovered outside that root is still dropped
    # by the scope filter and never auto-probed.
    if scope_path:
        if not Path(scope_path).is_file():
            ui.error(f"Scope file not found: {scope_path}")
            raise typer.Exit(code=2)
        scope = Scope.from_yaml(scope_path)
    else:
        from argus.core.scope import _as_ip, _host_of, registrable_domain

        scope = Scope.implicit(target)
        host = _host_of(target)
        if _as_ip(host) is not None:
            ui.console.print(
                f"[bold red]Running in IMPLICIT-SCOPE mode[/] — scope = "
                f"[bold]{host}[/] (single host)"
            )
        else:
            root = registrable_domain(host) or host
            ui.console.print(
                f"[bold red]Running in IMPLICIT-SCOPE mode[/] — scope = "
                f"[bold]{root}[/] and subdomains"
            )

    if not scope.is_in_scope(target):
        ui.error(f"Target {target!r} is not in scope per {scope_path or 'implicit scope'}.")
        raise typer.Exit(code=2)

    # --- model plan (single | ensemble | per-phase) ---------------------- #
    settings = cfg_mod.load_settings()
    plan = resolve_plan(
        cli_model=model,
        cli_models=llm.parse_models(models),
        multi_mode=multi_mode,
        default_model=settings.default_model,
        phase_models=settings.phase_models,
        recipe_model=recipe.model,
    )
    resolved_model = plan.primary
    if plan.mode != "single":
        ready = [m for m in plan.ensemble if llm.multi_model_ready(m)]
        not_ready = [m for m in plan.ensemble if m not in ready]
        ui.info(
            f"Multi-model ({plan.mode}): {', '.join(plan.ensemble)}"
            + (f"  (quorum {plan.quorum})" if plan.is_ensemble else "")
        )
        if not_ready:
            ui.warn(
                f"No API key for: {', '.join(not_ready)} — these are skipped; "
                "the run continues with the rest."
            )

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

    # --- operator skills (bring-your-own methodology) -------------------- #
    skills_text = ""
    if skills_path:
        from argus.core import skills as skills_mod

        try:
            skills_text = skills_mod.load_skills(skills_path)
        except skills_mod.SkillsError as exc:
            ui.error(str(exc))
            raise typer.Exit(code=2)
        ui.info(
            f"Loaded operator skills from {skills_path} ({len(skills_text)} chars) — "
            "folded into triage (needs a model; detection & documentation only)."
        )
        if dry_run:
            ui.warn("Skills only affect model-driven triage; a --dry-run performs no triage.")

    # --- build config + execute ------------------------------------------ #
    cfg = agent.build_run_config(
        recipe=recipe,
        target=target,
        model=resolved_model,
        scope=scope,
        dry_run=dry_run,
        assume_yes=assume_yes or dry_run,
        plan=plan,
        skills=skills_text,
    )
    model_desc = resolved_model if plan.mode == "single" else f"{plan.mode}:{','.join(plan.ensemble)}"
    ui.info(f"Run ID: {cfg.run_id}  model={model_desc}  dry_run={dry_run}")

    # Up-front, rough time estimate for the full recon (live ETA counts down
    # per-tool as the run proceeds).
    from argus.core import estimates
    from argus.phases.runner import planned_tools

    planned = planned_tools(cfg)
    if planned:
        eta = estimates.human_time(estimates.estimate_total(planned))
        ui.info(
            f"Estimated recon time: ~{eta} across {len(planned)} tool run(s) "
            f"[grey58](rough — nuclei/amass dominate)[/]"
        )

    final = agent.execute(cfg, scope)

    for line in final.get("phase_log", []):
        ui.info(line)
    if final.get("aborted"):
        ui.warn("Run aborted at the live-traffic gate.")
    else:
        ui.success(f"Run {cfg.run_id} complete. Artifacts in {cfg.run_dir}")
        if cfg.run_dir:
            for p in sorted(Path(cfg.run_dir).glob("argus_report_*")):
                ui.info(f"Report: {p}")
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
