"""Run orchestration — the core agent loop.

Assembles a :class:`RunConfig` from a recipe + CLI inputs + scope, seeds the
graph state (loading the standing hints file into context), runs the six-phase
graph under a persistent checkpointer, writes artifacts, and tracks session
status. Used by ``argus run``, ``argus scan``, and ``argus resume``.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Optional

from argus.core import hints, paths, report as report_mod, sessions
from argus.core.graph import build_graph
from argus.core.recipe import Recipe
from argus.core.scope import Scope
from argus.core.state import RunConfig, RunState, results_from_state


def new_run_id() -> str:
    return uuid.uuid4().hex[:12]


def build_run_config(
    *,
    recipe: Recipe,
    target: str,
    model: str,
    scope: Scope,
    dry_run: bool,
    assume_yes: bool,
    run_id: Optional[str] = None,
) -> RunConfig:
    rid = run_id or new_run_id()
    run_dir = str(paths.run_dir(rid))
    params = recipe.parameters or {}
    return RunConfig(
        run_id=rid,
        target=target,
        model=model,
        intensity=recipe.intensity,
        phases=recipe.phases,
        selected=recipe.extensions,
        flags=recipe.flags,
        dry_run=dry_run,
        assume_yes=assume_yes,
        run_dir=run_dir,
        wordlist=params.get("wordlist"),
        resolvers=params.get("resolvers"),
        nuclei_templates=params.get("nuclei_templates"),
    )


def initial_state(cfg: RunConfig, scope: Scope) -> RunState:
    state: RunState = {
        "config": cfg.model_dump(),
        "scope": scope.model_dump(),
        "gate_passed": cfg.dry_run or cfg.assume_yes,
        "aborted": False,
        # hints are loaded into context here; the report node / triage can use them
        "phase_log": [f"Loaded standing hints ({len(hints.load_hints())} chars)"],
    }
    return state


def execute(cfg: RunConfig, scope: Scope) -> RunState:
    """Run the pipeline to completion (or abort) and persist artifacts."""
    meta = sessions.SessionMeta(
        run_id=cfg.run_id, target=cfg.target, model=cfg.model,
        intensity=cfg.intensity, dry_run=cfg.dry_run, status="running",
    )
    sessions.save_meta(meta)

    checkpointer = sessions.make_checkpointer()
    graph = build_graph(checkpointer=checkpointer)
    state = initial_state(cfg, scope)
    try:
        final: RunState = graph.invoke(state, config=sessions.thread_config(cfg.run_id))
    except Exception:
        sessions.update_status(cfg.run_id, "error")
        raise
    finally:
        sessions.close_checkpointer(checkpointer)

    _persist_artifacts(cfg, final)
    sessions.update_status(cfg.run_id, "aborted" if final.get("aborted") else "completed")
    return final


def resume(run_id: str) -> RunState:
    """Resume an interrupted run from its last checkpoint."""
    meta = sessions.load_meta(run_id)
    if meta is None:
        raise ValueError(f"no such session: {run_id}")
    sessions.update_status(run_id, "running")
    checkpointer = sessions.make_checkpointer()
    graph = build_graph(checkpointer=checkpointer)
    try:
        # invoking with None resumes from the persisted checkpoint
        final: RunState = graph.invoke(None, config=sessions.thread_config(run_id))
    finally:
        sessions.close_checkpointer(checkpointer)
    _persist_artifacts_from_meta(run_id, final)
    sessions.update_status(run_id, "aborted" if final.get("aborted") else "completed")
    return final


def _persist_artifacts(cfg: RunConfig, final: RunState) -> None:
    results = results_from_state(final)
    run_path = paths.run_dir(cfg.run_id)
    md = final.get("report_markdown") or report_mod.to_markdown(cfg.run_id, cfg.target, results)
    (run_path / "report.md").write_text(md, encoding="utf-8")
    (run_path / "report.json").write_text(
        report_mod.to_json(cfg.run_id, cfg.target, results), encoding="utf-8"
    )
    (run_path / "run.log").write_text("\n".join(final.get("phase_log", [])), encoding="utf-8")


def _persist_artifacts_from_meta(run_id: str, final: RunState) -> None:
    meta = sessions.load_meta(run_id)
    target = meta.target if meta else run_id
    results = results_from_state(final)
    run_path = paths.run_dir(run_id)
    md = final.get("report_markdown") or report_mod.to_markdown(run_id, target, results)
    (run_path / "report.md").write_text(md, encoding="utf-8")
    (run_path / "report.json").write_text(
        report_mod.to_json(run_id, target, results), encoding="utf-8"
    )


def render_existing_report(run_id: str, fmt: str) -> str:
    """Re-render a finished run's report from its persisted artifacts."""
    run_path = paths.run_dir(run_id)
    if fmt == "json":
        p = run_path / "report.json"
    else:
        p = run_path / "report.md"
    if not p.exists():
        raise FileNotFoundError(f"no {fmt} report for run {run_id} (looked in {run_path})")
    return Path(p).read_text(encoding="utf-8")
