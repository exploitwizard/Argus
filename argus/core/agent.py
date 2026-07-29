"""Run orchestration — the core agent loop.

Assembles a :class:`RunConfig` from a recipe + CLI inputs + scope, seeds the
graph state (loading the standing hints file into context), runs the six-phase
graph under a persistent checkpointer, writes artifacts, and tracks session
status. Used by ``argus run``, ``argus scan``, and ``argus resume``.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Optional

from argus.core import hints, paths, report as report_mod, sessions
from argus.core.graph import build_graph
from argus.core.modelplan import ModelPlan
from argus.core.recipe import Recipe
from argus.core.scope import Scope
from argus.core.state import RunConfig, RunState, results_from_state, weaknesses_from_state
from argus.phases import runner
from argus.ui import progress


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
    plan: Optional["ModelPlan"] = None,
    skills: str = "",
) -> RunConfig:
    rid = run_id or new_run_id()
    run_dir = str(paths.run_dir(rid))
    params = recipe.parameters or {}
    plan = plan or ModelPlan(primary=model, ensemble=[model])
    return RunConfig(
        run_id=rid,
        target=target,
        model=plan.primary,
        models=plan.ensemble if plan.is_ensemble or plan.mode == "per-phase" else [],
        multi_mode=plan.mode,
        phase_models=plan.phase_models,
        consensus_quorum=plan.quorum,
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
        skills=skills,
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
        scope_name=scope.engagement,
    )
    sessions.save_meta(meta)

    checkpointer = sessions.make_checkpointer()
    graph = build_graph(checkpointer=checkpointer)
    state = initial_state(cfg, scope)
    reporter = progress.RunProgress(runner.planned_tools(cfg))
    progress.set_active(reporter)
    try:
        final: RunState = graph.invoke(state, config=sessions.thread_config(cfg.run_id))
    except Exception:
        sessions.update_status(cfg.run_id, "error")
        raise
    finally:
        reporter.finish()
        progress.clear_active()
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


def _write_results_source(
    run_path: Path, run_id: str, target: str, scope_name: str,
    results: list, weaknesses: list, phase_log: list[str],
) -> None:
    """Persist the faithful re-render source of truth (raw results + weaknesses)."""
    source = {
        "run_id": run_id,
        "target": target,
        "scope_name": scope_name,
        "results": [r.model_dump(mode="json") for r in results],
        "weaknesses": [w.model_dump(mode="json") for w in weaknesses],
        "phase_log": phase_log,
    }
    (run_path / "results.json").write_text(
        json.dumps(source, indent=2), encoding="utf-8"
    )


def _persist_artifacts(cfg: RunConfig, final: RunState) -> None:
    results = results_from_state(final)
    weaknesses = weaknesses_from_state(final)
    run_path = paths.run_dir(cfg.run_id)
    scope_name = _scope_name_for(cfg.run_id)

    _write_results_source(
        run_path, cfg.run_id, cfg.target, scope_name, results, weaknesses,
        final.get("phase_log", []),
    )
    # Aggregate summary (machine-readable, stable name) + shareable deliverables.
    (run_path / "report.json").write_text(
        report_mod.to_json(cfg.run_id, cfg.target, results, weaknesses=weaknesses),
        encoding="utf-8",
    )
    _write_deliverables(
        run_path, cfg.run_id, cfg.target, scope_name, results, weaknesses,
        markdown=final.get("report_markdown"), fmt="both",
    )
    (run_path / "run.log").write_text("\n".join(final.get("phase_log", [])), encoding="utf-8")


def _persist_artifacts_from_meta(run_id: str, final: RunState) -> None:
    meta = sessions.load_meta(run_id)
    target = meta.target if meta else run_id
    results = results_from_state(final)
    weaknesses = weaknesses_from_state(final)
    run_path = paths.run_dir(run_id)
    scope_name = meta.scope_name if meta else ""

    _write_results_source(
        run_path, run_id, target, scope_name, results, weaknesses,
        final.get("phase_log", []),
    )
    (run_path / "report.json").write_text(
        report_mod.to_json(run_id, target, results, weaknesses=weaknesses),
        encoding="utf-8",
    )
    _write_deliverables(
        run_path, run_id, target, scope_name, results, weaknesses,
        markdown=final.get("report_markdown"), fmt="both",
    )


def _scope_name_for(run_id: str) -> str:
    meta = sessions.load_meta(run_id)
    return meta.scope_name if meta else ""


def _write_deliverables(
    run_path: Path, run_id: str, target: str, scope_name: str,
    results: list, weaknesses: list, *, markdown: str | None = None, fmt: str = "both",
) -> list[Path]:
    """Write timestamped ``.md`` and/or ``.html`` deliverables; return their paths."""
    base = report_mod.timestamped_name(report_mod.report_basename(scope_name, target))
    written: list[Path] = []
    if fmt in ("md", "both"):
        md = markdown or report_mod.to_markdown(
            run_id, target, results, weaknesses=weaknesses
        )
        p = run_path / f"{base}.md"
        p.write_text(md, encoding="utf-8")
        written.append(p)
    if fmt in ("html", "both"):
        html = report_mod.to_html(run_id, target, results, weaknesses=weaknesses)
        p = run_path / f"{base}.html"
        p.write_text(html, encoding="utf-8")
        written.append(p)
    return written


def write_reports(run_id: str, fmt: str = "both") -> list[Path]:
    """Re-render a finished run's report(s) from ``results.json`` and write them.

    Returns the paths of the freshly written deliverables. ``fmt`` is
    ``md`` | ``html`` | ``both``.
    """
    from argus.core.models import ExtensionResult, Weakness

    run_path = paths.run_dir(run_id)
    source_path = run_path / "results.json"
    if not source_path.exists():
        raise FileNotFoundError(
            f"no results.json for run {run_id} (looked in {run_path}); "
            "cannot re-render — run the scan first"
        )
    data = json.loads(source_path.read_text(encoding="utf-8"))
    results = [ExtensionResult(**r) for r in data.get("results", [])]
    weaknesses = [Weakness(**w) for w in data.get("weaknesses", [])]
    return _write_deliverables(
        run_path, run_id, data.get("target", run_id), data.get("scope_name", ""),
        results, weaknesses, fmt=fmt,
    )
