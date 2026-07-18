"""Phase nodes for the LangGraph pipeline.

Nodes 1–5 run tools via :mod:`argus.phases.runner`. A human-in-the-loop gate
sits before Phase 2 (the first phase that touches the live target). Node 6
composes the report.
"""

from __future__ import annotations

from argus.core import report as report_mod
from argus.core.state import (
    RunState,
    config_from_state,
    results_from_state,
    scope_from_state,
    weaknesses_from_state,
)
from argus.phases.runner import run_tool_phase


def phase1(state: RunState) -> dict:
    return run_tool_phase(state, 1)


def phase2(state: RunState) -> dict:
    return run_tool_phase(state, 2)


def phase3(state: RunState) -> dict:
    return run_tool_phase(state, 3)


def phase4(state: RunState) -> dict:
    return run_tool_phase(state, 4)


def phase5(state: RunState) -> dict:
    return run_tool_phase(state, 5)


def gate(state: RunState) -> dict:
    """Human-in-the-loop gate before any live-traffic phase.

    The interactive prompt lives in the CLI; by the time the graph runs, the
    decision has been made (``assume_yes`` or ``dry_run`` both pass). This node
    records the decision into state so a resumed run knows the gate cleared.
    """
    cfg = config_from_state(state)
    passed = cfg.dry_run or cfg.assume_yes or state.get("gate_passed", False)
    return {"gate_passed": passed, "aborted": not passed}


def triage(state: RunState) -> dict:
    """Post–Phase-5 analysis: turn raw evidence into structured weaknesses.

    Offline / dry-run produces deterministic candidates; a live model enriches
    them with reproduction steps, safe PoCs, remediation, and cited research.
    Runs before reporting so every format renders the same findings.
    """
    from argus.core import triage as triage_mod

    cfg = config_from_state(state)
    scope = scope_from_state(state)
    results = results_from_state(state)
    weaknesses = triage_mod.triage_run(
        results, cfg.target, scope,
        model=cfg.model,
        models=cfg.models or None,
        quorum=cfg.consensus_quorum,
        concurrency=scope.limits.max_concurrency,
        dry_run=cfg.dry_run,
    )
    enriched = sum(1 for w in weaknesses if w.enriched)
    review = sum(1 for w in weaknesses if w.needs_manual_review)
    mode = "ensemble" if (cfg.models and cfg.multi_mode == "ensemble") else "single"
    log = (
        f"Triage ({mode}): {len(weaknesses)} weakness(es) documented"
        + (f", {enriched} enriched" if enriched else " (deterministic)")
        + (f", {review} need manual review" if review else "")
    )
    return {
        "weaknesses": [w.model_dump(mode="json") for w in weaknesses],
        "phase_log": [log],
    }


def phase6_report(state: RunState) -> dict:
    """Compose the Markdown report from typed results (deterministic)."""
    cfg = config_from_state(state)
    if 6 not in cfg.phases:
        return {"phase_log": ["Phase 6 (Reporting): skipped (not in recipe)"]}
    results = results_from_state(state)
    weaknesses = weaknesses_from_state(state)
    summary = ""
    md = report_mod.to_markdown(
        cfg.run_id, cfg.target, results, summary=summary, weaknesses=weaknesses
    )
    return {"report_markdown": md, "phase_log": ["Phase 6 (Reporting): report composed"]}
