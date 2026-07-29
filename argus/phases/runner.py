"""Phase execution — the bridge between the graph and the extension registry.

Each tool-running phase (1–5) uses the same logic: derive this phase's targets
from prior results, enforce scope, ask the registry for the phase's extensions
(recipe-selected or all available), run each, and merge typed results back into
the graph state. Phase 6 (reporting) is handled separately.
"""

from __future__ import annotations

from argus.core.models import ExtensionResult, Phase
from argus.core.scope import Scope
from argus.core.state import RunConfig, RunState, config_from_state, results_from_state, scope_from_state
from argus.extensions import ExtensionInputs, available_for_phase, get, has


def _known(results: list[ExtensionResult]) -> dict[str, list[str]]:
    subs = sorted({s.host for r in results for s in r.subdomains})
    hosts = sorted({h.url for r in results for h in r.live_hosts})
    urls = sorted({u.url for r in results for u in r.urls})
    return {"subdomains": subs, "live_hosts": hosts, "urls": urls}


def targets_for_phase(phase: int, cfg: RunConfig, known: dict[str, list[str]]) -> list[str]:
    """Compute the raw (pre-scope) target list a phase should act on."""
    if phase == Phase.ENUMERATION:
        return [cfg.target]
    if phase == Phase.HOST_DISCOVERY:
        return known["subdomains"] or [cfg.target]
    if phase == Phase.CONTENT_HARVEST:
        return known["live_hosts"] or [cfg.target]
    if phase == Phase.DEEP_ANALYSIS:
        return known["urls"] or known["live_hosts"]
    if phase == Phase.VULN_SCAN:
        return known["live_hosts"] or known["subdomains"] or [cfg.target]
    return []


def _select(phase: int, cfg: RunConfig) -> list:
    chosen = cfg.selected.get(phase)
    if chosen:
        exts = [get(n) for n in chosen if has(n)]
        return [e for e in exts if e.is_available()]
    return available_for_phase(phase)


def run_tool_phase(state: RunState, phase: int) -> dict:
    """Execute one tool-running phase; return the partial state update."""
    cfg = config_from_state(state)
    if phase not in cfg.phases:
        return {"phase_log": [f"Phase {phase} ({Phase(phase).label}): skipped (not in recipe)"]}
    scope: Scope = scope_from_state(state)
    prior = results_from_state(state)
    known = _known(prior)

    raw_targets = targets_for_phase(phase, cfg, known)
    in_scope, dropped = scope.filter(raw_targets)
    in_scope = in_scope[: scope.limits.max_hosts_per_phase]

    inputs = ExtensionInputs(
        targets=in_scope,
        run_dir=cfg.run_dir,
        wordlist=cfg.wordlist,
        resolvers=cfg.resolvers,
        rate_limit=scope.limits.requests_per_second,
        concurrency=scope.limits.max_concurrency,
        intensity=cfg.intensity,
        nuclei_templates=cfg.nuclei_templates,
    )

    result_dumps: list[dict] = []
    new_subs: list[str] = []
    new_hosts: list[str] = []
    ran_names: list[str] = []
    planned_names: list[str] = []
    noop_names: list[str] = []
    skipped: list[str] = []

    for ext in _select(phase, cfg):
        ext_inputs = inputs.model_copy(update={"extra_flags": cfg.flags.get(ext.name, [])})
        res = ext.run(ext_inputs, scope, dry_run=cfg.dry_run)
        result_dumps.append(res.model_dump(mode="json"))
        if not res.available:
            skipped.append(ext.name)
        elif res.ran:
            ran_names.append(ext.name)
            new_subs += [s.host for s in res.subdomains]
            new_hosts += [h.url for h in res.live_hosts]
        elif res.dry_run:
            planned_names.append(ext.name)  # command built, no traffic sent
        else:
            # available, but built no command (no in-scope targets / missing input)
            noop_names.append(ext.name)

    executed = f"planned {planned_names or '[]'}" if cfg.dry_run else f"ran {ran_names or '[]'}"
    parts = [f"{len(in_scope)} in-scope targets", executed]
    if noop_names:
        parts.append(f"no-op(no targets) {noop_names}")
    parts.append(f"skipped(unavailable) {skipped or '[]'}")
    parts.append(f"dropped {len(dropped)} out-of-scope")
    log = (
        f"Phase {phase} ({Phase(phase).label}): " + ", ".join(parts)
        + (" [DRY-RUN]" if cfg.dry_run else "")
    )

    return {
        "results": result_dumps,
        "subdomains": sorted(set(new_subs)),
        "live_hosts": sorted(set(new_hosts)),
        "dropped": dropped,
        "phase_log": [log],
    }
