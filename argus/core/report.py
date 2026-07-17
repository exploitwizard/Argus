"""Report rendering — deterministic Markdown/JSON from run results.

Phase 6 composes the report. The structured Markdown/JSON here is always
produced deterministically from typed results (so it works offline and in
tests). When a live model is configured, the report node may prepend an LLM
executive summary; that step is optional and degrades to this deterministic
report on any failure.
"""

from __future__ import annotations

import json
from collections import Counter

from argus.core.models import ExtensionResult

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def aggregate(results: list[ExtensionResult]) -> dict:
    """Collapse per-extension results into a de-duplicated summary dict."""
    subs = sorted({s.host for r in results for s in r.subdomains})
    hosts = sorted({h.url for r in results for h in r.live_hosts})
    ports = sorted({f"{p.host}:{p.port}" for r in results for p in r.open_ports})
    takeovers = sorted({t.host for r in results for t in r.takeovers if t.vulnerable})
    urls = sorted({u.url for r in results for u in r.urls})
    js = sorted({e.endpoint for r in results for e in r.js_endpoints})
    secrets = [
        {"detector": s.detector, "location": s.location, "verified": s.verified}
        for r in results
        for s in r.secrets
    ]
    params = sorted({f"{p.url}?{p.param}" for r in results for p in r.params})
    findings = [
        {
            "template_id": f.template_id,
            "name": f.name,
            "severity": f.severity,
            "matched_at": f.matched_at,
        }
        for r in results
        for f in r.findings
    ]
    findings.sort(key=lambda f: _SEV_ORDER.get(f["severity"], 5))
    sev_counts = Counter(f["severity"] for f in findings)
    return {
        "subdomains": subs,
        "live_hosts": hosts,
        "open_ports": ports,
        "takeovers": takeovers,
        "urls": urls,
        "js_endpoints": js,
        "secrets": secrets,
        "params": params,
        "findings": findings,
        "severity_counts": dict(sev_counts),
    }


def to_json(run_id: str, target: str, results: list[ExtensionResult]) -> str:
    data = {"run_id": run_id, "target": target, **aggregate(results)}
    return json.dumps(data, indent=2)


def to_markdown(
    run_id: str,
    target: str,
    results: list[ExtensionResult],
    *,
    summary: str = "",
) -> str:
    agg = aggregate(results)
    lines: list[str] = [
        f"# ARGUS Recon Report — {target}",
        "",
        f"- **Run ID:** `{run_id}`",
        f"- **Target:** {target}",
        "- **Scope:** authorized recon & detection only (no exploitation)",
        "",
    ]
    if summary:
        lines += ["## Executive summary", "", summary.strip(), ""]

    lines += ["## Overview", ""]
    lines += [
        f"- Subdomains discovered: **{len(agg['subdomains'])}**",
        f"- Live web hosts: **{len(agg['live_hosts'])}**",
        f"- Open web ports: **{len(agg['open_ports'])}**",
        f"- URLs harvested: **{len(agg['urls'])}**",
        f"- JS endpoints: **{len(agg['js_endpoints'])}**",
        f"- Hidden params: **{len(agg['params'])}**",
        f"- Potential takeovers: **{len(agg['takeovers'])}**",
        f"- Secret hits (metadata only): **{len(agg['secrets'])}**",
        f"- Findings: **{len(agg['findings'])}** {dict(agg['severity_counts'])}",
        "",
    ]

    if agg["takeovers"]:
        lines += ["## Potential subdomain takeovers", ""]
        lines += [f"- `{h}`" for h in agg["takeovers"]] + [""]

    if agg["findings"]:
        lines += ["## Findings (detection only)", "", "| Severity | Name | Matched At |", "|---|---|---|"]
        for f in agg["findings"]:
            lines.append(f"| {f['severity']} | {f['name']} | `{f['matched_at']}` |")
        lines.append("")

    if agg["secrets"]:
        lines += ["## Secret exposure (metadata only — values never stored)", ""]
        lines += ["| Detector | Location | Verified |", "|---|---|---|"]
        for s in agg["secrets"]:
            lines.append(f"| {s['detector']} | `{s['location']}` | {s['verified']} |")
        lines.append("")

    if agg["live_hosts"]:
        lines += ["## Live hosts", ""] + [f"- {h}" for h in agg["live_hosts"][:200]] + [""]

    return "\n".join(lines)
