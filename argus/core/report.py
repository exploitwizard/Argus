"""Report rendering — deterministic Markdown/JSON from run results.

Phase 6 composes the report. The structured Markdown/JSON here is always
produced deterministically from typed results (so it works offline and in
tests). When a live model is configured, the report node may prepend an LLM
executive summary; that step is optional and degrades to this deterministic
report on any failure.
"""

from __future__ import annotations

import html as _html
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

from argus.core.models import ExtensionResult, Weakness

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

# Engagement labels that aren't real names — fall back to the target instead.
_PLACEHOLDER_ENGAGEMENTS = {
    "", "unspecified", "implicit-scope", "dry-run (synthesized scope)",
}

# Cap how many raw items a human-readable report lists per section. The complete
# set always lives in report.json, so a 50k-URL crawl can't produce a giant .md.
MAX_LIST = 1000


def _severity_summary(sev_counts: dict[str, int]) -> str:
    """Compact severity breakdown like `` (critical: 1, medium: 2)`` — ``""`` if empty."""
    if not sev_counts:
        return ""
    ordered = sorted(sev_counts.items(), key=lambda kv: _SEV_ORDER.get(kv[0], 5))
    return " (" + ", ".join(f"{k}: {v}" for k, v in ordered) + ")"


def _md_list_section(title: str, items: list[str]) -> list[str]:
    """Markdown lines for a titled, monospaced bullet list (empty -> no section)."""
    if not items:
        return []
    out = [f"## {title} ({len(items)})", ""]
    out += [f"- `{it}`" for it in items[:MAX_LIST]]
    if len(items) > MAX_LIST:
        out.append(f"- _…and {len(items) - MAX_LIST} more — see `report.json` for the full list._")
    out.append("")
    return out


# --------------------------------------------------------------------------- #
# Report naming (Task 3)
# --------------------------------------------------------------------------- #
def slugify(text: str, *, max_len: int = 60) -> str:
    """Sanitize arbitrary text into a filesystem-safe slug.

    Lowercases, replaces any run of non-alphanumerics with a single ``-``, and
    trims to ``max_len``. Empty input yields ``"report"``.
    """
    slug = re.sub(r"[^a-z0-9]+", "-", text.strip().lower()).strip("-")
    slug = slug[:max_len].strip("-")
    return slug or "report"


def report_basename(scope_name: str, target: str) -> str:
    """Base filename (no extension, no timestamp) for a run's report.

    Uses the scope's engagement name when it's a real name; otherwise the target
    (implicit-scope mode). Returns ``argus_report_<slug>``.
    """
    source = target if scope_name.strip().lower() in _PLACEHOLDER_ENGAGEMENTS else scope_name
    return f"argus_report_{slugify(source)}"


def timestamped_name(basename: str, *, when: datetime | None = None) -> str:
    """Append a ``_YYYYMMDD-HHMMSS`` timestamp to a report basename."""
    stamp = (when or datetime.now()).strftime("%Y%m%d-%H%M%S")
    return f"{basename}_{stamp}"


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
    screenshots = sorted({s.path for r in results for s in r.screenshots})
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
        "screenshots": screenshots,
        "findings": findings,
        "severity_counts": dict(sev_counts),
    }


def live_host_details(results: list[ExtensionResult]) -> list[dict]:
    """De-duplicated live-host rows (url, status, title, webserver, tech).

    Unlike ``aggregate()['live_hosts']`` (URLs only), this keeps the probe
    metadata so the report can show a proper table. First occurrence wins.
    """
    seen: dict[str, dict] = {}
    for r in results:
        for h in r.live_hosts:
            if h.url not in seen:
                seen[h.url] = {
                    "url": h.url,
                    "status": h.status_code,
                    "title": h.title or "",
                    "webserver": h.webserver or "",
                    "tech": ", ".join(h.tech),
                }
    return [seen[u] for u in sorted(seen)]


def sort_weaknesses(weaknesses: list[Weakness]) -> list[Weakness]:
    return sorted(weaknesses, key=lambda w: _SEV_ORDER.get(w.severity, 5))


def render_weaknesses_section(weaknesses: list[Weakness]) -> str:
    """Render the 'Weaknesses and Vulnerabilities' section.

    Every flagged item is listed with all fields; a severity-sorted summary
    table leads. Nothing is omitted.
    """
    lines: list[str] = ["## Weaknesses and Vulnerabilities", ""]
    if not weaknesses:
        lines += ["_No weaknesses were flagged in this run._", ""]
        return "\n".join(lines)

    items = sort_weaknesses(weaknesses)
    lines += [
        f"_{len(items)} flagged item(s). Documented for responsible disclosure — "
        "detection & verification only, no exploitation._",
        "",
        "| # | Severity | Title | Affected asset | OWASP (2025) | CWE | Confidence |",
        "|---|---|---|---|---|---|---|",
    ]
    for i, w in enumerate(items, 1):
        lines.append(
            f"| {i} | {w.severity} | {w.title} | `{w.affected_asset}` | "
            f"{w.owasp_category} | {w.cwe} | {w.confidence} |"
        )
    lines.append("")

    for i, w in enumerate(items, 1):
        lines += [f"### {i}. {w.title}", ""]
        lines += [
            f"- **Affected asset:** `{w.affected_asset}`",
            f"- **Severity:** {w.severity}"
            + (f"  (`{w.cvss_vector}`)" if w.cvss_vector else ""),
            f"- **OWASP Top-10 (2025):** {w.owasp_category}",
            f"- **CWE:** {w.cwe or '—'}",
            f"- **Confidence:** {w.confidence}",
        ]
        if w.needs_manual_review:
            lines.append("- **⚠ Needs manual review** (models disagreed or low confidence)")
        if w.source_models:
            lines.append(f"- **Flagged by model(s):** {', '.join(w.source_models)}")
        lines += ["", "**Evidence**", "", "```", w.evidence.strip() or "(none)", "```", ""]

        lines += ["**Steps to reproduce**", ""]
        if w.reproduction_steps:
            lines += [f"{n}. {s}" for n, s in enumerate(w.reproduction_steps, 1)]
        else:
            lines.append("_Not yet documented (enable a model to enrich this finding)._")
        lines.append("")

        lines += ["**Proof of concept (safe verification)**", ""]
        lines += ["```", (w.proof_of_concept.strip() or "(not provided)"), "```", ""]

        lines += [f"**Impact:** {w.impact.strip() or '—'}", ""]
        lines += [f"**Remediation:** {w.remediation.strip() or '—'}", ""]

        lines += ["**References**", ""]
        if w.references:
            for ref in w.references:
                label = ref.title or ref.url
                src = f" — {ref.source}" if ref.source else ""
                lines.append(f"- [{label}]({ref.url}){src}")
        else:
            lines.append("_No external sources cited._")
        lines += ["", "---", ""]

    return "\n".join(lines)


def _weakness_json(weaknesses: list[Weakness]) -> list[dict]:
    return [w.model_dump(mode="json") for w in sort_weaknesses(weaknesses)]


def to_json(
    run_id: str,
    target: str,
    results: list[ExtensionResult],
    *,
    weaknesses: list[Weakness] | None = None,
) -> str:
    data = {"run_id": run_id, "target": target, **aggregate(results)}
    data["weaknesses"] = _weakness_json(weaknesses or [])
    return json.dumps(data, indent=2)


def to_markdown(
    run_id: str,
    target: str,
    results: list[ExtensionResult],
    *,
    summary: str = "",
    weaknesses: list[Weakness] | None = None,
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
        f"- Screenshots captured: **{len(agg['screenshots'])}**",
        f"- Potential takeovers: **{len(agg['takeovers'])}**",
        f"- Secret hits (metadata only): **{len(agg['secrets'])}**",
        f"- Findings: **{len(agg['findings'])}**{_severity_summary(agg['severity_counts'])}",
        "",
    ]

    # The flagship section: every AI-triaged weakness, with all fields.
    lines += [render_weaknesses_section(weaknesses or []), ""]

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

    # ---- discovered assets — the full recon inventory --------------------- #
    lines += _md_list_section("Subdomains", agg["subdomains"])
    lines += _md_list_section("Open web ports", agg["open_ports"])

    hosts = live_host_details(results)
    if hosts:
        lines += [f"## Live hosts ({len(hosts)})", "",
                  "| URL | Status | Title | Server | Tech |", "|---|---|---|---|---|"]
        for h in hosts[:MAX_LIST]:
            title = str(h["title"]).replace("|", "\\|")
            tech = str(h["tech"]).replace("|", "\\|")
            status = "" if h["status"] is None else h["status"]
            lines.append(f"| {h['url']} | {status} | {title} | {h['webserver']} | {tech} |")
        if len(hosts) > MAX_LIST:
            lines.append(f"\n_…and {len(hosts) - MAX_LIST} more — see `report.json`._")
        lines.append("")

    lines += _md_list_section("URLs harvested", agg["urls"])
    lines += _md_list_section("JS endpoints", agg["js_endpoints"])
    lines += _md_list_section("Hidden parameters", agg["params"])
    lines += _md_list_section("Screenshots", agg["screenshots"])

    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Self-contained HTML report (Task 3)
# --------------------------------------------------------------------------- #
_SEV_COLORS = {
    "critical": "#ff4d4d", "high": "#ff7a45", "medium": "#ffb020",
    "low": "#4da3ff", "info": "#8a8f98", "unknown": "#8a8f98",
}

_CSS = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin: 0; background: #16181d; color: #d6d9df;
  font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.55; }
.wrap { max-width: 960px; margin: 0 auto; padding: 2.5rem 1.5rem 4rem; }
h1, h2, h3 { color: #ff5555; font-weight: 700; letter-spacing: .3px; }
h1 { font-size: 1.9rem; border-bottom: 2px solid #ff5555; padding-bottom: .5rem; }
h2 { font-size: 1.35rem; margin-top: 2.5rem; border-left: 4px solid #ff5555;
  padding-left: .6rem; }
h3 { font-size: 1.1rem; color: #f2f3f5; }
a { color: #6db3ff; }
code, pre, .mono { font-family: SFMono-Regular, Menlo, Consolas, monospace; }
pre.evidence { background: #0e0f12; border: 1px solid #2a2d34; border-radius: 6px;
  padding: .8rem 1rem; overflow-x: auto; font-size: .85rem; color: #b9c0cc;
  white-space: pre-wrap; word-break: break-word; }
.meta { color: #8a8f98; font-size: .9rem; }
.badge { display: inline-block; padding: .1rem .55rem; border-radius: 999px;
  font-size: .72rem; font-weight: 700; text-transform: uppercase; color: #16181d; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; font-size: .9rem; }
th, td { border: 1px solid #2a2d34; padding: .45rem .6rem; text-align: left;
  vertical-align: top; }
th { background: #23262d; color: #f2f3f5; }
tr:nth-child(even) td { background: #1b1e24; }
.toc { background: #1b1e24; border: 1px solid #2a2d34; border-radius: 8px;
  padding: 1rem 1.4rem; }
.toc ul { margin: .3rem 0; padding-left: 1.2rem; }
.card { background: #1b1e24; border: 1px solid #2a2d34; border-left: 4px solid #ff5555;
  border-radius: 8px; padding: 1rem 1.3rem; margin: 1.2rem 0; }
.card h3 { margin-top: 0; }
.kv { margin: .15rem 0; }
.kv b { color: #f2f3f5; }
.review { color: #ffb020; font-weight: 700; }
.note { color: #8a8f98; font-style: italic; }
.disclaimer { color: #8a8f98; font-size: .85rem; border-top: 1px solid #2a2d34;
  margin-top: 3rem; padding-top: 1rem; }
img.shot { max-width: 100%; border: 1px solid #2a2d34; border-radius: 6px;
  margin: .5rem 0; }
""".strip()


def _esc(text: str) -> str:
    return _html.escape(str(text), quote=True)


def _html_list_section(title: str, anchor: str, items: list[str]) -> str:
    """A titled monospaced <ul> for a discovered-asset list (empty -> '')."""
    if not items:
        return ""
    lis = "".join(f"<li class='mono'>{_esc(it)}</li>" for it in items[:MAX_LIST])
    more = ""
    if len(items) > MAX_LIST:
        more = (f'<p class="note">…and {len(items) - MAX_LIST} more — '
                "see report.json for the full list.</p>")
    return f'<h2 id="{anchor}">{_esc(title)} ({len(items)})</h2><ul>{lis}</ul>{more}'


def _sev_badge(sev: str) -> str:
    color = _SEV_COLORS.get(sev, "#8a8f98")
    return f'<span class="badge" style="background:{color}">{_esc(sev)}</span>'


def _weakness_cards_html(weaknesses: list[Weakness]) -> str:
    if not weaknesses:
        return '<p class="note">No weaknesses were flagged in this run.</p>'
    items = sort_weaknesses(weaknesses)
    parts: list[str] = [
        f'<p class="note">{len(items)} flagged item(s). Documented for responsible '
        "disclosure — detection &amp; verification only, no exploitation.</p>",
        "<table><thead><tr><th>#</th><th>Severity</th><th>Title</th>"
        "<th>Affected asset</th><th>OWASP (2025)</th><th>CWE</th><th>Confidence</th>"
        "</tr></thead><tbody>",
    ]
    for i, w in enumerate(items, 1):
        parts.append(
            f"<tr><td>{i}</td><td>{_sev_badge(w.severity)}</td><td>{_esc(w.title)}</td>"
            f"<td class='mono'>{_esc(w.affected_asset)}</td><td>{_esc(w.owasp_category)}</td>"
            f"<td>{_esc(w.cwe)}</td><td>{_esc(w.confidence)}</td></tr>"
        )
    parts.append("</tbody></table>")

    for i, w in enumerate(items, 1):
        parts.append(f'<div class="card" id="w-{i}">')
        parts.append(f"<h3>{i}. {_esc(w.title)} {_sev_badge(w.severity)}</h3>")
        parts.append(f'<p class="kv"><b>Affected asset:</b> <span class="mono">{_esc(w.affected_asset)}</span></p>')
        cvss = f' <span class="mono">({_esc(w.cvss_vector)})</span>' if w.cvss_vector else ""
        parts.append(f'<p class="kv"><b>Severity:</b> {_esc(w.severity)}{cvss}</p>')
        parts.append(f'<p class="kv"><b>OWASP Top-10 (2025):</b> {_esc(w.owasp_category)}</p>')
        parts.append(f'<p class="kv"><b>CWE:</b> {_esc(w.cwe or "—")}</p>')
        parts.append(f'<p class="kv"><b>Confidence:</b> {_esc(w.confidence)}</p>')
        if w.needs_manual_review:
            parts.append('<p class="review">⚠ Needs manual review (models disagreed or low confidence)</p>')
        if w.source_models:
            parts.append(f'<p class="kv"><b>Flagged by model(s):</b> {_esc(", ".join(w.source_models))}</p>')

        parts.append("<p class='kv'><b>Evidence</b></p>")
        parts.append(f'<pre class="evidence">{_esc(w.evidence.strip() or "(none)")}</pre>')
        parts += _screenshot_imgs(w.evidence)

        parts.append("<p class='kv'><b>Steps to reproduce</b></p>")
        if w.reproduction_steps:
            parts.append("<ol>" + "".join(f"<li>{_esc(s)}</li>" for s in w.reproduction_steps) + "</ol>")
        else:
            parts.append('<p class="note">Not yet documented (enable a model to enrich this finding).</p>')

        parts.append("<p class='kv'><b>Proof of concept (safe verification)</b></p>")
        parts.append(f'<pre class="evidence">{_esc(w.proof_of_concept.strip() or "(not provided)")}</pre>')
        parts.append(f'<p class="kv"><b>Impact:</b> {_esc(w.impact.strip() or "—")}</p>')
        parts.append(f'<p class="kv"><b>Remediation:</b> {_esc(w.remediation.strip() or "—")}</p>')

        parts.append("<p class='kv'><b>References</b></p>")
        if w.references:
            refs = "".join(
                f'<li><a href="{_esc(r.url)}">{_esc(r.title or r.url)}</a>'
                + (f" — {_esc(r.source)}" if r.source else "") + "</li>"
                for r in w.references
            )
            parts.append(f"<ul>{refs}</ul>")
        else:
            parts.append('<p class="note">No external sources cited.</p>')
        parts.append("</div>")
    return "\n".join(parts)


def _screenshot_imgs(evidence: str) -> list[str]:
    """Emit relatively-linked <img> tags for any screenshot path in the evidence."""
    imgs: list[str] = []
    for m in re.finditer(r"Screenshot:\s*(\S+)", evidence):
        rel = Path(m.group(1)).name  # link relatively by basename (self-contained)
        imgs.append(f'<img class="shot" src="{_esc(rel)}" alt="screenshot: {_esc(rel)}">')
    return imgs


def to_html(
    run_id: str,
    target: str,
    results: list[ExtensionResult],
    *,
    summary: str = "",
    weaknesses: list[Weakness] | None = None,
) -> str:
    """Render a fully self-contained HTML report (inline CSS, no external assets).

    Identical content to :func:`to_markdown`, styled in the charcoal/red VAPT
    house look with a table of contents and weaknesses as styled cards.
    """
    agg = aggregate(results)
    weaknesses = weaknesses or []
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    toc = ["<h2>Contents</h2>", '<div class="toc"><ul>']
    if summary:
        toc.append('<li><a href="#summary">Executive summary</a></li>')
    toc += [
        '<li><a href="#overview">Overview</a></li>',
        '<li><a href="#weaknesses">Weaknesses and Vulnerabilities</a></li>',
    ]
    if agg["takeovers"]:
        toc.append('<li><a href="#takeovers">Potential subdomain takeovers</a></li>')
    if agg["findings"]:
        toc.append('<li><a href="#findings">Findings (detection only)</a></li>')
    if agg["secrets"]:
        toc.append('<li><a href="#secrets">Secret exposure</a></li>')
    for _key, _anchor, _label in (
        ("subdomains", "subdomains", "Subdomains"),
        ("open_ports", "ports", "Open web ports"),
        ("live_hosts", "hosts", "Live hosts"),
        ("urls", "urls", "URLs harvested"),
        ("js_endpoints", "js", "JS endpoints"),
        ("params", "params", "Hidden parameters"),
        ("screenshots", "screenshots", "Screenshots"),
    ):
        if agg[_key]:
            toc.append(f'<li><a href="#{_anchor}">{_label}</a></li>')
    toc.append("</ul></div>")

    body: list[str] = [
        f"<h1>ARGUS Recon Report — {_esc(target)}</h1>",
        f'<p class="meta">Run ID <code>{_esc(run_id)}</code> · generated {generated} · '
        "authorized recon &amp; detection only (no exploitation)</p>",
        "\n".join(toc),
    ]
    if summary:
        body += [f'<h2 id="summary">Executive summary</h2><p>{_esc(summary.strip())}</p>']

    body.append('<h2 id="overview">Overview</h2>')
    body.append("<table><tbody>" + "".join(
        f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in [
            ("Subdomains discovered", len(agg["subdomains"])),
            ("Live web hosts", len(agg["live_hosts"])),
            ("Open web ports", len(agg["open_ports"])),
            ("URLs harvested", len(agg["urls"])),
            ("JS endpoints", len(agg["js_endpoints"])),
            ("Hidden params", len(agg["params"])),
            ("Screenshots captured", len(agg["screenshots"])),
            ("Potential takeovers", len(agg["takeovers"])),
            ("Secret hits (metadata only)", len(agg["secrets"])),
            ("Findings", f"{len(agg['findings'])}{_severity_summary(agg['severity_counts'])}"),
        ]
    ) + "</tbody></table>")

    body.append('<h2 id="weaknesses">Weaknesses and Vulnerabilities</h2>')
    body.append(_weakness_cards_html(weaknesses))

    if agg["takeovers"]:
        body.append('<h2 id="takeovers">Potential subdomain takeovers</h2>')
        body.append("<ul>" + "".join(f"<li class='mono'>{_esc(h)}</li>" for h in agg["takeovers"]) + "</ul>")

    if agg["findings"]:
        body.append('<h2 id="findings">Findings (detection only)</h2>')
        rows = "".join(
            f"<tr><td>{_sev_badge(f['severity'])}</td><td>{_esc(f['name'])}</td>"
            f"<td class='mono'>{_esc(f['matched_at'])}</td></tr>"
            for f in agg["findings"]
        )
        body.append(f"<table><thead><tr><th>Severity</th><th>Name</th><th>Matched at</th></tr></thead><tbody>{rows}</tbody></table>")

    if agg["secrets"]:
        body.append('<h2 id="secrets">Secret exposure (metadata only — values never stored)</h2>')
        rows = "".join(
            f"<tr><td>{_esc(s['detector'])}</td><td class='mono'>{_esc(s['location'])}</td>"
            f"<td>{_esc(s['verified'])}</td></tr>"
            for s in agg["secrets"]
        )
        body.append(f"<table><thead><tr><th>Detector</th><th>Location</th><th>Verified</th></tr></thead><tbody>{rows}</tbody></table>")

    body.append(_html_list_section("Subdomains", "subdomains", agg["subdomains"]))
    body.append(_html_list_section("Open web ports", "ports", agg["open_ports"]))

    hosts = live_host_details(results)
    if hosts:
        body.append(f'<h2 id="hosts">Live hosts ({len(hosts)})</h2>')
        rows = "".join(
            f"<tr><td class='mono'>{_esc(h['url'])}</td><td>{_esc('' if h['status'] is None else h['status'])}</td>"
            f"<td>{_esc(h['title'])}</td><td>{_esc(h['webserver'])}</td><td>{_esc(h['tech'])}</td></tr>"
            for h in hosts[:MAX_LIST]
        )
        body.append(
            "<table><thead><tr><th>URL</th><th>Status</th><th>Title</th>"
            f"<th>Server</th><th>Tech</th></tr></thead><tbody>{rows}</tbody></table>"
        )
        if len(hosts) > MAX_LIST:
            body.append(f'<p class="note">…and {len(hosts) - MAX_LIST} more — see report.json.</p>')

    body.append(_html_list_section("URLs harvested", "urls", agg["urls"]))
    body.append(_html_list_section("JS endpoints", "js", agg["js_endpoints"]))
    body.append(_html_list_section("Hidden parameters", "params", agg["params"]))
    body.append(_html_list_section("Screenshots", "screenshots", agg["screenshots"]))

    body.append(
        '<p class="disclaimer">Generated by ARGUS for authorized reconnaissance and '
        "responsible disclosure only. Findings document and verify weaknesses; the tool "
        "performs detection, not exploitation. Secret values are never captured or stored.</p>"
    )

    return (
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>ARGUS Report — {_esc(target)}</title>\n<style>\n{_CSS}\n</style>\n"
        f'</head>\n<body>\n<div class="wrap">\n{chr(10).join(body)}\n</div>\n</body>\n</html>\n'
    )
