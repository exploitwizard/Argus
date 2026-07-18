"""Report rendering tests — aggregation, dedupe, severity ordering, JSON."""

from __future__ import annotations

import json

from argus.core import report
from argus.core.models import Reference, Weakness
from argus.extensions import get
from conftest import load_fixture


def _weaknesses():
    return [
        Weakness(
            title="Apache Log4j RCE", affected_asset="https://api.example.com/x",
            owasp_category="A06:2025 Vulnerable and Outdated Components", cwe="CWE-1035",
            severity="critical", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            confidence="high", evidence="nuclei matched CVE-2021-44228",
            reproduction_steps=["Send the probe", "Observe the callback"],
            proof_of_concept="curl -sI https://api.example.com/x",
            impact="Remote code execution.", remediation="Upgrade Log4j to 2.17+.",
            references=[Reference(url="https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                                  title="CVE-2021-44228", source="NVD")],
            source_models=["mock/model"],
        ),
        Weakness(
            title="Exposed .git", affected_asset="https://dev.example.com/.git/",
            owasp_category="A01:2025 Broken Access Control", cwe="CWE-200",
            severity="medium", confidence="medium", evidence="dir listing",
        ),
    ]


def _results():
    return [
        get("subfinder").parse(load_fixture("subfinder.txt")),
        get("httpx").parse(load_fixture("httpx.jsonl")),
        get("subzy").parse(load_fixture("subzy.txt")),
        get("nuclei").parse(load_fixture("nuclei.jsonl")),
        get("trufflehog").parse(load_fixture("trufflehog.jsonl")),
    ]


def test_aggregate_dedupes_and_counts():
    agg = report.aggregate(_results())
    assert "www.example.com" in agg["subdomains"]
    assert agg["severity_counts"]["critical"] == 1
    assert len(agg["takeovers"]) == 2


def test_findings_sorted_by_severity():
    agg = report.aggregate(_results())
    severities = [f["severity"] for f in agg["findings"]]
    # critical must come before medium/info
    assert severities.index("critical") < severities.index("info")


def test_markdown_has_sections_and_hides_secret_value():
    md = report.to_markdown("run123", "example.com", _results(), summary="All good.")
    assert "# ARGUS Recon Report — example.com" in md
    assert "Executive summary" in md
    assert "Findings (detection only)" in md
    assert "AKIAEXAMPLE" not in md  # secret value never rendered


def test_json_is_valid_and_structured():
    js = report.to_json("run123", "example.com", _results())
    data = json.loads(js)
    assert data["run_id"] == "run123"
    assert data["target"] == "example.com"
    assert isinstance(data["findings"], list)


# ---- Weaknesses and Vulnerabilities section (Task 2) -------------------- #
def test_weaknesses_section_has_summary_table_and_all_fields():
    section = report.render_weaknesses_section(_weaknesses())
    assert "## Weaknesses and Vulnerabilities" in section
    # severity-sorted summary table leads, critical first
    assert section.index("critical") < section.index("medium")
    assert "| # | Severity | Title |" in section
    # every field renders
    for token in [
        "Steps to reproduce", "Proof of concept", "Impact:", "Remediation:",
        "References", "A06:2025 Vulnerable and Outdated Components", "CWE-1035",
        "CVSS:3.1", "nvd.nist.gov", "Flagged by model(s):", "mock/model",
    ]:
        assert token in section, token


def test_weaknesses_section_empty_is_explicit():
    section = report.render_weaknesses_section([])
    assert "## Weaknesses and Vulnerabilities" in section
    assert "No weaknesses were flagged" in section


def test_markdown_and_json_both_carry_weaknesses():
    md = report.to_markdown("r", "example.com", _results(), weaknesses=_weaknesses())
    assert "## Weaknesses and Vulnerabilities" in md
    assert "Apache Log4j RCE" in md

    data = json.loads(report.to_json("r", "example.com", _results(), weaknesses=_weaknesses()))
    assert len(data["weaknesses"]) == 2
    assert data["weaknesses"][0]["severity"] == "critical"  # sorted
    assert data["weaknesses"][0]["references"][0]["source"] == "NVD"


# ---- report naming (Task 3) --------------------------------------------- #
def test_slugify_sanitizes():
    assert report.slugify("Example Corp bug bounty") == "example-corp-bug-bounty"
    assert report.slugify("api.example.com") == "api-example-com"
    assert report.slugify("  !!!  ") == "report"  # empty -> fallback
    assert len(report.slugify("x" * 200)) <= 60


def test_report_basename_prefers_scope_name_else_target():
    # a real engagement name wins
    assert report.report_basename("Example Corp bug bounty", "example.com") == \
        "argus_report_example-corp-bug-bounty"
    # placeholder engagement (implicit-scope) falls back to the target
    assert report.report_basename("implicit-scope", "api.example.com") == \
        "argus_report_api-example-com"
    assert report.report_basename("unspecified", "example.com") == \
        "argus_report_example-com"


def test_timestamped_name_appends_stamp():
    from datetime import datetime
    name = report.timestamped_name("argus_report_x", when=datetime(2026, 7, 18, 9, 30, 15))
    assert name == "argus_report_x_20260718-093015"


# ---- self-contained HTML (Task 3) --------------------------------------- #
def test_html_is_self_contained_and_styled():
    html = report.to_html("run123", "example.com", _results(), weaknesses=_weaknesses())
    assert html.startswith("<!doctype html>")
    assert "</html>" in html
    assert "<style>" in html and "</style>" in html          # inline CSS
    # self-contained: no external asset LOADS (css/js/fonts/images/cdn).
    # Reference hyperlinks (<a href="http...">) to advisories are allowed.
    assert 'src="http' not in html                           # no remote images/scripts
    assert "<link" not in html                               # no external stylesheet
    assert "<script" not in html                             # no scripts at all
    assert "@import" not in html
    assert "cdn" not in html.lower()
    # VAPT look + flagship section rendered as cards/table
    assert "Weaknesses and Vulnerabilities" in html
    assert 'class="card"' in html
    assert "Apache Log4j RCE" in html
    # secret value never rendered
    assert "AKIAEXAMPLE" not in html


def test_html_severity_badges_and_toc():
    html = report.to_html("r", "example.com", _results(), weaknesses=_weaknesses())
    assert "Contents" in html and 'href="#weaknesses"' in html
    assert 'class="badge"' in html
