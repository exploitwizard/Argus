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


def _rich_results():
    """Results that populate the discovered-asset inventory (urls, js, ports…)."""
    return [
        get("subfinder").parse(load_fixture("subfinder.txt")),
        get("naabu").parse(load_fixture("naabu.txt")),
        get("httpx").parse(load_fixture("httpx.jsonl")),
        get("gau").parse(load_fixture("gau.txt")),
        get("katana").parse(load_fixture("katana.txt")),
        get("linkfinder").parse(load_fixture("linkfinder.txt")),
    ]


def test_report_lists_every_discovered_asset_not_just_counts():
    results = _rich_results()
    agg = report.aggregate(results)
    assert agg["urls"] and agg["js_endpoints"] and agg["subdomains"] and agg["open_ports"]

    md = report.to_markdown("r", "example.com", results)
    # Titled sections with the real counts, not bare numbers in the overview.
    assert f"## URLs harvested ({len(agg['urls'])})" in md
    assert f"## JS endpoints ({len(agg['js_endpoints'])})" in md
    assert f"## Subdomains ({len(agg['subdomains'])})" in md
    assert f"## Open web ports ({len(agg['open_ports'])})" in md
    # The actual items are listed, not summarized away.
    assert agg["urls"][0] in md
    assert agg["js_endpoints"][0] in md

    html = report.to_html("r", "example.com", results)
    assert 'id="urls"' in html and 'id="js"' in html and 'id="subdomains"' in html
    assert f"URLs harvested ({len(agg['urls'])})" in html


def test_live_hosts_render_with_probe_metadata():
    results = _rich_results()
    md = report.to_markdown("r", "example.com", results)
    assert "| URL | Status | Title | Server | Tech |" in md
    rows = report.live_host_details(results)
    assert rows and {"url", "status", "title", "webserver", "tech"} <= rows[0].keys()
    # status code and tech make it into the rendered table
    assert "403" in md and "Cloudflare" in md


def test_findings_overview_has_no_empty_dict():
    # The old bug printed "Findings: 0 {}" — the empty severity dict leaked.
    for renderer in (report.to_markdown, report.to_html):
        out = renderer("r", "example.com", _rich_results())
        assert "{}" not in out


def test_severity_summary_formats_and_empty():
    assert report._severity_summary({}) == ""
    assert report._severity_summary({"medium": 2, "critical": 1}) == " (critical: 1, medium: 2)"


def _results_with_screenshot(png_path: str):
    from argus.core.models import ExtensionResult, Phase, Screenshot
    return [ExtensionResult(
        extension="gowitness", phase=Phase.VULN_SCAN,
        screenshots=[Screenshot(url="https://www.example.com", path=png_path)],
    )]


def test_html_embeds_screenshot_as_self_contained_image(tmp_path):
    # A real 1x1 PNG so the report base64-embeds it (portable, no external load).
    png = tmp_path / "shot.png"
    png.write_bytes(bytes.fromhex(
        "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4"
        "890000000a49444154789c6360000002000154a24f9f0000000049454e44ae426082"
    ))
    results = _results_with_screenshot(str(png))
    html = report.to_html("r", "example.com", results)
    assert 'id="screenshots"' in html
    assert 'src="data:image/png;base64,' in html   # embedded, self-contained
    assert 'src="http' not in html                  # still no external loads
    assert 'class="gallery"' in html


def test_html_screenshot_falls_back_to_relative_when_missing():
    results = _results_with_screenshot("/no/such/dir/missing.png")
    html = report.to_html("r", "example.com", results)
    assert 'src="screenshots/missing.png"' in html   # relative, not http
    assert 'src="http' not in html


def test_markdown_lists_screenshots_with_image_syntax():
    results = _results_with_screenshot("/runs/x/screenshots/a.png")
    md = report.to_markdown("r", "example.com", results)
    assert "## Screenshots (1)" in md
    assert "![https://www.example.com](screenshots/a.png)" in md


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
