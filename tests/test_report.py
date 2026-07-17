"""Report rendering tests — aggregation, dedupe, severity ordering, JSON."""

from __future__ import annotations

import json

from argus.core import report
from argus.extensions import get
from conftest import load_fixture


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
