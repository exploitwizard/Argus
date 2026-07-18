"""Graph wiring + full end-to-end run with every tool mocked (no network)."""

from __future__ import annotations

import pytest

from argus.core import agent, sessions
from argus.core.graph import build_graph
from argus.core.recipe import Recipe
from argus.core.scope import Scope
from conftest import load_fixture

_FIXTURES = {
    "subfinder": "subfinder.txt",
    "dnsx": "dnsx.txt",
    "httpx": "httpx.jsonl",
    "naabu": "naabu.txt",
    "subzy": "subzy.txt",
    "katana": "katana.txt",
    "gau": "gau.txt",
    "ffuf": "ffuf.json",
    "linkfinder": "linkfinder.txt",
    "trufflehog": "trufflehog.jsonl",
    "arjun": "arjun.json",
    "nuclei": "nuclei.jsonl",
    "gowitness": "gowitness.txt",
}

IN_SCOPE = Scope.from_dict(
    {"in_scope": {"domains": ["example.com", "*.example.com"]},
     "limits": {"max_hosts_per_phase": 50}}
)


@pytest.fixture
def mock_all_tools(monkeypatch):
    """Replace Extension.run so the pipeline runs offline off recorded output."""
    def fake_run(self, inputs, scope, *, dry_run=False, timeout=None):
        if self.name in _FIXTURES:
            res = self.parse(load_fixture(_FIXTURES[self.name]))
        else:
            from argus.core.models import ExtensionResult
            res = ExtensionResult(extension=self.name, phase=self.phase)
        res.available = True
        res.ran = not dry_run
        res.dry_run = dry_run
        return res

    # Force every tool available so the pipeline is deterministic on any machine.
    monkeypatch.setattr("argus.extensions.base.Extension.is_available", lambda self: True)
    monkeypatch.setattr("argus.extensions.base.Extension.run", fake_run)


def test_graph_has_expected_nodes_and_edges():
    g = build_graph().get_graph()
    nodes = set(g.nodes.keys())
    assert {"phase1", "gate", "phase2", "phase3", "phase4", "phase5",
            "triage", "report"} <= nodes


def test_full_run_end_to_end(mock_all_tools, monkeypatch):
    # Keep triage offline/deterministic: enrichment gets no usable JSON, so it
    # falls back to the deterministic candidates (no network call).
    monkeypatch.setattr("argus.core.llm.complete", lambda *a, **k: "")

    recipe = Recipe(name="e2e", intensity="med", phases=[1, 2, 3, 4, 5, 6])
    cfg = agent.build_run_config(
        recipe=recipe, target="example.com", model="test/model",
        scope=IN_SCOPE, dry_run=False, assume_yes=True,
    )
    final = agent.execute(cfg, IN_SCOPE)

    assert final.get("aborted") is False
    md = final["report_markdown"]
    assert "ARGUS Recon Report" in md
    assert "Apache Log4j RCE" in md            # nuclei finding surfaced
    assert "takeover.example.com" in md        # subzy takeover surfaced
    assert "Weaknesses and Vulnerabilities" in md
    # secret metadata present but never the value
    assert "AKIAEXAMPLE" not in md

    meta = sessions.load_meta(cfg.run_id)
    assert meta is not None and meta.status == "completed"

    # artifacts persisted: re-render source, aggregate json, and both deliverables
    from argus.core import paths
    run_path = paths.run_dir(cfg.run_id)
    assert (run_path / "results.json").exists()
    assert (run_path / "report.json").exists()
    md_files = list(run_path.glob("argus_report_*.md"))
    html_files = list(run_path.glob("argus_report_*.html"))
    assert md_files and html_files
    # implicit/target-derived slug when scope has no engagement name
    assert md_files[0].name.startswith("argus_report_example-com_")
    # the HTML deliverable carries the flagship section too
    assert "Weaknesses and Vulnerabilities" in html_files[0].read_text()


def test_write_reports_rerenders_selected_formats(mock_all_tools, monkeypatch):
    monkeypatch.setattr("argus.core.llm.complete", lambda *a, **k: "")
    recipe = Recipe(name="e2e", phases=[1, 2, 3, 4, 5, 6])
    cfg = agent.build_run_config(
        recipe=recipe, target="example.com", model="test/model",
        scope=IN_SCOPE, dry_run=False, assume_yes=True,
    )
    agent.execute(cfg, IN_SCOPE)

    md_only = agent.write_reports(cfg.run_id, "md")
    assert len(md_only) == 1 and md_only[0].suffix == ".md"

    html_only = agent.write_reports(cfg.run_id, "html")
    assert len(html_only) == 1 and html_only[0].suffix == ".html"

    both = agent.write_reports(cfg.run_id, "both")
    assert {p.suffix for p in both} == {".md", ".html"}
    assert "Weaknesses and Vulnerabilities" in both[0].read_text()


def test_write_reports_without_source_errors():
    with pytest.raises(FileNotFoundError):
        agent.write_reports("nonexistent-run", "both")


def test_gate_blocks_live_run_without_authorization(mock_all_tools):
    recipe = Recipe(name="blocked", phases=[1, 2, 3, 4, 5, 6])
    cfg = agent.build_run_config(
        recipe=recipe, target="example.com", model="test/model",
        scope=IN_SCOPE, dry_run=False, assume_yes=False,  # gate should abort
    )
    final = agent.execute(cfg, IN_SCOPE)
    assert final.get("aborted") is True
    # phase 2+ never ran: no live hosts collected past the gate
    log = "\n".join(final.get("phase_log", []))
    assert "Phase 2" not in log or "skipped" in log
    assert sessions.load_meta(cfg.run_id).status == "aborted"


def test_dry_run_sends_no_traffic(mock_all_tools):
    recipe = Recipe(name="dry", phases=[1, 2, 3, 6])
    cfg = agent.build_run_config(
        recipe=recipe, target="example.com", model="test/model",
        scope=IN_SCOPE, dry_run=True, assume_yes=False,
    )
    final = agent.execute(cfg, IN_SCOPE)
    assert final.get("aborted") is False  # dry-run passes the gate
    from argus.core.state import results_from_state
    assert all(r.dry_run for r in results_from_state(final) if r.available)


def test_resume_completes_cleanly(mock_all_tools):
    recipe = Recipe(name="resumable", phases=[1, 2, 3, 6])
    cfg = agent.build_run_config(
        recipe=recipe, target="example.com", model="test/model",
        scope=IN_SCOPE, dry_run=True, assume_yes=True,
    )
    agent.execute(cfg, IN_SCOPE)
    resumed = agent.resume(cfg.run_id)
    assert resumed.get("aborted") is False
    assert sessions.load_meta(cfg.run_id).status == "completed"


def test_out_of_scope_targets_are_dropped(mock_all_tools):
    narrow = Scope.from_dict({"in_scope": {"domains": ["example.com"]}})  # apex only
    recipe = Recipe(name="scoped", phases=[1, 2, 6])
    cfg = agent.build_run_config(
        recipe=recipe, target="example.com", model="test/model",
        scope=narrow, dry_run=False, assume_yes=True,
    )
    final = agent.execute(cfg, narrow)
    # subfinder returns *.example.com hosts; with apex-only scope they are dropped
    assert final.get("dropped")
