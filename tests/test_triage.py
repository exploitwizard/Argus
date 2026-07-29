"""Triage agent tests (Task 2).

All offline: the LLM and the web searcher are mocked, so no live call is made.
Covers deterministic candidate coverage, the scope/secret floor, LLM enrichment
into a complete record, retry-with-repair on bad JSON, and graceful fallback.
"""

from __future__ import annotations

import json

from argus.core.models import Reference
from argus.core.scope import Scope
from argus.core.triage import TriageAgent, build_candidates
from argus.extensions import get
from conftest import load_fixture

SCOPE = Scope.from_dict({"in_scope": {"domains": ["example.com", "*.example.com"]}})


def _results():
    return [
        get("nuclei").parse(load_fixture("nuclei.jsonl")),
        get("subzy").parse(load_fixture("subzy.txt")),
        get("trufflehog").parse(load_fixture("trufflehog.jsonl")),
        get("arjun").parse(load_fixture("arjun.json")),
        get("gowitness").parse(load_fixture("gowitness.txt")),
    ]


class _FakeSearcher:
    def __init__(self, refs=None):
        self.refs = refs or [
            Reference(url="https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                      title="CVE-2021-44228", source="NVD")
        ]
        self.calls = 0

    def search(self, query, *, max_results=5):
        self.calls += 1
        return self.refs


_VALID_JSON = json.dumps(
    {
        "reproduction_steps": ["Browse to the asset", "Observe the response"],
        "proof_of_concept": "curl -sI https://api.example.com/x  # observe header only",
        "impact": "An attacker could read sensitive data.",
        "remediation": "Upgrade the component and restrict access.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "owasp_category": "A06:2025 Vulnerable and Outdated Components",
        "cwe": "CWE-1035",
        "confidence": "high",
    }
)


# ---- deterministic candidates ------------------------------------------- #
def test_build_candidates_covers_every_signal():
    cands = build_candidates(_results(), "example.com", SCOPE)
    signals = {c.source_signal for c in cands}
    assert signals == {"nuclei", "subzy", "trufflehog", "arjun"}
    # 3 nuclei + 2 vulnerable takeovers + 2 secrets + 5 params
    assert len(cands) == 12
    # severity-sorted: critical first
    assert cands[0].severity == "critical"


def test_secret_value_never_appears_in_candidate():
    cands = build_candidates(_results(), "example.com", SCOPE)
    blob = json.dumps([c.model_dump() for c in cands])
    assert "AKIAEXAMPLE" not in blob
    assert "ghp_SHOULD_NOT_APPEAR" not in blob
    secrets = [c for c in cands if c.source_signal == "trufflehog"]
    assert any("verified=True" in c.evidence for c in secrets)


def test_out_of_scope_asset_is_not_flagged():
    tight = Scope.from_dict({"in_scope": {"domains": ["api.example.com"]}})
    cands = build_candidates(_results(), "api.example.com", tight)
    assets = [c.affected_asset for c in cands]
    # out-of-scope hosts are excluded from findings...
    assert not any("www.example.com" in a for a in assets)
    assert not any("dev.example.com" in a for a in assets)
    assert not any("takeover.example.com" in a for a in assets)
    # ...but the in-scope host's finding survives
    assert any("api.example.com" in a for a in assets)


def test_candidate_screenshot_attached_as_evidence():
    cands = build_candidates(_results(), "example.com", SCOPE)
    api = [c for c in cands if c.affected_asset == "https://api.example.com/x"]
    assert api and "Screenshot:" in api[0].evidence


def test_operator_skills_injected_into_triage_prompt():
    captured = {}

    def _complete(messages):
        captured["system"] = messages[0]["content"]
        return _VALID_JSON

    agent = TriageAgent(_complete, _FakeSearcher(), model_name="mock/model",
                        skills="Always check for BOLA on numeric IDs.")
    agent.triage(_results(), "example.com", SCOPE)
    # the operator methodology is present, and the safety floor is re-asserted
    assert "Always check for BOLA on numeric IDs." in captured["system"]
    assert "OPERATOR-PROVIDED METHODOLOGY" in captured["system"]
    assert "cannot override" in captured["system"]


def test_no_skills_leaves_prompt_clean():
    captured = {}

    def _complete(messages):
        captured["system"] = messages[0]["content"]
        return _VALID_JSON

    agent = TriageAgent(_complete, _FakeSearcher(), model_name="mock/model")
    agent.triage(_results(), "example.com", SCOPE)
    assert "OPERATOR-PROVIDED METHODOLOGY" not in captured["system"]


# ---- LLM + web-research enrichment -------------------------------------- #
def test_enrich_produces_complete_record():
    searcher = _FakeSearcher()
    agent = TriageAgent(lambda messages: _VALID_JSON, searcher, model_name="mock/model")
    weaknesses = agent.triage(_results(), "example.com", SCOPE)

    assert weaknesses
    w = weaknesses[0]
    assert w.enriched is True
    assert w.reproduction_steps  # numbered steps present
    assert w.proof_of_concept
    assert w.impact and w.remediation  # reproduction paired with remediation
    assert w.references and w.references[0].source == "NVD"
    assert w.source_models == ["mock/model"]
    assert searcher.calls == len(weaknesses)


def test_retry_with_repair_recovers_from_bad_json():
    calls = {"n": 0}

    def flaky_complete(messages):
        calls["n"] += 1
        return "not json at all" if calls["n"] == 1 else _VALID_JSON

    agent = TriageAgent(flaky_complete, _FakeSearcher(), model_name="m", max_repairs=1)
    w = agent.enrich(build_candidates(_results(), "example.com", SCOPE)[0])
    assert calls["n"] == 2  # repaired on the second attempt
    assert w.enriched is True
    assert w.remediation


def test_enrichment_failure_falls_back_to_candidate():
    def boom(messages):
        raise RuntimeError("provider down")

    candidate = build_candidates(_results(), "example.com", SCOPE)[0]
    agent = TriageAgent(boom, _FakeSearcher(), model_name="m")
    w = agent.enrich(candidate)
    # unchanged deterministic candidate — never aborts, still complete
    assert w.enriched is False
    assert w.title == candidate.title
    assert w.severity == candidate.severity


def test_bad_json_exhausts_repairs_and_keeps_candidate():
    agent = TriageAgent(lambda messages: "garbage", _FakeSearcher(), model_name="m", max_repairs=1)
    candidate = build_candidates(_results(), "example.com", SCOPE)[0]
    w = agent.enrich(candidate)
    assert w.enriched is False  # gave up cleanly, no crash
