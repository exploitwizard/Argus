"""Multi-model tests (Task 4) — fully offline (litellm mocked).

Covers concurrent dispatch, plan resolution, and the ensemble/consensus merge:
agreement boosts rank/confidence and records provenance; disagreement flags
manual review; one failing model never aborts the batch.
"""

from __future__ import annotations

import asyncio
import json

from argus.core import llm
from argus.core.llm import ModelReply
from argus.core.modelplan import (
    MODE_ENSEMBLE,
    MODE_PER_PHASE,
    MODE_SINGLE,
    default_quorum,
    resolve_plan,
)
from argus.core.scope import Scope
from argus.core.triage import _Enrichment, build_candidates, merge_opinions, triage_ensemble
from argus.extensions import get
from conftest import load_fixture

SCOPE = Scope.from_dict({"in_scope": {"domains": ["example.com", "*.example.com"]}})


def _results():
    return [
        get("nuclei").parse(load_fixture("nuclei.jsonl")),
        get("subzy").parse(load_fixture("subzy.txt")),
    ]


# ---- parse / plan ------------------------------------------------------- #
def test_parse_models_dedupes_and_orders():
    assert llm.parse_models("a, b ,a,c,") == ["a", "b", "c"]
    assert llm.parse_models("") == []
    assert llm.parse_models(None) == []


def test_default_quorum_is_majority():
    assert default_quorum(1) == 1
    assert default_quorum(2) == 1
    assert default_quorum(3) == 2
    assert default_quorum(4) == 2


def test_resolve_plan_single_vs_ensemble_vs_perphase():
    single = resolve_plan(cli_model="m1", cli_models=[], multi_mode="ensemble",
                          default_model="def")
    assert single.mode == MODE_SINGLE and single.primary == "m1"

    ens = resolve_plan(cli_model=None, cli_models=["a", "b", "c"],
                       multi_mode="ensemble", default_model="def")
    assert ens.mode == MODE_ENSEMBLE and ens.is_ensemble and ens.quorum == 2
    assert ens.triage_models() == ["a", "b", "c"]

    pp = resolve_plan(cli_model=None, cli_models=["strong", "fast"],
                      multi_mode="per-phase", default_model="def",
                      phase_models={"mechanical": "fast", "triage": "strong"})
    assert pp.mode == MODE_PER_PHASE
    assert pp.for_role("mechanical") == "fast"
    assert pp.for_role("triage") == "strong"
    # per-phase triage runs a single (strong) model, not the whole ensemble
    assert pp.triage_models() == ["strong"]


def test_resolve_plan_precedence_cli_over_default():
    p = resolve_plan(cli_model="cli", cli_models=[], multi_mode="ensemble",
                     default_model="settings", recipe_model="recipe")
    assert p.primary == "cli"
    p2 = resolve_plan(cli_model=None, cli_models=[], multi_mode="ensemble",
                      default_model="settings", recipe_model="recipe")
    assert p2.primary == "recipe"


# ---- concurrent dispatch ------------------------------------------------ #
def test_complete_many_dispatches_to_all(monkeypatch):
    async def fake_acomplete(model, messages, **kw):
        await asyncio.sleep(0)  # yield — proves concurrency path works
        return f"reply from {model}"

    monkeypatch.setattr(llm, "acomplete", fake_acomplete)
    replies = llm.complete_many(["m1", "m2", "m3"], [{"role": "user", "content": "x"}])
    assert [r.model for r in replies] == ["m1", "m2", "m3"]
    assert all(r.ok for r in replies)
    assert replies[1].text == "reply from m2"


def test_complete_many_isolates_one_failure(monkeypatch):
    async def fake_acomplete(model, messages, **kw):
        if model == "bad":
            raise RuntimeError("no api key for bad")
        return f"ok {model}"

    monkeypatch.setattr(llm, "acomplete", fake_acomplete)
    replies = llm.complete_many(["good", "bad", "good2"], [{"role": "user", "content": "x"}])
    by = {r.model: r for r in replies}
    assert by["good"].ok and by["good2"].ok
    assert not by["bad"].ok and "no api key" in by["bad"].error
    # the batch did not raise; every model got a reply slot
    assert len(replies) == 3


# ---- consensus merge ---------------------------------------------------- #
def _enr(confirmed=True, severity="high", **kw):
    base = dict(
        reproduction_steps=["step 1", "step 2"], proof_of_concept="curl -sI ...",
        impact="data exposure", remediation="patch it", confidence="medium",
        confirmed=confirmed, severity=severity,
    )
    base.update(kw)
    return _Enrichment(**base)


def test_merge_agreement_boosts_confidence_and_records_models():
    cand = build_candidates(_results(), "example.com", SCOPE)[0]
    merged = merge_opinions(cand, [("A", _enr()), ("B", _enr())], quorum=2)
    assert merged.enriched is True
    assert merged.source_models == ["A", "B"]      # provenance recorded
    assert merged.confidence == "high"             # medium -> high (quorum met)
    assert merged.needs_manual_review is False
    assert merged.remediation == "patch it"


def test_merge_disagreement_flags_manual_review():
    cand = build_candidates(_results(), "example.com", SCOPE)[0]
    merged = merge_opinions(
        cand, [("A", _enr(confirmed=True)), ("B", _enr(confirmed=False))], quorum=1
    )
    assert merged.needs_manual_review is True
    assert merged.source_models == ["A"]           # only the confirmer
    # divergent confirmation => no confidence boost
    assert merged.confidence == "medium"


def test_merge_divergent_severity_flags_review():
    cand = build_candidates(_results(), "example.com", SCOPE)[0]
    merged = merge_opinions(
        cand, [("A", _enr(severity="high")), ("B", _enr(severity="low"))], quorum=1
    )
    assert merged.needs_manual_review is True


def test_merge_all_failed_keeps_candidate():
    cand = build_candidates(_results(), "example.com", SCOPE)[0]
    merged = merge_opinions(cand, [("A", None), ("B", None)], quorum=1)
    assert merged.enriched is False
    assert merged.title == cand.title


# ---- ensemble end to end (injected complete_many) ----------------------- #
def test_triage_ensemble_merges_and_ranks():
    payload = {
        "A": json.dumps(dict(reproduction_steps=["r"], proof_of_concept="p",
                             impact="i", remediation="m", confidence="medium",
                             confirmed=True, severity="high")),
        "B": json.dumps(dict(reproduction_steps=["r", "r2"], proof_of_concept="p",
                             impact="i", remediation="m2", confidence="high",
                             confirmed=True, severity="high")),
    }

    def fake_complete_many(models, messages, *, concurrency=8, **kw):
        return [ModelReply(model=m, ok=True, text=payload[m]) for m in models]

    weaknesses = triage_ensemble(
        _results(), "example.com", SCOPE, models=["A", "B"], quorum=2,
        complete_many=fake_complete_many,
    )
    assert weaknesses
    top = weaknesses[0]
    assert set(top.source_models) == {"A", "B"}
    assert top.enriched is True
    # highest-severity finding floats to the top
    assert top.severity == "critical"


def test_triage_ensemble_survives_partial_failure():
    def fake_complete_many(models, messages, *, concurrency=8, **kw):
        out = []
        for m in models:
            if m == "B":
                out.append(ModelReply(model=m, ok=False, error="down"))
            else:
                out.append(ModelReply(model=m, ok=True, text=json.dumps(
                    dict(reproduction_steps=["r"], remediation="m",
                         confirmed=True, severity="high", confidence="medium"))))
        return out

    weaknesses = triage_ensemble(
        _results(), "example.com", SCOPE, models=["A", "B"], quorum=1,
        complete_many=fake_complete_many,
    )
    assert weaknesses
    # only the surviving model is credited; run did not abort
    assert all(w.source_models in ([], ["A"]) for w in weaknesses)
    assert any(w.enriched for w in weaknesses)
