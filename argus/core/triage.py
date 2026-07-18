"""Post–Phase-5 analysis / triage agent.

Turns raw tool evidence into documented, structured :class:`Weakness` findings
for responsible disclosure. Two layers:

1. :func:`build_candidates` — deterministic and offline. Every security-relevant
   signal (nuclei finding, subdomain takeover, exposed secret, discovered param)
   becomes a candidate with a default OWASP-2025 / CWE mapping, severity, and
   CVSS-style vector. This guarantees *nothing flagged is ever omitted*, even
   with no model configured.
2. :class:`TriageAgent` — enriches each candidate via the LLM (reproduction
   steps, a safe verification PoC, impact, remediation) and the web-research
   tool (cited CVEs/advisories). Any LLM/search failure keeps the deterministic
   candidate, so a run never aborts on triage.

Ethics floor: findings are produced only for in-scope assets, every finding
pairs reproduction with remediation, and the agent documents/verifies — it never
emits exploitation actions. Secret *values* are never included (metadata only).
"""

from __future__ import annotations

import json
from typing import Callable

from pydantic import BaseModel, Field, ValidationError

from argus.core.models import ExtensionResult, Reference, Weakness
from argus.core.research import NullWebSearcher, WebSearcher
from argus.core.scope import Scope, _as_ip, _host_of

CompleteFn = Callable[[list[dict]], str]

# --------------------------------------------------------------------------- #
# Default OWASP-2025 / CWE / CVSS mappings (deterministic baseline)
# --------------------------------------------------------------------------- #
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

# Representative CVSS 3.1 vectors per severity (baseline; the LLM may refine).
_CVSS_BY_SEV = {
    "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "high": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    "medium": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "low": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
    "info": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
}

# nuclei tag -> (OWASP 2025 category, CWE). First matching tag wins.
_TAG_MAP: list[tuple[str, tuple[str, str]]] = [
    ("sqli", ("A03:2025 Injection", "CWE-89")),
    ("injection", ("A03:2025 Injection", "CWE-74")),
    ("xss", ("A03:2025 Injection", "CWE-79")),
    ("rce", ("A03:2025 Injection", "CWE-94")),
    ("ssrf", ("A10:2025 Server-Side Request Forgery", "CWE-918")),
    ("lfi", ("A01:2025 Broken Access Control", "CWE-22")),
    ("traversal", ("A01:2025 Broken Access Control", "CWE-22")),
    ("idor", ("A01:2025 Broken Access Control", "CWE-639")),
    ("exposure", ("A01:2025 Broken Access Control", "CWE-200")),
    ("disclosure", ("A01:2025 Broken Access Control", "CWE-200")),
    ("default-login", ("A07:2025 Identification and Authentication Failures", "CWE-1392")),
    ("auth", ("A07:2025 Identification and Authentication Failures", "CWE-287")),
    ("crypto", ("A02:2025 Cryptographic Failures", "CWE-327")),
    ("ssl", ("A02:2025 Cryptographic Failures", "CWE-326")),
    ("cve", ("A06:2025 Vulnerable and Outdated Components", "CWE-1035")),
    ("tech", ("A06:2025 Vulnerable and Outdated Components", "CWE-1035")),
    ("misconfig", ("A05:2025 Security Misconfiguration", "CWE-16")),
    ("config", ("A05:2025 Security Misconfiguration", "CWE-16")),
]
_DEFAULT_MAP = ("A05:2025 Security Misconfiguration", "CWE-16")


def _map_finding(tags: list[str], name: str) -> tuple[str, str]:
    haystack = " ".join(tags + [name]).lower()
    for needle, mapping in _TAG_MAP:
        if needle in haystack:
            return mapping
    return _DEFAULT_MAP


# --------------------------------------------------------------------------- #
# Candidate construction (deterministic, offline, complete)
# --------------------------------------------------------------------------- #
def build_candidates(
    results: list[ExtensionResult], target: str, scope: Scope
) -> list[Weakness]:
    """Turn every security-relevant signal into a structured candidate.

    Screenshots (gowitness) and httpx metadata are attached as evidence context.
    Only in-scope assets yield findings (defensive re-check of the scope floor).
    """
    screenshots = {s.url: s.path for r in results for s in r.screenshots}
    hostmeta = {h.url: h for r in results for h in r.live_hosts}
    candidates: list[Weakness] = []

    def _shot(asset: str) -> str:
        for url, path in screenshots.items():
            if asset and (asset in url or url in asset):
                return f"\nScreenshot: {path}"
        return ""

    for r in results:
        for f in r.findings:  # nuclei
            owasp, cwe = _map_finding(f.tags, f.name)
            sev = (f.severity or "info").lower()
            asset = f.matched_at or target
            ev = (
                f"nuclei template `{f.template_id}` matched at {f.matched_at}\n"
                f"severity={sev} tags={', '.join(f.tags) or '-'}" + _shot(asset)
            )
            candidates.append(
                Weakness(
                    title=f.name, affected_asset=asset, owasp_category=owasp, cwe=cwe,
                    severity=sev, cvss_vector=_CVSS_BY_SEV.get(sev, ""),
                    confidence="medium", evidence=ev, source_signal="nuclei",
                )
            )
        for t in r.takeovers:  # subzy
            if not t.vulnerable:
                continue
            asset = t.host
            candidates.append(
                Weakness(
                    title=f"Potential subdomain takeover ({t.service or 'unknown service'})",
                    affected_asset=asset,
                    owasp_category="A05:2025 Security Misconfiguration", cwe="CWE-350",
                    severity="high", cvss_vector=_CVSS_BY_SEV["high"], confidence="high",
                    evidence=f"subzy flagged `{asset}` as claimable "
                             f"(service={t.service or 'unknown'})" + _shot(asset),
                    source_signal="subzy",
                )
            )
        for s in r.secrets:  # trufflehog — metadata only, never the value
            sev = "high" if s.verified else "medium"
            candidates.append(
                Weakness(
                    title=f"Exposed secret ({s.detector})",
                    affected_asset=s.location,
                    owasp_category="A02:2025 Cryptographic Failures", cwe="CWE-798",
                    severity=sev, cvss_vector=_CVSS_BY_SEV[sev],
                    confidence="high" if s.verified else "medium",
                    evidence=f"trufflehog detector={s.detector} location={s.location} "
                             f"verified={s.verified} (secret value intentionally not stored)",
                    source_signal="trufflehog",
                )
            )
        for p in r.params:  # arjun — attack surface, needs manual review
            candidates.append(
                Weakness(
                    title=f"Undocumented parameter `{p.param}`",
                    affected_asset=p.url,
                    owasp_category="A03:2025 Injection", cwe="CWE-20",
                    severity="info", cvss_vector=_CVSS_BY_SEV["info"], confidence="low",
                    evidence=f"arjun discovered hidden parameter `{p.param}` on {p.url}",
                    needs_manual_review=True, source_signal="arjun",
                )
            )

    # Scope floor: only in-scope assets become findings. Assets that are local
    # artifacts (a filesystem path, e.g. a downloaded JS bundle) or non-network
    # labels are kept — they were derived from already in-scope collection.
    in_scope = [w for w in candidates if _asset_in_scope(scope, w.affected_asset)]
    in_scope.sort(key=lambda w: _SEV_ORDER.get(w.severity, 5))
    _ = hostmeta  # metadata reserved for future evidence enrichment
    return in_scope


def _asset_in_scope(scope: Scope, asset: str) -> bool:
    """Scope-check a candidate's asset, treating non-network assets as in scope.

    A network location (URL with a host, or a bare host/IP) is checked against
    the scope. A filesystem path or a non-host label is kept, since it can only
    exist because in-scope collection produced it.
    """
    a = asset.strip()
    if not a or a.startswith(("/", "./", "../")) or "\\" in a:
        return True
    host = _host_of(a)
    if not host or (_as_ip(host) is None and "." not in host):
        return True
    return scope.is_in_scope(a)


# --------------------------------------------------------------------------- #
# LLM enrichment payload
# --------------------------------------------------------------------------- #
class _Enrichment(BaseModel):
    """Validated shape of the LLM's enrichment reply."""

    reproduction_steps: list[str] = Field(default_factory=list)
    proof_of_concept: str = ""
    impact: str = ""
    remediation: str = ""
    cvss_vector: str = ""
    owasp_category: str = ""
    cwe: str = ""
    confidence: str = ""
    # Consensus signals (ensemble mode): is this a genuine weakness, and the
    # model's own severity opinion.
    confirmed: bool = True
    severity: str = ""

    def content_score(self) -> int:
        """Rough richness score — used to pick the best enrichment on a merge."""
        return (
            len(self.reproduction_steps)
            + bool(self.proof_of_concept)
            + bool(self.impact)
            + bool(self.remediation)
        )


_SYSTEM = (
    "You are ARGUS's vulnerability triage analyst for AUTHORIZED, in-scope "
    "targets only. You document and verify weaknesses for responsible "
    "disclosure. You NEVER produce exploitation payloads or actions that cause "
    "damage — proof-of-concept must be a minimal, safe verification only. Every "
    "finding must pair reproduction with concrete remediation. Never include "
    "raw secret values. Respond with a single JSON object and nothing else."
)


class TriageAgent:
    """Enriches deterministic candidates via LLM + web research."""

    def __init__(
        self,
        complete_fn: CompleteFn,
        searcher: WebSearcher | None = None,
        *,
        model_name: str = "",
        max_repairs: int = 1,
    ) -> None:
        self._complete = complete_fn
        self._searcher = searcher or NullWebSearcher()
        self._model_name = model_name
        self._max_repairs = max_repairs

    def triage(
        self, results: list[ExtensionResult], target: str, scope: Scope
    ) -> list[Weakness]:
        return [self.enrich(w) for w in build_candidates(results, target, scope)]

    def enrich(self, w: Weakness) -> Weakness:
        """Augment one candidate. On any failure, return it unchanged."""
        try:
            data = self._enrichment_json(w)
        except Exception:
            return w
        if data is None:
            return w
        merged = w.model_copy(
            update={
                "reproduction_steps": data.reproduction_steps or w.reproduction_steps,
                "proof_of_concept": data.proof_of_concept or w.proof_of_concept,
                "impact": data.impact or w.impact,
                "remediation": data.remediation or w.remediation,
                "cvss_vector": data.cvss_vector or w.cvss_vector,
                "owasp_category": data.owasp_category or w.owasp_category,
                "cwe": data.cwe or w.cwe,
                "confidence": data.confidence or w.confidence,
                "enriched": True,
                "source_models": ([self._model_name] if self._model_name else []),
            }
        )
        merged.references = self._research(merged)
        return merged

    # ---- internals ------------------------------------------------------ #
    def _enrichment_json(self, w: Weakness) -> _Enrichment | None:
        messages = _build_messages(w)
        for _ in range(self._max_repairs + 1):
            raw = self._complete(messages)
            parsed = _try_parse(raw)
            if parsed is not None:
                return parsed
            # retry-with-repair: tell the model exactly what was wrong
            messages = messages + [
                {"role": "assistant", "content": raw},
                {"role": "user", "content": "That response was not valid JSON matching "
                                            "the schema. Reply with ONLY the JSON object."},
            ]
        return None

    def _research(self, w: Weakness) -> list[Reference]:
        query = f"{w.title} {w.cwe} {w.owasp_category} affecting {w.affected_asset}"
        try:
            refs = self._searcher.search(query)
        except Exception:
            return w.references
        return refs or w.references


def triage_run(
    results: list[ExtensionResult],
    target: str,
    scope: Scope,
    *,
    model: str | None = None,
    models: list[str] | None = None,
    quorum: int = 1,
    concurrency: int = 8,
    dry_run: bool = False,
) -> list[Weakness]:
    """Graph-facing entry point.

    Offline / dry-run → deterministic candidates only (no network). With 2+
    ``models`` → ensemble/consensus triage. With a single model → LLM +
    web-research enrichment. Any failure degrades to the deterministic candidate.
    """
    if dry_run:
        return build_candidates(results, target, scope)

    ensemble = models or ([model] if model else [])
    if len(ensemble) > 1:
        from argus.core.research import LiteLLMWebSearcher
        try:
            return triage_ensemble(
                results, target, scope, models=ensemble, quorum=quorum,
                searcher=LiteLLMWebSearcher(ensemble[0]), concurrency=concurrency,
            )
        except Exception:
            return build_candidates(results, target, scope)

    if not ensemble:
        return build_candidates(results, target, scope)

    single = ensemble[0]
    from argus.core import llm
    from argus.core.research import LiteLLMWebSearcher

    def _complete(messages: list[dict]) -> str:
        return llm.complete(single, messages, max_tokens=1200, temperature=0.1)

    agent = TriageAgent(_complete, LiteLLMWebSearcher(single), model_name=single)
    try:
        return agent.triage(results, target, scope)
    except Exception:
        return build_candidates(results, target, scope)


def _build_messages(w: Weakness) -> list[dict]:
    """The enrichment prompt for one candidate — shared by single and ensemble."""
    user = (
        "Enrich this weakness for a responsible-disclosure report. Keep the "
        "PoC safe (verification only, no exploitation).\n\n"
        f"Title: {w.title}\nAsset: {w.affected_asset}\nSeverity: {w.severity}\n"
        f"OWASP: {w.owasp_category}\nCWE: {w.cwe}\nEvidence:\n{w.evidence}\n\n"
        "Return a JSON object with keys: reproduction_steps (array of strings), "
        "proof_of_concept (string), impact (string), remediation (string), "
        "cvss_vector (string), owasp_category (string), cwe (string), "
        "confidence (one of high|medium|low), confirmed (boolean — is this a "
        "genuine weakness?), severity (one of critical|high|medium|low|info)."
    )
    return [
        {"role": "system", "content": _SYSTEM},
        {"role": "user", "content": user},
    ]


# --------------------------------------------------------------------------- #
# Ensemble / consensus (Task 4)
# --------------------------------------------------------------------------- #
_CONF_ORDER = ["low", "medium", "high"]


def _boost_confidence(conf: str) -> str:
    try:
        i = _CONF_ORDER.index(conf)
    except ValueError:
        return conf
    return _CONF_ORDER[min(i + 1, len(_CONF_ORDER) - 1)]


def merge_opinions(
    candidate: Weakness,
    opinions: list[tuple[str, _Enrichment | None]],
    quorum: int,
) -> Weakness:
    """Merge several models' opinions of one candidate into a final Weakness.

    * ``source_models`` records every model that *confirmed* the weakness.
    * ≥``quorum`` confirmations boosts confidence and (via a higher rank score)
      floats the finding up.
    * Disagreement — some confirm and some reject, or materially divergent
      severity — flags ``needs_manual_review``.
    * If no model produced a usable opinion, the deterministic candidate stands.
    """
    valid = [(m, e) for m, e in opinions if e is not None]
    if not valid:
        return candidate

    confirmers = [m for m, e in valid if e.confirmed]
    rejecters = [m for m, e in valid if not e.confirmed]
    # Choose the richest confirming opinion for the prose fields (fall back to any).
    pool = [(m, e) for m, e in valid if e.confirmed] or valid
    best_model, best = max(pool, key=lambda me: me[1].content_score())

    severities = {e.severity for _, e in valid if e.severity}
    divergent_sev = len(severities) > 1
    disagreement = bool(confirmers and rejecters) or divergent_sev
    quorum_met = len(confirmers) >= quorum

    merged = candidate.model_copy(
        update={
            "reproduction_steps": best.reproduction_steps or candidate.reproduction_steps,
            "proof_of_concept": best.proof_of_concept or candidate.proof_of_concept,
            "impact": best.impact or candidate.impact,
            "remediation": best.remediation or candidate.remediation,
            "cvss_vector": best.cvss_vector or candidate.cvss_vector,
            "owasp_category": best.owasp_category or candidate.owasp_category,
            "cwe": best.cwe or candidate.cwe,
            "confidence": best.confidence or candidate.confidence,
            "enriched": True,
            "source_models": sorted(confirmers),
            "needs_manual_review": candidate.needs_manual_review or disagreement or not confirmers,
        }
    )
    if quorum_met and not disagreement:
        merged.confidence = _boost_confidence(merged.confidence)
    return merged


def _rank_score(w: Weakness) -> tuple[int, int, int]:
    """Sort key: severity, then consensus strength, then confidence (all desc)."""
    sev = _SEV_ORDER.get(w.severity, 5)
    return (sev, -len(w.source_models), -_CONF_ORDER.index(w.confidence)
            if w.confidence in _CONF_ORDER else 0)


def triage_ensemble(
    results: list[ExtensionResult],
    target: str,
    scope: Scope,
    *,
    models: list[str],
    quorum: int,
    searcher: WebSearcher | None = None,
    concurrency: int = 8,
    complete_many: Callable[..., list] | None = None,
) -> list[Weakness]:
    """Ensemble triage: enrich each candidate with all models, merge by consensus.

    ``complete_many`` is injected for testing; by default it dispatches through
    the LiteLLM async layer. A model that fails contributes no opinion but never
    aborts the batch.
    """
    if complete_many is None:
        from argus.core import llm
        complete_many = llm.complete_many

    searcher = searcher or NullWebSearcher()
    candidates = build_candidates(results, target, scope)
    merged: list[Weakness] = []
    for cand in candidates:
        messages = _build_messages(cand)
        replies = complete_many(models, messages, concurrency=concurrency)
        opinions: list[tuple[str, _Enrichment | None]] = [
            (r.model, _try_parse(r.text) if r.ok else None) for r in replies
        ]
        w = merge_opinions(cand, opinions, quorum)
        if w.enriched:
            try:
                refs = searcher.search(
                    f"{w.title} {w.cwe} {w.owasp_category} affecting {w.affected_asset}"
                )
                w.references = refs or w.references
            except Exception:
                pass
        merged.append(w)
    merged.sort(key=_rank_score)
    return merged


def _try_parse(raw: str) -> _Enrichment | None:
    blob = _extract_json_object(raw)
    if blob is None:
        return None
    try:
        return _Enrichment.model_validate_json(blob)
    except ValidationError:
        try:
            return _Enrichment(**json.loads(blob))
        except (json.JSONDecodeError, ValidationError, TypeError):
            return None


def _extract_json_object(text: str) -> str | None:
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start : end + 1]
    return None
