"""Runtime web research for the triage agent.

Enriches each weakness with current external context — matching CVE(s), public
advisories, vendor guidance — and returns *cited* :class:`Reference` objects.

Web search rides the existing LiteLLM gateway: providers that expose a native
web-search tool (Anthropic, OpenAI, Gemini) use it; others degrade to the
model's own knowledge. Every searcher is *best-effort* — it never raises and
never blocks a run. Tests inject a fake searcher, so no live network is touched.
"""

from __future__ import annotations

import json
import re
from typing import Protocol

from argus.core.models import Reference

_URL_RE = re.compile(r"https?://[^\s\"'>)\]]+")

# Authoritative hosts we prefer to cite, in priority order.
_AUTHORITATIVE = (
    "nvd.nist.gov",
    "cve.org",
    "mitre.org",
    "owasp.org",
    "cisa.gov",
    "github.com",
)


class WebSearcher(Protocol):
    """Anything that can turn a query into cited references."""

    def search(self, query: str, *, max_results: int = 5) -> list[Reference]: ...


class NullWebSearcher:
    """Offline default — returns no references, never touches the network."""

    def search(self, query: str, *, max_results: int = 5) -> list[Reference]:
        return []


class LiteLLMWebSearcher:
    """Best-effort searcher over the LiteLLM gateway using provider-native search.

    Asks the model (with web search enabled where the provider supports it) for
    authoritative sources and parses back a list of references. Any failure —
    missing key, provider without search, malformed output — yields ``[]``.
    """

    def __init__(self, model: str) -> None:
        self.model = model

    def search(self, query: str, *, max_results: int = 5) -> list[Reference]:
        try:
            text = self._complete_with_search(query, max_results)
        except Exception:
            return []
        return _parse_references(text, max_results)

    def _complete_with_search(self, query: str, max_results: int) -> str:
        import litellm

        from argus.core import llm

        prompt = (
            "You are a security research assistant. Using authoritative sources "
            "(NVD, CVE, vendor advisories, OWASP, project docs), find current "
            f"context for this weakness:\n\n{query}\n\n"
            f"Return ONLY a JSON array of up to {max_results} objects with keys "
            '"url", "title", "source". Prefer primary sources. No prose.'
        )
        messages = [{"role": "user", "content": prompt}]
        kwargs = llm._call_kwargs(self.model)
        # Enable provider-native web search where litellm advertises support;
        # harmless kwargs are ignored by providers that lack the tool.
        try:
            if litellm.supports_web_search(model=self.model):
                kwargs["web_search_options"] = {"search_context_size": "low"}
        except Exception:
            pass
        resp = litellm.completion(
            messages=messages, max_tokens=800, temperature=0.0, **kwargs
        )
        return resp["choices"][0]["message"]["content"] or ""


def _parse_references(text: str, max_results: int) -> list[Reference]:
    """Parse references from a model reply — JSON first, URL-scrape fallback."""
    refs: list[Reference] = []
    blob = _extract_json_array(text)
    if blob is not None:
        try:
            for item in json.loads(blob):
                if isinstance(item, dict) and item.get("url"):
                    refs.append(
                        Reference(
                            url=str(item["url"]),
                            title=str(item.get("title", "")),
                            source=str(item.get("source", "")),
                        )
                    )
        except (json.JSONDecodeError, TypeError, ValueError):
            refs = []
    if not refs:  # fallback: scrape bare URLs out of the text
        for url in dict.fromkeys(_URL_RE.findall(text)):
            refs.append(Reference(url=url, source=_source_of(url)))
    refs.sort(key=lambda r: _authority_rank(r.url))
    return refs[:max_results]


def _extract_json_array(text: str) -> str | None:
    start = text.find("[")
    end = text.rfind("]")
    if start != -1 and end != -1 and end > start:
        return text[start : end + 1]
    return None


def _source_of(url: str) -> str:
    for host in _AUTHORITATIVE:
        if host in url:
            return host
    return ""


def _authority_rank(url: str) -> int:
    for i, host in enumerate(_AUTHORITATIVE):
        if host in url:
            return i
    return len(_AUTHORITATIVE)
