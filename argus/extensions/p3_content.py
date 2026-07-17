"""Phase 3 — Content/URL Harvesting: crawl, historical URLs, content-discovery.

Tools: katana, gau, ffuf.
"""

from __future__ import annotations

import json

from argus.core.models import ExtensionResult, Phase, Url
from argus.core.scope import Scope
from argus.extensions.base import Extension, ExtensionInputs
from argus.extensions.registry import register
from argus.extensions.util import iter_json_lines, nonblank_lines, targets_file


def _urls(output: str, source: str) -> list[Url]:
    out: list[Url] = []
    seen: set[str] = set()
    for line in nonblank_lines(output):
        u = line.split()[0]
        if u.startswith("http") and u not in seen:
            seen.add(u)
            out.append(Url(url=u, source=source))
    return out


@register
class Katana(Extension):
    name = "katana"
    phase = Phase.CONTENT_HARVEST
    required_binary = "katana"
    install_hint = "go install github.com/projectdiscovery/katana/cmd/katana@latest"
    description = "Crawl live hosts for URLs and endpoints."

    def build_command(self, inputs: ExtensionInputs, scope: Scope) -> list[str]:
        if not inputs.targets:
            return []
        infile = targets_file(inputs, "katana_seeds.txt")
        depth = {"low": "1", "med": "2", "high": "3"}.get(inputs.intensity, "2")
        return [
            "katana", "-silent", "-list", infile, "-depth", depth,
            "-rate-limit", str(inputs.rate_limit),
        ] + inputs.extra_flags

    def parse(self, output: str) -> ExtensionResult:
        return ExtensionResult(extension=self.name, phase=self.phase, urls=_urls(output, "katana"))


@register
class Gau(Extension):
    name = "gau"
    phase = Phase.CONTENT_HARVEST
    required_binary = "gau"
    install_hint = "go install github.com/lc/gau/v2/cmd/gau@latest"
    description = "Fetch known/historical URLs from public archives (passive)."

    def build_command(self, inputs: ExtensionInputs, scope: Scope) -> list[str]:
        if not inputs.targets:
            return []
        return ["gau", "--threads", str(inputs.concurrency)] + inputs.targets

    def parse(self, output: str) -> ExtensionResult:
        return ExtensionResult(extension=self.name, phase=self.phase, urls=_urls(output, "gau"))


@register
class Ffuf(Extension):
    name = "ffuf"
    phase = Phase.CONTENT_HARVEST
    required_binary = "ffuf"
    install_hint = "go install github.com/ffuf/ffuf/v2@latest"
    description = "Content-discovery fuzzing against the first live host."

    def build_command(self, inputs: ExtensionInputs, scope: Scope) -> list[str]:
        if not inputs.targets or not inputs.wordlist:
            return []
        base = inputs.targets[0].rstrip("/")
        return [
            "ffuf",
            "-w", inputs.wordlist,
            "-u", f"{base}/FUZZ",
            "-json",
            "-rate", str(inputs.rate_limit),
            "-mc", "200,204,301,302,307,401,403",
        ] + inputs.extra_flags

    def parse(self, output: str) -> ExtensionResult:
        urls: list[Url] = []
        seen: set[str] = set()

        def add(u: str | None) -> None:
            if u and u not in seen:
                seen.add(u)
                urls.append(Url(url=u, source="ffuf"))

        # ffuf `-json` emits one summary object with a "results" array.
        try:
            summary = json.loads(output) if output.strip().startswith("{") else None
        except (ValueError, json.JSONDecodeError):
            summary = None
        if isinstance(summary, dict) and isinstance(summary.get("results"), list):
            for r in summary["results"]:
                if isinstance(r, dict):
                    add(r.get("url"))
            return ExtensionResult(extension=self.name, phase=self.phase, urls=urls)

        # Fallback: ndjson, one result object per line.
        for obj in iter_json_lines(output):
            u = obj.get("url")
            if not u and isinstance(obj.get("input"), dict):
                add(obj["input"].get("FUZZURL") or obj["input"].get("url"))
            else:
                add(u)
        return ExtensionResult(extension=self.name, phase=self.phase, urls=urls)
