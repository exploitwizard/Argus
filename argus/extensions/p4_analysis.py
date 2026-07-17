"""Phase 4 — Deep Analysis: JS endpoint extraction, secret hunting, hidden params.

Tools: LinkFinder, trufflehog, arjun.

Secret hunting stores only *metadata* (detector, location, verified). The secret
value itself is never captured, printed, or persisted.
"""

from __future__ import annotations

import json

from argus.core.models import (
    DiscoveredParam,
    ExtensionResult,
    JsEndpoint,
    Phase,
    SecretHit,
)
from argus.core.scope import Scope
from argus.extensions.base import Extension, ExtensionInputs
from argus.extensions.registry import register
from argus.extensions.util import iter_json_lines, nonblank_lines, targets_file


@register
class LinkFinder(Extension):
    name = "linkfinder"
    phase = Phase.DEEP_ANALYSIS
    required_binary = "linkfinder"
    install_hint = "pip install linkfinder  # or clone github.com/GerbenJavado/LinkFinder"
    description = "Extract endpoints from JavaScript files."

    def build_command(self, inputs: ExtensionInputs, scope: Scope) -> list[str]:
        if not inputs.targets:
            return []
        return ["linkfinder", "-i", inputs.targets[0], "-o", "cli"] + inputs.extra_flags

    def parse(self, output: str) -> ExtensionResult:
        endpoints: list[JsEndpoint] = []
        seen: set[str] = set()
        for line in nonblank_lines(output):
            ep = line.split()[0]
            if ep and ep not in seen and not ep.startswith("["):
                seen.add(ep)
                endpoints.append(JsEndpoint(endpoint=ep))
        return ExtensionResult(extension=self.name, phase=self.phase, js_endpoints=endpoints)


@register
class Trufflehog(Extension):
    name = "trufflehog"
    phase = Phase.DEEP_ANALYSIS
    required_binary = "trufflehog"
    install_hint = "go install github.com/trufflesecurity/trufflehog/v3@latest"
    description = "Detect leaked secrets in crawled content (metadata only, no values)."

    def build_command(self, inputs: ExtensionInputs, scope: Scope) -> list[str]:
        source = inputs.run_dir or "."
        return ["trufflehog", "filesystem", source, "--json", "--no-update"]

    def parse(self, output: str) -> ExtensionResult:
        hits: list[SecretHit] = []
        for obj in iter_json_lines(output):
            detector = obj.get("DetectorName") or obj.get("detector_name") or "unknown"
            meta = obj.get("SourceMetadata") or {}
            data = meta.get("Data") if isinstance(meta, dict) else {}
            location = _first_location(data)
            hits.append(
                SecretHit(
                    detector=str(detector),
                    location=location,
                    verified=bool(obj.get("Verified", False)),
                )
            )
            # NB: we intentionally ignore obj["Raw"] / obj["RawV2"] — the secret.
        return ExtensionResult(extension=self.name, phase=self.phase, secrets=hits)


def _first_location(data: object) -> str:
    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, dict):
                for key in ("file", "link", "uri", "path"):
                    if v.get(key):
                        return str(v[key])
    return "unknown"


@register
class Arjun(Extension):
    name = "arjun"
    phase = Phase.DEEP_ANALYSIS
    required_binary = "arjun"
    install_hint = "pip install arjun"
    description = "Discover hidden HTTP parameters."

    def build_command(self, inputs: ExtensionInputs, scope: Scope) -> list[str]:
        if not inputs.targets:
            return []
        outfile = targets_file(inputs, "arjun_seeds.txt")  # reuse run_dir for -oJ path
        out_json = outfile.replace("arjun_seeds.txt", "arjun_out.json")
        return [
            "arjun", "-u", inputs.targets[0],
            "-oJ", out_json,
            "--stable",
        ] + inputs.extra_flags

    def parse(self, output: str) -> ExtensionResult:
        params: list[DiscoveredParam] = []
        # arjun writes JSON to -oJ; when piped it may also emit the mapping.
        try:
            data = json.loads(output) if output.strip().startswith("{") else {}
        except (ValueError, json.JSONDecodeError):
            data = {}
        for url, found in data.items():
            if isinstance(found, list):
                for p in found:
                    params.append(DiscoveredParam(url=url, param=str(p)))
            elif isinstance(found, dict):
                for p in found.get("params", []):
                    params.append(DiscoveredParam(url=url, param=str(p)))
        return ExtensionResult(extension=self.name, phase=self.phase, params=params)
