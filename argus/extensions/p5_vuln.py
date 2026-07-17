"""Phase 5 — Vuln Scan & Triage: template-based detection and screenshots.

Tools: nuclei, gowitness.

ARGUS *detects* only. nuclei is run in detection mode; ARGUS never runs
exploitation templates or takes any exploit action.
"""

from __future__ import annotations

from argus.core.models import ExtensionResult, Finding, Phase, Screenshot
from argus.core.scope import Scope
from argus.extensions.base import Extension, ExtensionInputs
from argus.extensions.registry import register
from argus.extensions.util import iter_json_lines, nonblank_lines, targets_file


@register
class Nuclei(Extension):
    name = "nuclei"
    phase = Phase.VULN_SCAN
    required_binary = "nuclei"
    install_hint = "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    description = "Template-based vulnerability detection (detection only, no exploitation)."

    def build_command(self, inputs: ExtensionInputs, scope: Scope) -> list[str]:
        if not inputs.targets:
            return []
        infile = targets_file(inputs, "nuclei_targets.txt")
        # Detection-oriented severities; exclude nothing exploitative is *run*.
        sev = {
            "low": "low,medium,high,critical",
            "med": "info,low,medium,high,critical",
            "high": "info,low,medium,high,critical",
        }.get(inputs.intensity, "info,low,medium,high,critical")
        cmd = [
            "nuclei",
            "-jsonl",
            "-list", infile,
            "-severity", sev,
            "-rate-limit", str(inputs.rate_limit),
        ]
        if inputs.nuclei_templates:
            cmd += ["-templates", inputs.nuclei_templates]
        return cmd + inputs.extra_flags

    def parse(self, output: str) -> ExtensionResult:
        findings: list[Finding] = []
        for obj in iter_json_lines(output):
            info = obj.get("info") or {}
            findings.append(
                Finding(
                    template_id=obj.get("template-id") or obj.get("template_id") or "unknown",
                    name=info.get("name") or obj.get("template-id") or "unknown",
                    severity=(info.get("severity") or "info").lower(),
                    matched_at=obj.get("matched-at") or obj.get("host") or "",
                    tags=list(info.get("tags") or []),
                )
            )
        return ExtensionResult(extension=self.name, phase=self.phase, findings=findings)


@register
class Gowitness(Extension):
    name = "gowitness"
    phase = Phase.VULN_SCAN
    required_binary = "gowitness"
    install_hint = "go install github.com/sensepost/gowitness@latest"
    description = "Capture screenshots of live web hosts for visual triage."

    def build_command(self, inputs: ExtensionInputs, scope: Scope) -> list[str]:
        if not inputs.targets:
            return []
        infile = targets_file(inputs, "gowitness_urls.txt")
        outdir = (inputs.run_dir or ".") + "/screenshots"
        return ["gowitness", "scan", "file", "-f", infile, "--screenshot-path", outdir]

    def parse(self, output: str) -> ExtensionResult:
        shots: list[Screenshot] = []
        for line in nonblank_lines(output):
            # gowitness logs contain `url=... path=...` fields.
            url = _kv(line, "url")
            path = _kv(line, "path") or _kv(line, "filename")
            if path:
                shots.append(Screenshot(url=url or "unknown", path=path))
        return ExtensionResult(extension=self.name, phase=self.phase, screenshots=shots)


def _kv(line: str, key: str) -> str:
    marker = f"{key}="
    if marker not in line:
        return ""
    tail = line.split(marker, 1)[1]
    return tail.split()[0].strip().strip('"') if tail.split() else ""
