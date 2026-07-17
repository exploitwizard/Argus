"""Phase 1 — Enumeration: passive+active subdomain discovery and resolution.

Tools: subfinder, amass, puredns, dnsx.
"""

from __future__ import annotations

import re

from argus.core.models import ExtensionResult, Phase, Subdomain
from argus.core.scope import Scope
from argus.extensions.base import Extension, ExtensionInputs
from argus.extensions.registry import register
from argus.extensions.util import nonblank_lines, targets_file

_HOST_RE = re.compile(r"[a-z0-9](?:[a-z0-9\-\.]*[a-z0-9])?", re.IGNORECASE)


def _subdomains(output: str, source: str) -> list[Subdomain]:
    out: list[Subdomain] = []
    seen: set[str] = set()
    for line in nonblank_lines(output):
        host = line.split()[0].strip().lower().rstrip(".")
        if "." in host and _HOST_RE.fullmatch(host) and host not in seen:
            seen.add(host)
            out.append(Subdomain(host=host, source=source))
    return out


@register
class Subfinder(Extension):
    name = "subfinder"
    phase = Phase.ENUMERATION
    required_binary = "subfinder"
    install_hint = "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    description = "Passive subdomain discovery."

    def build_command(self, inputs: ExtensionInputs, scope: Scope) -> list[str]:
        if not inputs.targets:
            return []
        cmd = ["subfinder", "-silent", "-d", ",".join(inputs.targets)]
        return cmd + inputs.extra_flags

    def parse(self, output: str) -> ExtensionResult:
        return ExtensionResult(
            extension=self.name, phase=self.phase, subdomains=_subdomains(output, "subfinder")
        )


@register
class Amass(Extension):
    name = "amass"
    phase = Phase.ENUMERATION
    required_binary = "amass"
    install_hint = "go install github.com/owasp-amass/amass/v4/...@master"
    description = "Passive subdomain enumeration (passive mode only — no brute force)."

    def build_command(self, inputs: ExtensionInputs, scope: Scope) -> list[str]:
        if not inputs.targets:
            return []
        # Passive only: never active brute-force / no exploitation.
        cmd = ["amass", "enum", "-passive", "-d", ",".join(inputs.targets)]
        return cmd + inputs.extra_flags

    def parse(self, output: str) -> ExtensionResult:
        return ExtensionResult(
            extension=self.name, phase=self.phase, subdomains=_subdomains(output, "amass")
        )


@register
class Puredns(Extension):
    name = "puredns"
    phase = Phase.ENUMERATION
    required_binary = "puredns"
    install_hint = "go install github.com/d3mondev/puredns/v2@latest"
    description = "Mass DNS resolution and wildcard filtering of candidate subdomains."

    def build_command(self, inputs: ExtensionInputs, scope: Scope) -> list[str]:
        if not inputs.targets:
            return []
        infile = targets_file(inputs, "puredns_candidates.txt")
        cmd = ["puredns", "resolve", infile, "--quiet"]
        if inputs.resolvers:
            cmd += ["-r", inputs.resolvers]
        return cmd + inputs.extra_flags

    def parse(self, output: str) -> ExtensionResult:
        return ExtensionResult(
            extension=self.name, phase=self.phase, subdomains=_subdomains(output, "puredns")
        )


@register
class Dnsx(Extension):
    name = "dnsx"
    phase = Phase.ENUMERATION
    required_binary = "dnsx"
    install_hint = "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    description = "Fast DNS resolver to confirm which subdomains resolve."

    def build_command(self, inputs: ExtensionInputs, scope: Scope) -> list[str]:
        if not inputs.targets:
            return []
        infile = targets_file(inputs, "dnsx_hosts.txt")
        return ["dnsx", "-silent", "-l", infile] + inputs.extra_flags

    def parse(self, output: str) -> ExtensionResult:
        subs: list[Subdomain] = []
        seen: set[str] = set()
        for line in nonblank_lines(output):
            # `-silent` prints resolved host; `-a -resp` adds `[A] [1.2.3.4]`.
            host = line.split()[0].split("[")[0].strip().lower().rstrip(".")
            if "." in host and host not in seen:
                seen.add(host)
                subs.append(Subdomain(host=host, source="dnsx"))
        return ExtensionResult(extension=self.name, phase=self.phase, subdomains=subs)
