"""Phase 2 — Host/Service Discovery: probe live web hosts, web-port scan,
subdomain-takeover detection.

Tools: httpx, naabu (web ports only), subzy.
"""

from __future__ import annotations

from argus.core.models import ExtensionResult, LiveHost, OpenPort, Phase, Takeover
from argus.core.scope import Scope
from argus.extensions.base import Extension, ExtensionInputs
from argus.extensions.registry import register
from argus.extensions.util import (
    WEB_PORTS,
    iter_json_lines,
    nonblank_lines,
    targets_file,
)


@register
class Httpx(Extension):
    name = "httpx"
    phase = Phase.HOST_DISCOVERY
    required_binary = "httpx"
    install_hint = "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    description = "Probe hosts for live web servers; capture status, title, tech."

    def build_command(self, inputs: ExtensionInputs, scope: Scope) -> list[str]:
        if not inputs.targets:
            return []
        infile = targets_file(inputs, "httpx_hosts.txt")
        return [
            "httpx",
            "-json",
            "-silent",
            "-l", infile,
            "-title", "-tech-detect", "-status-code", "-web-server",
            "-rate-limit", str(inputs.rate_limit),
        ] + inputs.extra_flags

    def parse(self, output: str) -> ExtensionResult:
        hosts: list[LiveHost] = []
        for obj in iter_json_lines(output):
            url = obj.get("url") or obj.get("input")
            if not url:
                continue
            hosts.append(
                LiveHost(
                    url=url,
                    status_code=obj.get("status_code") or obj.get("status-code"),
                    title=obj.get("title"),
                    webserver=obj.get("webserver") or obj.get("web-server"),
                    tech=list(obj.get("tech") or obj.get("technologies") or []),
                )
            )
        return ExtensionResult(extension=self.name, phase=self.phase, live_hosts=hosts)


@register
class Naabu(Extension):
    name = "naabu"
    phase = Phase.HOST_DISCOVERY
    required_binary = "naabu"
    install_hint = "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    description = "Scan a fixed set of WEB-relevant ports only (no general port scanning)."

    def build_command(self, inputs: ExtensionInputs, scope: Scope) -> list[str]:
        if not inputs.targets:
            return []
        infile = targets_file(inputs, "naabu_hosts.txt")
        # Hard-coded web ports: ARGUS is web-recon only and must not stray into
        # general network/host scanning, so -p is not operator-overridable here.
        return [
            "naabu",
            "-silent",
            "-list", infile,
            "-port", WEB_PORTS,
            "-rate", str(inputs.rate_limit),
        ]

    def parse(self, output: str) -> ExtensionResult:
        ports: list[OpenPort] = []
        for line in nonblank_lines(output):
            if ":" in line:
                host, _, port = line.rpartition(":")
                if port.isdigit():
                    ports.append(OpenPort(host=host.strip(), port=int(port)))
        return ExtensionResult(extension=self.name, phase=self.phase, open_ports=ports)


@register
class Subzy(Extension):
    name = "subzy"
    phase = Phase.HOST_DISCOVERY
    required_binary = "subzy"
    install_hint = "go install github.com/PentestPad/subzy@latest"
    description = "Detect (not exploit) dangling subdomain takeovers."

    def build_command(self, inputs: ExtensionInputs, scope: Scope) -> list[str]:
        if not inputs.targets:
            return []
        infile = targets_file(inputs, "subzy_hosts.txt")
        return ["subzy", "run", "--targets", infile, "--hide_fails"] + inputs.extra_flags

    def parse(self, output: str) -> ExtensionResult:
        takeovers: list[Takeover] = []
        for line in nonblank_lines(output):
            upper = line.upper()
            # "[ NOT VULNERABLE ]" contains the substring "VULNERABLE" — exclude it.
            if "NOT VULNERABLE" in upper or "VULNERABLE" not in upper:
                continue
            # Representative line: "[ VULNERABLE ] sub.example.com  (Github Pages)"
            host = ""
            service = None
            for token in line.replace("[", " ").replace("]", " ").split():
                if "." in token and token.lower() != "vulnerable":
                    host = token.strip().lower()
                    break
            if "(" in line and ")" in line:
                service = line[line.rfind("(") + 1 : line.rfind(")")].strip() or None
            if host:
                takeovers.append(Takeover(host=host, service=service, vulnerable=True))
        return ExtensionResult(extension=self.name, phase=self.phase, takeovers=takeovers)
