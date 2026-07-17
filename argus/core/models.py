"""Typed domain models for ARGUS.

Every piece of data that moves between extensions, phases, the graph state, and
the report is a Pydantic model defined here. Tool parsers return
:class:`ExtensionResult`; the graph merges those into the run state.

Security note: secret-hunting results deliberately store only *metadata* about a
finding (detector, location, verified flag) — never the secret value itself.
"""

from __future__ import annotations

from enum import IntEnum

from pydantic import BaseModel, Field


class Phase(IntEnum):
    """The six recon phases. Ordering matters — the graph runs them in order."""

    ENUMERATION = 1
    HOST_DISCOVERY = 2
    CONTENT_HARVEST = 3
    DEEP_ANALYSIS = 4
    VULN_SCAN = 5
    REPORTING = 6

    @property
    def label(self) -> str:
        return {
            1: "Enumeration",
            2: "Host/Service Discovery",
            3: "Content/URL Harvesting",
            4: "Deep Analysis",
            5: "Vuln Scan & Triage",
            6: "Reporting",
        }[int(self)]


# --------------------------------------------------------------------------- #
# Per-tool result item models
# --------------------------------------------------------------------------- #
class Subdomain(BaseModel):
    host: str
    source: str = "unknown"


class LiveHost(BaseModel):
    url: str
    status_code: int | None = None
    title: str | None = None
    webserver: str | None = None
    tech: list[str] = Field(default_factory=list)


class OpenPort(BaseModel):
    host: str
    port: int


class Takeover(BaseModel):
    host: str
    service: str | None = None
    vulnerable: bool = False


class Url(BaseModel):
    url: str
    source: str = "unknown"


class JsEndpoint(BaseModel):
    endpoint: str
    source_js: str | None = None


class SecretHit(BaseModel):
    """Metadata about a discovered secret. The secret value is never stored."""

    detector: str
    location: str
    verified: bool = False


class DiscoveredParam(BaseModel):
    url: str
    param: str


class Finding(BaseModel):
    template_id: str
    name: str
    severity: str = "info"
    matched_at: str
    tags: list[str] = Field(default_factory=list)


class Screenshot(BaseModel):
    url: str
    path: str


# --------------------------------------------------------------------------- #
# Uniform extension result container
# --------------------------------------------------------------------------- #
class ExtensionResult(BaseModel):
    """Uniform, typed container every extension parser returns.

    A parser only fills the fields relevant to its tool; everything else stays
    empty. This keeps merging into the run state trivial and fully typed.
    """

    extension: str
    phase: Phase
    available: bool = True
    ran: bool = False
    dry_run: bool = False
    command: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    subdomains: list[Subdomain] = Field(default_factory=list)
    live_hosts: list[LiveHost] = Field(default_factory=list)
    open_ports: list[OpenPort] = Field(default_factory=list)
    takeovers: list[Takeover] = Field(default_factory=list)
    urls: list[Url] = Field(default_factory=list)
    js_endpoints: list[JsEndpoint] = Field(default_factory=list)
    secrets: list[SecretHit] = Field(default_factory=list)
    params: list[DiscoveredParam] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    screenshots: list[Screenshot] = Field(default_factory=list)

    @property
    def item_count(self) -> int:
        return (
            len(self.subdomains)
            + len(self.live_hosts)
            + len(self.open_ports)
            + len(self.takeovers)
            + len(self.urls)
            + len(self.js_endpoints)
            + len(self.secrets)
            + len(self.params)
            + len(self.findings)
            + len(self.screenshots)
        )
