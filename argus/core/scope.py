"""Scope enforcement — the contract that keeps a run inside authorized bounds.

Every host/URL ARGUS is about to touch is checked here *before* any tool runs.
Out-of-scope items are dropped and logged, never sent. Out-of-scope rules take
precedence over in-scope rules.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field


class Limits(BaseModel):
    max_concurrency: int = 20
    requests_per_second: int = 10
    max_hosts_per_phase: int = 500


class Scope(BaseModel):
    """Parsed scope file plus the matching logic that enforces it."""

    engagement: str = "unspecified"
    authorized_by: str = "unspecified"
    in_scope_domains: list[str] = Field(default_factory=list)
    in_scope_cidrs: list[str] = Field(default_factory=list)
    out_of_scope_domains: list[str] = Field(default_factory=list)
    out_of_scope_cidrs: list[str] = Field(default_factory=list)
    limits: Limits = Field(default_factory=Limits)
    intensity: str = "med"

    # ---- loading -------------------------------------------------------- #
    @classmethod
    def from_yaml(cls, path: str | Path) -> "Scope":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls.from_dict(data)

    @classmethod
    def implicit(cls, target: str) -> "Scope":
        """Derive a target-only scope for implicit-scope mode.

        The target's *registrable domain* becomes the scope root: the apex plus
        every subdomain of it. An IP target is scoped to that exact host (``/32``
        or ``/128``). Nothing outside this root is in scope, so assets discovered
        elsewhere are dropped by :meth:`filter` and never probed.
        """
        host = _host_of(target)
        ip = _as_ip(host)
        if ip is not None:
            suffix = "/32" if ip.version == 4 else "/128"
            return cls(
                engagement="implicit-scope",
                in_scope_cidrs=[f"{host}{suffix}"],
            )
        root = registrable_domain(host) or host
        return cls(
            engagement="implicit-scope",
            in_scope_domains=[root, f"*.{root}"],
        )

    @classmethod
    def from_dict(cls, data: dict) -> "Scope":
        in_scope = data.get("in_scope") or {}
        out_scope = data.get("out_of_scope") or {}
        limits = data.get("limits") or {}
        return cls(
            engagement=data.get("engagement", "unspecified"),
            authorized_by=data.get("authorized_by", "unspecified"),
            in_scope_domains=[_norm(d) for d in (in_scope.get("domains") or [])],
            in_scope_cidrs=list(in_scope.get("cidrs") or []),
            out_of_scope_domains=[_norm(d) for d in (out_scope.get("domains") or [])],
            out_of_scope_cidrs=list(out_scope.get("cidrs") or []),
            limits=Limits(**limits) if limits else Limits(),
            intensity=data.get("intensity", "med"),
        )

    # ---- matching ------------------------------------------------------- #
    def is_in_scope(self, target: str) -> bool:
        """True only if ``target`` matches an in-scope rule and no out rule.

        ``target`` may be a bare host, an IP, or a URL. Out-of-scope always wins.
        """
        host = _host_of(target)
        if not host:
            return False
        if self._matches_any(host, self.out_of_scope_domains, self.out_of_scope_cidrs):
            return False
        return self._matches_any(host, self.in_scope_domains, self.in_scope_cidrs)

    def filter(self, targets: list[str]) -> tuple[list[str], list[str]]:
        """Split ``targets`` into (kept_in_scope, dropped_out_of_scope)."""
        kept: list[str] = []
        dropped: list[str] = []
        for t in targets:
            (kept if self.is_in_scope(t) else dropped).append(t)
        return kept, dropped

    # ---- internals ------------------------------------------------------ #
    def _matches_any(self, host: str, domains: list[str], cidrs: list[str]) -> bool:
        ip = _as_ip(host)
        if ip is not None:
            for cidr in cidrs:
                try:
                    if ip in ipaddress.ip_network(cidr, strict=False):
                        return True
                except ValueError:
                    continue
        for pattern in domains:
            if _domain_match(host, pattern):
                return True
        return False


# Common multi-label public suffixes. Not the full PSL (which would need a
# network fetch / bundled data file); a curated set that covers the registries
# ARGUS realistically meets. Derivation stays fully offline for the test suite.
_MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset(
    {
        "co.uk", "org.uk", "me.uk", "gov.uk", "ac.uk", "net.uk", "sch.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
        "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
        "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in", "gov.in", "ac.in",
        "co.za", "org.za", "net.za", "gov.za",
        "com.br", "net.br", "org.br", "gov.br",
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
        "com.cn", "net.cn", "org.cn", "gov.cn",
        "com.sg", "edu.sg", "gov.sg", "net.sg", "org.sg",
        "com.mx", "com.tr", "com.tw", "com.hk", "com.my", "com.ar", "com.co",
        "co.id", "co.kr", "co.il", "co.th", "or.th", "in.th",
    }
)


def registrable_domain(host: str) -> str | None:
    """Return the registrable domain (eTLD+1) of ``host``, or ``None``.

    ``api.example.com`` → ``example.com``; ``a.b.example.co.uk`` →
    ``example.co.uk``. Returns ``None`` for IPs or hosts too short to have an
    apex. Uses the curated :data:`_MULTI_LABEL_SUFFIXES` set for two-label TLDs.
    """
    host = _host_of(host)
    if not host or _as_ip(host) is not None:
        return None
    labels = host.split(".")
    if len(labels) < 2:
        return None
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def _norm(d: str) -> str:
    return d.strip().lower().rstrip(".")


def _host_of(target: str) -> str:
    t = target.strip().lower()
    if "://" in t:
        parsed = urlparse(t)
        host = parsed.hostname or ""
    else:
        # strip any path/port that slipped in without a scheme
        host = t.split("/")[0].split(":")[0]
    return host.rstrip(".")


def _as_ip(host: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _domain_match(host: str, pattern: str) -> bool:
    """Match a host against a domain pattern.

    ``*.example.com`` matches ``example.com`` and any subdomain of it. A bare
    ``example.com`` matches only that exact host.
    """
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    return host == pattern
