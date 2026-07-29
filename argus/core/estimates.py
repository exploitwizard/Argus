"""Rough runtime estimates for the recon pipeline.

These are deliberately coarse, offline heuristics: a typical wall-clock cost per
tool on a small target, used to show an up-front "this will take about N" and a
live ETA that counts down as tools finish. They are *estimates* — real duration
depends on the target, network, and how much each phase discovers. nuclei and
amass dominate, which is why the numbers are weighted toward them.
"""

from __future__ import annotations

# Typical wall-clock seconds for one run of each tool on a small target.
# Keyed by the extension ``name``. Anything unlisted falls back to DEFAULT.
TYPICAL_SECONDS: dict[str, float] = {
    # Phase 1 — enumeration
    "subfinder": 20,
    "amass": 90,     # passive enum is slow to settle
    "puredns": 20,
    "dnsx": 10,
    # Phase 2 — host/service discovery
    "httpx": 15,
    "naabu": 30,
    "subzy": 10,
    # Phase 3 — content/url harvesting
    "katana": 45,
    "gau": 20,
    "ffuf": 60,
    # Phase 4 — deep analysis
    "linkfinder": 10,
    "trufflehog": 15,
    "arjun": 60,     # probes each URL for hidden params
    # Phase 5 — vuln scan & triage
    "nuclei": 300,   # thousands of templates — the long pole
    "gowitness": 30,
}

DEFAULT_SECONDS = 30.0


def typical_seconds(tool: str) -> float:
    """Rough typical runtime (seconds) for one run of ``tool``."""
    return float(TYPICAL_SECONDS.get(tool, DEFAULT_SECONDS))


def estimate_total(planned: list[tuple[int, str]]) -> float:
    """Sum the typical runtimes of a planned ``(phase, tool)`` list."""
    return sum(typical_seconds(name) for _, name in planned)


def human_time(seconds: float) -> str:
    """Format a duration as a compact human string: ``45s``, ``12m30s``, ``1h05m``."""
    total = round(max(0.0, seconds))
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h{m:02d}m"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"
