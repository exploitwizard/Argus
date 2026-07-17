"""Skill/hints loading.

ARGUS loads a standing behavioral-rules file (``argus_skill.md`` or
``.argushints``) into the agent's system context on every run. This carries the
operator's non-negotiable rules — scope discipline, rate limits, report format,
and the hard "recon and detection only" boundary.

Lookup order (first found wins):
  1. ``$ARGUS_HINTS`` env var, if set
  2. ``./.argushints`` in the current working directory
  3. ``./argus_skill.md`` in the current working directory
  4. the packaged default shipped with ARGUS
"""

from __future__ import annotations

import os
from pathlib import Path

_PACKAGED = Path(__file__).resolve().parent.parent / "argus_skill.md"

_FALLBACK = (
    "You are ARGUS, an authorized web-application reconnaissance agent.\n"
    "- Recon and detection ONLY: never exploit, never brute-force auth, never spray creds.\n"
    "- Never act on out-of-scope hosts. The scope file is authoritative.\n"
    "- Honor the configured rate-limit and concurrency ceilings.\n"
    "- Never print or store secret values; only their metadata.\n"
)


def hints_path() -> Path | None:
    env = os.environ.get("ARGUS_HINTS")
    if env and Path(env).is_file():
        return Path(env)
    for candidate in (Path.cwd() / ".argushints", Path.cwd() / "argus_skill.md", _PACKAGED):
        if candidate.is_file():
            return candidate
    return None


def load_hints() -> str:
    path = hints_path()
    if path is None:
        return _FALLBACK
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return _FALLBACK
