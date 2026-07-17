"""Small helpers shared by tool extensions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from argus.extensions.base import ExtensionInputs

# Web-relevant ports only. ARGUS never does general host/network port scanning.
WEB_PORTS = "80,443,8080,8443,8000,8888,3000,5000,8081,9000,9443"


def targets_file(inputs: ExtensionInputs, name: str) -> str:
    """Write the in-scope targets to ``run_dir/name`` and return its path.

    Writing a local input file sends no network traffic, so it is safe under
    dry-run. When no ``run_dir`` is set (pure planning/unit tests), a stable
    placeholder path is returned instead of touching the filesystem.
    """
    if not inputs.run_dir:
        return f"<{name}>"
    path = Path(inputs.run_dir) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(inputs.targets) + "\n", encoding="utf-8")
    return str(path)


def iter_json_lines(output: str) -> Iterator[dict]:
    """Yield parsed objects from JSON-lines output, skipping blanks/garbage."""
    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except (ValueError, json.JSONDecodeError):
            continue
        if isinstance(obj, dict):
            yield obj


def nonblank_lines(output: str) -> Iterator[str]:
    for line in output.splitlines():
        line = line.strip()
        if line:
            yield line
