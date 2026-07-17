"""Dependency doctor — verify each recon binary and print install hints.

Drives entirely off the extension registry, so it always reflects exactly the
tools ARGUS can actually run. Missing tools are reported, not fatal — ARGUS
degrades gracefully.
"""

from __future__ import annotations

import shutil

from pydantic import BaseModel

from argus.core.models import Phase
from argus.extensions import all_extensions


class ToolStatus(BaseModel):
    name: str
    phase: int
    binary: str
    available: bool
    path: str | None
    install_hint: str


def check_all() -> list[ToolStatus]:
    """Probe every registered extension's binary."""
    out: list[ToolStatus] = []
    for ext in all_extensions():
        path = shutil.which(ext.required_binary)
        out.append(
            ToolStatus(
                name=ext.name,
                phase=int(ext.phase),
                binary=ext.required_binary,
                available=path is not None,
                path=path,
                install_hint=ext.install_hint,
            )
        )
    return out


def summary(statuses: list[ToolStatus]) -> tuple[int, int]:
    available = sum(1 for s in statuses if s.available)
    return available, len(statuses)


def group_by_phase(statuses: list[ToolStatus]) -> dict[int, list[ToolStatus]]:
    grouped: dict[int, list[ToolStatus]] = {}
    for s in statuses:
        grouped.setdefault(s.phase, []).append(s)
    return dict(sorted(grouped.items()))


def phase_label(phase: int) -> str:
    return Phase(phase).label
