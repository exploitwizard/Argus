"""Live per-tool progress for a recon run.

While the pipeline runs each external tool with its output captured, this module
gives the terminal something to watch: a spinner for the tool currently running,
and a per-tool line as each finishes showing ``done/total`` and a live ETA that
counts down using the estimates in :mod:`argus.core.estimates`.

The active reporter is a module-level singleton because the LangGraph state is
serialized (a live object can't live in it). :func:`set_active` is called once
per run around ``graph.invoke``; each phase calls :func:`run_tool` / :func:`phase_header`.
When no reporter is active (unit tests calling a phase directly), the helpers are
no-ops that simply run the tool — so nothing is coupled to the UI being present.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from argus.core.estimates import human_time, typical_seconds
from argus.core.models import ExtensionResult, Phase
from argus.ui import console as ui


def _summarize(res: ExtensionResult, dry_run: bool) -> str:
    """One short phrase describing what a tool produced."""
    if not res.available:
        return "[yellow]skipped — not installed[/]"
    if dry_run:
        return "[grey58]planned (no traffic)[/]" if res.command else "[grey58]no in-scope targets[/]"
    if not res.ran:
        return "[grey58]no in-scope targets[/]"
    n = res.item_count
    if res.errors:
        return f"[yellow]{n} item(s), {len(res.errors)} error(s)[/]"
    return f"{n} item(s)"


class RunProgress:
    """Tracks how many tool-runs are done vs remaining and renders each one."""

    def __init__(self, planned: list[tuple[int, str]]) -> None:
        self.total = len(planned)
        self.done = 0
        self.remaining_secs = sum(typical_seconds(n) for _, n in planned)
        self.started = time.monotonic()

    def phase_header(self, phase: int) -> None:
        ui.console.print(f"\n[bold red]Phase {int(phase)}[/] — {Phase(phase).label}")

    def run_tool(self, name: str, fn: Callable[[], ExtensionResult], *, dry_run: bool) -> ExtensionResult:
        """Show a spinner while ``fn`` runs, then print the completion line."""
        eta = human_time(self.remaining_secs)
        status = (
            f"  [bold]{name}[/] running…  "
            f"[grey58][{self.done}/{self.total} done · ~{eta} left][/]"
        )
        t0 = time.monotonic()
        # Rich's status spinner is transient (clears when done) and degrades to a
        # no-op on non-terminals, so tests and piped output stay clean.
        with ui.console.status(status, spinner="dots"):
            res = fn()
        elapsed = time.monotonic() - t0

        self.done += 1
        self.remaining_secs = max(0.0, self.remaining_secs - typical_seconds(name))
        left = human_time(self.remaining_secs)
        ui.console.print(
            f"  [green]✔[/] {name:<12} [grey58]{elapsed:5.1f}s[/] · {_summarize(res, dry_run)}"
            f"   [grey58][{self.done}/{self.total} · ~{left} left][/]"
        )
        return res

    def finish(self) -> None:
        elapsed = human_time(time.monotonic() - self.started)
        ui.console.print(f"\n[grey58]Recon finished — {self.done} tool run(s) in {elapsed}.[/]")


# --------------------------------------------------------------------------- #
# module-level active reporter
# --------------------------------------------------------------------------- #
_active: RunProgress | None = None


def set_active(progress: RunProgress | None) -> None:
    global _active
    _active = progress


def active() -> RunProgress | None:
    return _active


def clear_active() -> None:
    global _active
    _active = None


def phase_header(phase: int) -> None:
    if _active is not None:
        _active.phase_header(phase)


def run_tool(name: str, fn: Callable[[], ExtensionResult], *, dry_run: bool) -> ExtensionResult:
    """Run ``fn`` under the active reporter, or plainly if none is active."""
    if _active is None:
        return fn()
    return _active.run_tool(name, fn, dry_run=dry_run)
