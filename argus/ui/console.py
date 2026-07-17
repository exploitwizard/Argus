"""Terminal presentation layer: banner, colored phase banners, and the
first-run authorization gate. Kept free of business logic so a future
``textual`` dashboard can reuse the same primitives.
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from argus import __version__
from argus.core import paths

# Charcoal / red house style, matching the VAPT report palette.
ACCENT = "bold red"
CHARCOAL = "grey23"

console = Console()

_BANNER_ART = r"""
    ___    ____  ______ __  __ _____
   /   |  / __ \/ ____// / / // ___/
  / /| | / /_/ / / __ / / / / \__ \
 / ___ |/ _, _/ /_/ // /_/ / ___/ /
/_/  |_/_/ |_|\____/ \____/ /____/
"""


def print_banner() -> None:
    """Render the ARGUS banner with version and the authorized-use notice."""
    art = Text(_BANNER_ART, style=ACCENT)
    subtitle = Text.assemble(
        ("Autonomous Recon & Guided Unified Scanner", "bold white"),
        ("  v", "grey58"),
        (__version__, "grey58"),
    )
    body = Text.assemble(
        art,
        "\n",
        subtitle,
        "\n\n",
        ("recon & detection only — no exploitation, no auth brute-force", "italic grey58"),
    )
    console.print(
        Panel(
            body,
            border_style=ACCENT,
            title="[bold red]ARGUS[/]",
            subtitle="[grey58]authorized testing only[/]",
            padding=(1, 4),
        )
    )


def phase_banner(number: int, name: str) -> None:
    """Print a bold banner announcing the start of a phase."""
    console.print()
    console.print(
        Panel(
            Text(f"PHASE {number} — {name.upper()}", style="bold white", justify="center"),
            border_style=ACCENT,
            style=f"on {CHARCOAL}",
            padding=(0, 2),
        )
    )


def warn(msg: str) -> None:
    console.print(f"[bold yellow]⚠[/]  {msg}")


def error(msg: str) -> None:
    console.print(f"[bold red]✖[/]  {msg}")


def success(msg: str) -> None:
    console.print(f"[bold green]✔[/]  {msg}")


def info(msg: str) -> None:
    console.print(f"[grey58]•[/]  {msg}")


_AUTHORIZATION_NOTICE = """\
[bold red]AUTHORIZED USE ONLY[/]

ARGUS sends live reconnaissance traffic to the targets you point it at and
detects (does not exploit) vulnerabilities. Running it against systems you do
not own or lack [bold]explicit written authorization[/] to test may be a crime.

By continuing you confirm that:
  • You have written authorization to test every in-scope target.
  • You will honor the scope file's in/out-of-scope rules and rate limits.
  • You accept sole responsibility for how ARGUS is used.

This acknowledgement is stored locally so you are only asked once.
"""


def require_authorization(assume_yes: bool = False) -> bool:
    """First-run gate. Returns True if the operator has acknowledged the
    authorized-use notice (now or previously), False if they declined.

    Passing ``assume_yes=True`` records acknowledgement non-interactively
    (for the ``--i-am-authorized`` flag).
    """
    marker = paths.auth_ack_path()
    if marker.exists():
        return True

    console.print(Panel(_AUTHORIZATION_NOTICE, border_style=ACCENT, padding=(1, 3)))

    if assume_yes:
        _write_ack(marker)
        success("Authorization acknowledged (via --i-am-authorized).")
        return True

    try:
        answer = console.input(
            "[bold]Type [red]I AM AUTHORIZED[/red] to continue (or anything else to abort): [/]"
        ).strip()
    except (EOFError, KeyboardInterrupt):
        console.print()
        error("Aborted — authorization not acknowledged.")
        return False

    if answer == "I AM AUTHORIZED":
        _write_ack(marker)
        success("Authorization acknowledged. You will not be asked again on this machine.")
        return True

    error("Authorization not acknowledged — refusing to run.")
    return False


_LIVE_GATE_NOTICE = """\
[bold red]LIVE-TRAFFIC GATE[/]

The next phase sends live reconnaissance traffic to the target below. Review the
plan, then confirm. ARGUS performs recon & detection only — no exploitation.
"""


def live_run_gate(
    *,
    target: str,
    in_scope_hosts: int,
    phases: list[int],
    tool_names: list[str],
    assume_yes: bool = False,
) -> bool:
    """Human-in-the-loop gate shown before any live-traffic phase.

    Returns True to proceed, False to abort. ``assume_yes`` (from
    ``--i-am-authorized`` / non-interactive use) passes without prompting.
    """
    console.print(Panel(_LIVE_GATE_NOTICE, border_style=ACCENT, padding=(1, 3)))
    info(f"Target:            {target}")
    info(f"In-scope hosts:    {in_scope_hosts}")
    info(f"Phases to run:     {phases}")
    info(f"Available tools:   {', '.join(tool_names) if tool_names else '(none installed)'}")
    if assume_yes:
        success("Proceeding (authorization pre-accepted).")
        return True
    try:
        answer = console.input("[bold]Proceed with live traffic? Type [red]yes[/red]: [/]").strip()
    except (EOFError, KeyboardInterrupt):
        console.print()
        error("Aborted at live-traffic gate.")
        return False
    if answer.lower() == "yes":
        return True
    error("Aborted at live-traffic gate.")
    return False


def _write_ack(marker: Path) -> None:
    import datetime

    marker.write_text(
        f"acknowledged {datetime.datetime.now().isoformat(timespec='seconds')}\n",
        encoding="utf-8",
    )
