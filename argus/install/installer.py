"""Auto-installer — resolve and install missing recon tools.

Extends the dependency doctor (:mod:`argus.install.check_tools`) into an
installer. It reuses the extension registry's availability check, picks the
correct install method per tool (apt / go install / pipx / isolated-venv shim),
handles the Kali environment quirks, and is **idempotent** — already-present
tools are skipped.

Safety:
  * The exact commands are shown *before* anything runs; the CLI requires
    confirmation (``--yes`` to skip).
  * Any command needing ``sudo`` is surfaced before execution — never a silent
    privilege escalation.
  * Everything runs through injected ``runner`` / ``is_installed`` / ``confirm``
    / ``emit`` callables, so the test suite performs no real installs or network.
"""

from __future__ import annotations

import os
import shlex
import shutil
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable

from argus.install.check_tools import ToolStatus, check_all


class InstallMethod(str, Enum):
    APT = "apt"
    GO = "go"
    PIPX = "pipx"
    LINKFINDER = "linkfinder-venv-shim"


# Tools installed from the Kali apt repo (spec's apt list). Package == binary.
_APT_TOOLS = {"nuclei", "naabu", "dnsx", "gowitness", "arjun", "trufflehog"}
# Python tools that fall back to pipx when apt is unavailable (non-Kali).
_PIPX_FALLBACK = {"arjun"}
# apt prerequisite packages that must exist before a tool builds/runs.
_APT_PREREQS = {"naabu": "libpcap-dev", "puredns": "massdns"}

_LINKFINDER_REPO = "https://github.com/GerbenJavado/LinkFinder.git"
_LINKFINDER_DIR = "/opt/LinkFinder"
_LINKFINDER_SHIM = "/usr/local/bin/linkfinder"


@dataclass
class Command:
    """One shell command in an install plan."""

    argv: list[str]
    needs_sudo: bool = False

    def display(self) -> str:
        return " ".join(shlex.quote(a) for a in self.argv)


@dataclass
class InstallPlan:
    """The full, ordered set of commands to install one tool."""

    name: str
    binary: str
    method: InstallMethod
    prereqs: list[Command] = field(default_factory=list)
    commands: list[Command] = field(default_factory=list)
    post: list[Command] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def all_commands(self) -> list[Command]:
        return [*self.prereqs, *self.commands, *self.post]

    @property
    def needs_sudo(self) -> bool:
        return any(c.needs_sudo for c in self.all_commands())


@dataclass
class InstallResult:
    name: str
    binary: str
    method: InstallMethod
    ok: bool
    detail: str = ""


# --------------------------------------------------------------------------- #
# method selection
# --------------------------------------------------------------------------- #
def select_method(status: ToolStatus, *, has_apt: bool) -> InstallMethod:
    """Pick the install method for one tool.

    apt where the Kali package exists (falling back to go/pipx off-Kali),
    the isolated-venv shim for LinkFinder, otherwise ``go install``.
    """
    if status.name == "linkfinder":
        return InstallMethod.LINKFINDER
    if status.name in _APT_TOOLS:
        if has_apt:
            return InstallMethod.APT
        # off-Kali fallback: Python tools -> pipx, Go tools -> go install
        return InstallMethod.PIPX if status.name in _PIPX_FALLBACK else InstallMethod.GO
    return InstallMethod.GO


def _apt_prereq_commands(
    name: str, *, has_apt: bool, is_installed: Callable[[str], bool]
) -> list[Command]:
    """apt prerequisites (libpcap-dev, massdns) — verified first, installed if missing.

    Only emitted when apt is available; off-Kali the operator installs these by
    other means (a note is added instead).
    """
    pkg = _APT_PREREQS.get(name)
    if not pkg or not has_apt:
        return []
    # massdns provides a `massdns` binary we can probe; libpcap-dev is a lib, so
    # we (idempotently) ask apt regardless — apt is a no-op if already satisfied.
    if pkg == "massdns" and is_installed("massdns"):
        return []
    return [Command(["sudo", "apt-get", "install", "-y", pkg], needs_sudo=True)]


def build_plan(status: ToolStatus, *, has_apt: bool, is_installed: Callable[[str], bool]) -> InstallPlan:
    """Construct the install plan for a single (missing) tool."""
    method = select_method(status, has_apt=has_apt)
    prereqs = _apt_prereq_commands(status.name, has_apt=has_apt, is_installed=is_installed)
    commands: list[Command] = []
    post: list[Command] = []
    notes: list[str] = []
    if status.name in _APT_PREREQS and not has_apt:
        notes.append(
            f"Requires '{_APT_PREREQS[status.name]}' — install it via your system "
            "package manager (apt not detected)."
        )

    if method is InstallMethod.APT:
        commands.append(Command(["sudo", "apt-get", "install", "-y", status.binary], needs_sudo=True))
    elif method is InstallMethod.GO:
        commands.append(Command(_go_command(status)))
        notes.append("Ensure ~/go/bin is on your PATH so the binary is found.")
    elif method is InstallMethod.PIPX:
        commands.append(Command(["pipx", "install", _pip_package(status)]))
        notes.append("pipx installs outside the ARGUS venv, onto the system PATH.")
    elif method is InstallMethod.LINKFINDER:
        commands, notes = _linkfinder_commands()

    if status.name == "nuclei":
        post.append(Command(["nuclei", "-update-templates"]))

    return InstallPlan(
        name=status.name, binary=status.binary, method=method,
        prereqs=prereqs, commands=commands, post=post, notes=notes,
    )


def _go_command(status: ToolStatus) -> list[str]:
    """The ``go install`` argv — reuse the extension's install_hint when it is one."""
    hint = status.install_hint.strip()
    if hint.startswith("go install "):
        return shlex.split(hint.split("#", 1)[0].strip())
    return ["go", "install", f"{status.binary}@latest"]


def _pip_package(status: ToolStatus) -> str:
    return status.name


def _linkfinder_commands() -> tuple[list[Command], list[str]]:
    """Clone → dedicated venv → requirements → /usr/local/bin shim."""
    venv_py = f"{_LINKFINDER_DIR}/.venv/bin/python"
    shim = (
        f'#!/bin/sh\nexec {venv_py} {_LINKFINDER_DIR}/linkfinder.py "$@"\n'
    )
    cmds = [
        Command(["git", "clone", "--depth", "1", _LINKFINDER_REPO, _LINKFINDER_DIR]),
        Command(["python3", "-m", "venv", f"{_LINKFINDER_DIR}/.venv"]),
        Command([venv_py, "-m", "pip", "install", "-r", f"{_LINKFINDER_DIR}/requirements.txt"]),
        # write the shim then make it executable (surfaced as sudo — /usr/local/bin)
        Command(["sudo", "tee", _LINKFINDER_SHIM], needs_sudo=True),
        Command(["sudo", "chmod", "+x", _LINKFINDER_SHIM], needs_sudo=True),
    ]
    notes = [
        "LinkFinder runs from its own venv; the shim at "
        f"{_LINKFINDER_SHIM} points at {venv_py}.",
        f"Shim contents:\n{shim.strip()}",
    ]
    return cmds, notes


# --------------------------------------------------------------------------- #
# environment checks
# --------------------------------------------------------------------------- #
def has_apt(is_installed: Callable[[str], bool] | None = None) -> bool:
    check = is_installed or (lambda b: shutil.which(b) is not None)
    return check("apt-get")


def go_bin_on_path(env_path: str | None = None, home: str | None = None) -> tuple[bool, str]:
    """Check that ``~/go/bin`` is on PATH; return (ok, guidance-if-not)."""
    path = env_path if env_path is not None else os.environ.get("PATH", "")
    home_dir = Path(home) if home else Path.home()
    go_bin = str(home_dir / "go" / "bin")
    entries = path.split(os.pathsep)
    if go_bin in entries:
        return True, ""
    return False, (
        f"~/go/bin ({go_bin}) is not on your PATH — go-installed tools won't be "
        f"found. Add:  export PATH=\"$PATH:{go_bin}\"  to your shell profile."
    )


# --------------------------------------------------------------------------- #
# planning + execution
# --------------------------------------------------------------------------- #
def _default_is_installed(binary: str) -> bool:
    return shutil.which(binary) is not None


def build_plans(
    *,
    only_missing: bool = True,
    statuses: list[ToolStatus] | None = None,
    is_installed: Callable[[str], bool] | None = None,
) -> list[InstallPlan]:
    """Plans for every tool that needs installing (idempotent: present ones skipped)."""
    is_installed = is_installed or _default_is_installed
    statuses = statuses if statuses is not None else check_all()
    apt = has_apt(is_installed)
    plans: list[InstallPlan] = []
    for s in statuses:
        if only_missing and s.available:
            continue
        plans.append(build_plan(s, has_apt=apt, is_installed=is_installed))
    return plans


def render_plan_lines(plans: list[InstallPlan]) -> list[str]:
    """Human-readable rendering of every command that would run, sudo surfaced."""
    lines: list[str] = []
    for p in plans:
        tag = "  [needs sudo]" if p.needs_sudo else ""
        lines.append(f"{p.name} ({p.method.value}){tag}:")
        for c in p.all_commands():
            marker = "sudo " if c.needs_sudo and not c.argv[0] == "sudo" else ""
            lines.append(f"    $ {marker}{c.display()}")
        for note in p.notes:
            lines.append(f"    # {note}")
    return lines


@dataclass
class RunOutcome:
    returncode: int = 0
    stderr: str = ""


Runner = Callable[[list[str]], RunOutcome]
Emit = Callable[[str], None]


def _execute_plan(
    plan: InstallPlan, *, runner: Runner, is_installed: Callable[[str], bool], emit: Emit,
) -> InstallResult:
    """Run one plan's commands, then re-check availability. Never raises."""
    for cmd in plan.all_commands():
        if cmd.needs_sudo:
            emit(f"  [sudo] {cmd.display()}")   # surface privilege escalation
        else:
            emit(f"  $ {cmd.display()}")
        try:
            outcome = runner(cmd.argv)
        except Exception as exc:  # a command blowing up must not abort the batch
            return InstallResult(plan.name, plan.binary, plan.method, ok=False,
                                 detail=f"command errored: {exc}")
        if outcome.returncode != 0:
            return InstallResult(plan.name, plan.binary, plan.method, ok=False,
                                 detail=(outcome.stderr or f"exit {outcome.returncode}").strip()[:200])

    # re-check: did the binary actually land?
    if is_installed(plan.binary):
        return InstallResult(plan.name, plan.binary, plan.method, ok=True, detail="installed")
    return InstallResult(plan.name, plan.binary, plan.method, ok=False,
                         detail="ran, but binary still not found on PATH")


def install_tools(
    *,
    assume_yes: bool,
    dry_run: bool = False,
    only_missing: bool = True,
    statuses: list[ToolStatus] | None = None,
    runner: Runner | None = None,
    is_installed: Callable[[str], bool] | None = None,
    confirm: Callable[[], bool] | None = None,
    emit: Emit | None = None,
) -> list[InstallResult]:
    """Orchestrate the install: show plan → confirm → per-tool run → re-check.

    One tool failing never aborts the others. Returns a result per attempted
    tool. All side effects go through injected callables (tests pass fakes).
    """
    emit = emit or (lambda s: None)
    is_installed = is_installed or _default_is_installed
    confirm = confirm or (lambda: False)

    plans = build_plans(only_missing=only_missing, statuses=statuses, is_installed=is_installed)
    if not plans:
        emit("All recon tools are already installed. Nothing to do.")
        return []

    # 1. Show the exact commands FIRST (sudo surfaced) — before anything runs.
    emit("The following commands will be run:")
    for line in render_plan_lines(plans):
        emit(line)

    if any(p.needs_sudo for p in plans):
        emit("Some steps require sudo (shown above). You will be prompted by sudo itself.")

    if dry_run:
        emit("[dry-run] No commands were executed.")
        return []

    # 2. Confirmation gate (skipped by --yes / assume_yes).
    if not assume_yes and not confirm():
        emit("Aborted — no changes made.")
        return []

    # 3. Per-tool: run → re-check → report; continue past failures.
    if runner is None:
        runner = _subprocess_runner
    results: list[InstallResult] = []
    for plan in plans:
        emit(f"Installing {plan.name} via {plan.method.value}…")
        res = _execute_plan(plan, runner=runner, is_installed=is_installed, emit=emit)
        results.append(res)
        emit(f"  {'✔' if res.ok else '✖'} {plan.name}: {res.detail}")

    ok = sum(1 for r in results if r.ok)
    emit(f"Done: {ok}/{len(results)} tool(s) installed. "
         f"{len(results) - ok} still missing." if ok < len(results)
         else f"Done: all {ok} tool(s) installed.")
    return results


def _subprocess_runner(argv: list[str]) -> RunOutcome:
    import subprocess

    proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    return RunOutcome(returncode=proc.returncode, stderr=proc.stderr or "")
