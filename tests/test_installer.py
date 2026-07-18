"""Auto-installer tests (Task 5) — every subprocess call is mocked.

No real installs and no network: `runner`, `is_installed`, `confirm`, and `emit`
are all injected fakes.
"""

from __future__ import annotations

import pytest

from argus.install.check_tools import ToolStatus
from argus.install.installer import (
    InstallMethod,
    RunOutcome,
    build_plan,
    build_plans,
    go_bin_on_path,
    install_tools,
    render_plan_lines,
    select_method,
)


def _status(name: str, binary: str | None = None, available: bool = False, hint: str = "") -> ToolStatus:
    return ToolStatus(
        name=name, phase=1, binary=binary or name, available=available,
        path=None, install_hint=hint,
    )


def _always_missing(binary: str) -> bool:
    # apt-get present (Kali-like) so apt tools resolve to apt; every tool missing.
    return binary == "apt-get"


# ---- method selection --------------------------------------------------- #
@pytest.mark.parametrize(
    "name,expected",
    [
        ("nuclei", InstallMethod.APT),
        ("naabu", InstallMethod.APT),
        ("dnsx", InstallMethod.APT),
        ("gowitness", InstallMethod.APT),
        ("trufflehog", InstallMethod.APT),
        ("arjun", InstallMethod.APT),        # apt primary on Kali
        ("subfinder", InstallMethod.GO),
        ("katana", InstallMethod.GO),
        ("subzy", InstallMethod.GO),
        ("puredns", InstallMethod.GO),
        ("linkfinder", InstallMethod.LINKFINDER),
    ],
)
def test_method_selection_on_kali(name, expected):
    assert select_method(_status(name), has_apt=True) is expected


def test_method_selection_off_kali_falls_back():
    # no apt: apt-Python tool -> pipx, apt-Go tool -> go install
    assert select_method(_status("arjun"), has_apt=False) is InstallMethod.PIPX
    assert select_method(_status("nuclei"), has_apt=False) is InstallMethod.GO


# ---- plan construction -------------------------------------------------- #
def test_go_plan_reuses_install_hint():
    s = _status("subfinder", hint="go install github.com/pd/subfinder/v2/cmd/subfinder@latest")
    plan = build_plan(s, has_apt=True, is_installed=_always_missing)
    assert plan.method is InstallMethod.GO
    assert plan.commands[0].argv == [
        "go", "install", "github.com/pd/subfinder/v2/cmd/subfinder@latest"
    ]


def test_nuclei_updates_templates_after_install():
    plan = build_plan(_status("nuclei"), has_apt=True, is_installed=_always_missing)
    assert plan.post and plan.post[-1].argv == ["nuclei", "-update-templates"]


def test_naabu_has_libpcap_prereq_and_puredns_massdns():
    naabu = build_plan(_status("naabu"), has_apt=True, is_installed=_always_missing)
    assert any("libpcap-dev" in c.argv for c in naabu.prereqs)
    # massdns prereq present when massdns is not installed
    puredns = build_plan(_status("puredns"), has_apt=True, is_installed=_always_missing)
    assert any("massdns" in c.argv for c in puredns.prereqs)
    # ...and skipped when it's already there (idempotent)
    have_massdns = lambda b: b in ("apt-get", "massdns")  # noqa: E731
    puredns2 = build_plan(_status("puredns"), has_apt=True, is_installed=have_massdns)
    assert not puredns2.prereqs


def test_linkfinder_venv_shim_sequence_needs_sudo():
    plan = build_plan(_status("linkfinder"), has_apt=True, is_installed=_always_missing)
    assert plan.method is InstallMethod.LINKFINDER
    joined = " ".join(a for c in plan.commands for a in c.argv)
    assert "git" in joined and "venv" in joined and "requirements.txt" in joined
    assert "/usr/local/bin/linkfinder" in joined
    assert plan.needs_sudo  # writing the shim into /usr/local/bin


# ---- sudo surfacing ----------------------------------------------------- #
def test_render_surfaces_sudo_commands():
    plan = build_plan(_status("nuclei"), has_apt=True, is_installed=_always_missing)
    lines = "\n".join(render_plan_lines([plan]))
    assert "[needs sudo]" in lines
    assert "sudo apt-get install -y nuclei" in lines


def test_sudo_command_shown_before_any_runner_call():
    events: list[str] = []

    def emit(s):
        events.append(f"emit:{s}")

    def runner(argv):
        events.append(f"run:{' '.join(argv)}")
        return RunOutcome(returncode=0)

    statuses = [_status("nuclei")]
    install_tools(
        assume_yes=True, statuses=statuses, runner=runner,
        is_installed=lambda b: b == "apt-get" or b == "nuclei", emit=emit,
    )
    shown_sudo = next(i for i, e in enumerate(events) if "sudo apt-get install -y nuclei" in e and e.startswith("emit"))
    first_run = next(i for i, e in enumerate(events) if e.startswith("run:"))
    assert shown_sudo < first_run  # commands displayed before execution


# ---- confirmation gating ------------------------------------------------ #
def test_confirmation_declined_runs_nothing():
    calls: list[list[str]] = []
    install_tools(
        assume_yes=False, statuses=[_status("nuclei")],
        runner=lambda a: calls.append(a) or RunOutcome(),  # type: ignore[func-returns-value]
        is_installed=_always_missing, confirm=lambda: False, emit=lambda s: None,
    )
    assert calls == []  # nothing executed without confirmation


def test_confirmation_accepted_runs():
    calls: list[list[str]] = []

    def runner(argv):
        calls.append(argv)
        return RunOutcome(returncode=0)

    install_tools(
        assume_yes=False, statuses=[_status("nuclei")], runner=runner,
        is_installed=lambda b: True, confirm=lambda: True, emit=lambda s: None,
    )
    assert calls  # confirmed -> commands ran


def test_dry_run_shows_but_runs_nothing():
    calls: list = []
    install_tools(
        assume_yes=True, dry_run=True, statuses=[_status("nuclei")],
        runner=lambda a: calls.append(a), is_installed=_always_missing, emit=lambda s: None,
    )
    assert calls == []


# ---- batch resilience + re-check --------------------------------------- #
def test_one_failure_does_not_abort_batch():
    def runner(argv):
        if "naabu" in argv:
            return RunOutcome(returncode=1, stderr="E: package not found")
        return RunOutcome(returncode=0)

    def is_installed(binary):
        if binary == "apt-get":
            return True
        return binary != "naabu"  # naabu never lands; others do

    statuses = [_status("nuclei"), _status("naabu"), _status("dnsx")]
    results = install_tools(
        assume_yes=True, statuses=statuses, runner=runner,
        is_installed=is_installed, emit=lambda s: None,
    )
    by = {r.name: r for r in results}
    assert len(results) == 3            # all attempted despite the failure
    assert by["nuclei"].ok and by["dnsx"].ok
    assert not by["naabu"].ok


def test_recheck_flags_binary_that_never_appeared():
    # runner "succeeds" but the binary is still missing afterwards
    results = install_tools(
        assume_yes=True, statuses=[_status("subfinder", hint="go install x@latest")],
        runner=lambda a: RunOutcome(returncode=0),
        is_installed=lambda b: b == "apt-get",  # subfinder still missing
        emit=lambda s: None,
    )
    assert results[0].ok is False
    assert "still not found" in results[0].detail


def test_runner_exception_is_captured():
    def boom(argv):
        raise OSError("permission denied")

    results = install_tools(
        assume_yes=True, statuses=[_status("nuclei")], runner=boom,
        is_installed=lambda b: True, emit=lambda s: None,
    )
    assert results[0].ok is False and "errored" in results[0].detail


# ---- idempotency + PATH check ------------------------------------------ #
def test_build_plans_skips_present_tools():
    statuses = [
        _status("nuclei", available=True),   # already present -> skipped
        _status("naabu", available=False),
    ]
    plans = build_plans(statuses=statuses, is_installed=_always_missing)
    assert [p.name for p in plans] == ["naabu"]


def test_install_tools_noop_when_all_present():
    msgs: list[str] = []
    results = install_tools(
        assume_yes=True, statuses=[_status("nuclei", available=True)],
        runner=lambda a: RunOutcome(), is_installed=lambda b: True, emit=msgs.append,
    )
    assert results == []
    assert any("already installed" in m for m in msgs)


def test_go_bin_path_check():
    ok, _ = go_bin_on_path(env_path="/usr/bin:/home/u/go/bin", home="/home/u")
    assert ok
    bad, guidance = go_bin_on_path(env_path="/usr/bin", home="/home/u")
    assert not bad and "go/bin" in guidance
