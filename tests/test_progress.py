"""Tests for the live progress reporter's bookkeeping (offline, deterministic).

The visual rendering is exercised indirectly; here we assert the done/remaining
counting and the no-op behavior when no reporter is active.
"""

from __future__ import annotations

import pytest

from argus.core.models import ExtensionResult, Phase
from argus.ui import progress as prog


@pytest.fixture(autouse=True)
def _clear_active():
    prog.clear_active()
    yield
    prog.clear_active()


def _fake_result() -> ExtensionResult:
    return ExtensionResult(extension="subfinder", phase=Phase.ENUMERATION, ran=True)


def test_run_tool_noop_without_active_reporter():
    called = {"n": 0}

    def fn() -> ExtensionResult:
        called["n"] += 1
        return _fake_result()

    res = prog.run_tool("subfinder", fn, dry_run=False)
    assert called["n"] == 1
    assert res.extension == "subfinder"
    # phase_header is also a no-op and must not raise.
    prog.phase_header(1)


def test_runprogress_counts_and_eta_countdown():
    reporter = prog.RunProgress([(1, "subfinder"), (1, "dnsx"), (5, "nuclei")])
    assert reporter.total == 3
    assert reporter.done == 0
    assert reporter.remaining_secs == 20 + 10 + 300

    prog.set_active(reporter)
    prog.run_tool("subfinder", _fake_result, dry_run=False)
    assert reporter.done == 1
    assert reporter.remaining_secs == 10 + 300  # subfinder's 20s subtracted

    prog.run_tool("nuclei", _fake_result, dry_run=False)
    assert reporter.done == 2
    assert reporter.remaining_secs == 10  # nuclei's 300s subtracted


def test_remaining_never_negative():
    reporter = prog.RunProgress([(1, "subfinder")])
    prog.set_active(reporter)
    # Run more tools than planned; remaining must clamp at 0, not go negative.
    prog.run_tool("nuclei", _fake_result, dry_run=False)
    assert reporter.remaining_secs == 0.0
    assert reporter.done == 1


def test_set_and_clear_active():
    assert prog.active() is None
    reporter = prog.RunProgress([])
    prog.set_active(reporter)
    assert prog.active() is reporter
    prog.clear_active()
    assert prog.active() is None
