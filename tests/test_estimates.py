"""Tests for the rough runtime-estimate helpers (offline, deterministic)."""

from __future__ import annotations

from argus.core import estimates


def test_typical_seconds_known_and_fallback():
    assert estimates.typical_seconds("nuclei") == 300
    assert estimates.typical_seconds("subfinder") == 20
    # Unknown tool falls back to the default.
    assert estimates.typical_seconds("does-not-exist") == estimates.DEFAULT_SECONDS


def test_estimate_total_sums_planned_tools():
    planned = [(1, "subfinder"), (1, "dnsx"), (5, "nuclei")]
    assert estimates.estimate_total(planned) == 20 + 10 + 300


def test_estimate_total_empty_is_zero():
    assert estimates.estimate_total([]) == 0


def test_human_time_formatting():
    assert estimates.human_time(0) == "0s"
    assert estimates.human_time(45) == "45s"
    assert estimates.human_time(59) == "59s"
    assert estimates.human_time(60) == "1m00s"
    assert estimates.human_time(90) == "1m30s"
    assert estimates.human_time(3600) == "1h00m"
    assert estimates.human_time(3661) == "1h01m"


def test_human_time_negative_clamped():
    assert estimates.human_time(-10) == "0s"
