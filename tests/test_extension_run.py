"""Extension.run() behavior — availability, dry-run, and no-crash guarantees."""

from __future__ import annotations

import subprocess

from argus.core.scope import Scope
from argus.extensions import ExtensionInputs, get

SCOPE = Scope.from_dict({"in_scope": {"domains": ["example.com", "*.example.com"]}})
INPUTS = ExtensionInputs(targets=["example.com"], rate_limit=5, concurrency=10)


def test_missing_binary_degrades_gracefully(monkeypatch):
    monkeypatch.setattr("argus.extensions.base.Extension.is_available", lambda self: False)
    res = get("subfinder").run(INPUTS, SCOPE)
    assert res.available is False
    assert res.ran is False
    assert res.errors == []  # not an error, just skipped


def test_dry_run_builds_command_but_does_not_execute(monkeypatch):
    monkeypatch.setattr("argus.extensions.base.Extension.is_available", lambda self: True)

    def _boom(*a, **k):
        raise AssertionError("subprocess.run must not be called during dry-run")

    monkeypatch.setattr(subprocess, "run", _boom)
    res = get("httpx").run(INPUTS, SCOPE, dry_run=True)
    assert res.dry_run is True
    assert res.ran is False
    assert res.command and res.command[0] == "httpx"


def test_no_targets_yields_no_command(monkeypatch):
    monkeypatch.setattr("argus.extensions.base.Extension.is_available", lambda self: True)
    res = get("subfinder").run(ExtensionInputs(targets=[]), SCOPE, dry_run=True)
    assert res.ran is False
    assert res.command == []


def test_subprocess_failure_is_captured_not_raised(monkeypatch):
    monkeypatch.setattr("argus.extensions.base.Extension.is_available", lambda self: True)

    def _fail(*a, **k):
        raise OSError("no such file")

    monkeypatch.setattr(subprocess, "run", _fail)
    res = get("nuclei").run(INPUTS, SCOPE)
    assert res.errors and "exec failed" in res.errors[0]


def test_run_parses_real_output(monkeypatch, fixture_text):
    monkeypatch.setattr("argus.extensions.base.Extension.is_available", lambda self: True)

    class FakeProc:
        stdout = fixture_text("subfinder.txt")
        stderr = ""
        returncode = 0

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProc())
    res = get("subfinder").run(INPUTS, SCOPE)
    assert res.ran is True
    assert any(s.host == "api.example.com" for s in res.subdomains)


def test_naabu_only_scans_web_ports():
    cmd = get("naabu").build_command(INPUTS, SCOPE)
    assert "-port" in cmd
    ports = cmd[cmd.index("-port") + 1]
    # Every planned port is a web-relevant port; no full-range scanning.
    assert all(p in {"80", "443", "8080", "8443", "8000", "8888", "3000",
                     "5000", "8081", "9000", "9443"} for p in ports.split(","))
