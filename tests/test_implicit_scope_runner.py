"""Implicit-scope safety floor (Task 1).

Confirms that when a run uses an implicit scope (no scope file), hosts discovered
*outside* the registrable-domain root are dropped by the phase runner and never
handed to a tool — i.e. they receive no traffic without an explicit scope.
"""

from __future__ import annotations

from argus.core.models import ExtensionResult, Phase, Subdomain
from argus.core.scope import Scope
from argus.core.state import RunConfig
from argus.phases import runner


class _CapturingExt:
    """Stand-in extension that records the targets it is asked to run against."""

    name = "capture"

    def __init__(self) -> None:
        self.seen: list[str] = []

    def run(self, inputs, scope, dry_run=False):  # noqa: ANN001
        self.seen = list(inputs.targets)
        return ExtensionResult(extension=self.name, phase=Phase.HOST_DISCOVERY, available=True)


def _state_with_discovered_subdomains(hosts: list[str]) -> dict:
    scope = Scope.implicit("example.com")
    cfg = RunConfig(run_id="test", target="example.com", model="m", dry_run=True)
    prior = ExtensionResult(
        extension="subfinder",
        phase=Phase.ENUMERATION,
        subdomains=[Subdomain(host=h) for h in hosts],
    )
    return {
        "config": cfg.model_dump(),
        "scope": scope.model_dump(),
        "results": [prior.model_dump(mode="json")],
    }


def test_out_of_root_discovery_never_reaches_tool(monkeypatch):
    ext = _CapturingExt()
    monkeypatch.setattr(runner, "_select", lambda phase, cfg: [ext])

    state = _state_with_discovered_subdomains(
        ["api.example.com", "attacker.com", "asset.cloudfront.net", "mail.example.com"]
    )
    update = runner.run_tool_phase(state, Phase.HOST_DISCOVERY)

    # Only in-root hosts were handed to the tool.
    assert set(ext.seen) == {"api.example.com", "mail.example.com"}
    # The third-party hosts were dropped, not silently forgotten.
    assert set(update["dropped"]) == {"attacker.com", "asset.cloudfront.net"}
