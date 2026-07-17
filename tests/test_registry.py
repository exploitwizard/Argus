"""Extension registry tests."""

from __future__ import annotations

import pytest

from argus.core.models import Phase
from argus.extensions import all_extensions, available_for_phase, for_phase, get, has

EXPECTED = {
    1: {"subfinder", "amass", "puredns", "dnsx"},
    2: {"httpx", "naabu", "subzy"},
    3: {"katana", "gau", "ffuf"},
    4: {"linkfinder", "trufflehog", "arjun"},
    5: {"nuclei", "gowitness"},
}


def test_all_fifteen_register():
    names = {e.name for e in all_extensions()}
    assert len(all_extensions()) == 15
    assert names == set().union(*EXPECTED.values())


@pytest.mark.parametrize("phase,names", EXPECTED.items())
def test_for_phase_membership(phase, names):
    assert {e.name for e in for_phase(phase)} == names


def test_every_extension_has_contract_fields():
    for e in all_extensions():
        assert e.name and e.required_binary and e.install_hint
        assert isinstance(e.phase, Phase)


def test_get_and_has():
    assert has("subfinder")
    assert not has("nope")
    assert get("nuclei").phase == Phase.VULN_SCAN


def test_available_for_phase_respects_installed(monkeypatch):
    # Force everything unavailable -> nothing is returned as available.
    monkeypatch.setattr("argus.extensions.base.Extension.is_available", lambda self: False)
    assert available_for_phase(1) == []


def test_duplicate_registration_rejected():
    from argus.extensions.base import Extension
    from argus.extensions.registry import register

    with pytest.raises(ValueError):
        @register
        class Dup(Extension):
            name = "subfinder"  # already taken
            required_binary = "x"

            def build_command(self, inputs, scope):
                return []

            def parse(self, output):
                return self._empty()
