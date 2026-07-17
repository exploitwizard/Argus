"""Shared pytest fixtures.

All tests run fully offline. Filesystem state (config, data, runs, checkpoints)
is redirected into a per-test temp dir so nothing touches the real user profile,
and no test ever performs a network call.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.core import paths

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


@pytest.fixture(autouse=True)
def isolate_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect ARGUS config/data dirs into a temp dir for every test."""
    cfg = tmp_path / "config"
    data = tmp_path / "data"
    cfg.mkdir(parents=True, exist_ok=True)
    data.mkdir(parents=True, exist_ok=True)

    def _config_dir() -> Path:
        cfg.mkdir(parents=True, exist_ok=True)
        return cfg

    def _data_dir() -> Path:
        data.mkdir(parents=True, exist_ok=True)
        return data

    monkeypatch.setattr(paths, "config_dir", _config_dir)
    monkeypatch.setattr(paths, "data_dir", _data_dir)
    return tmp_path


@pytest.fixture
def fixture_text():
    return load_fixture
