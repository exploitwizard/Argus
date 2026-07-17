"""Recipe loading, parameter substitution, and validation tests."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from argus.core.recipe import Recipe, load_recipe, parse_param_args


def _write(tmp_path: Path, text: str) -> str:
    p = tmp_path / "recipe.yaml"
    p.write_text(textwrap.dedent(text), encoding="utf-8")
    return str(p)


def test_load_shipped_recipes():
    root = Path(__file__).resolve().parent.parent / "argus" / "recipes"
    for name in ("quick-recon.yaml", "deep-recon.yaml"):
        r = load_recipe(root / name)
        assert isinstance(r, Recipe)
        assert r.phases


def test_parameter_substitution(tmp_path):
    path = _write(
        tmp_path,
        """
        name: t
        intensity: ${intensity}
        scope: ${scope_path}
        parameters:
          intensity: high
          scope_path: /tmp/scope.yaml
        """,
    )
    r = load_recipe(path)
    assert r.intensity == "high"
    assert r.scope == "/tmp/scope.yaml"


def test_cli_override_beats_default(tmp_path):
    path = _write(
        tmp_path,
        """
        name: t
        intensity: ${intensity}
        parameters:
          intensity: low
        """,
    )
    r = load_recipe(path, overrides={"intensity": "med"})
    assert r.intensity == "med"


def test_undefined_parameter_raises(tmp_path):
    path = _write(
        tmp_path,
        """
        name: t
        scope: ${missing}
        """,
    )
    with pytest.raises(ValueError) as exc:
        load_recipe(path)
    assert "missing" in str(exc.value)


def test_invalid_intensity_rejected(tmp_path):
    path = _write(tmp_path, "name: t\nintensity: ludicrous\n")
    with pytest.raises(Exception):
        load_recipe(path)


def test_invalid_phase_rejected(tmp_path):
    path = _write(tmp_path, "name: t\nphases: [1, 2, 9]\n")
    with pytest.raises(Exception):
        load_recipe(path)


def test_extension_phase_keys_coerced_to_int(tmp_path):
    path = _write(
        tmp_path,
        """
        name: t
        extensions:
          1: [subfinder]
          2: [httpx]
        """,
    )
    r = load_recipe(path)
    assert r.extensions[1] == ["subfinder"]
    assert r.extensions[2] == ["httpx"]


def test_parse_param_args():
    assert parse_param_args(["a=1", "b=x=y"]) == {"a": "1", "b": "x=y"}
    with pytest.raises(ValueError):
        parse_param_args(["bad"])
