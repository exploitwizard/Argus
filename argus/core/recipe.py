"""Recipes — goose-style YAML playbooks.

A recipe bundles which phases/extensions run, their flags, model choice,
intensity, scope reference, and user-substitutable parameters into one
shareable, re-runnable file.

``${param}`` placeholders anywhere in the recipe are substituted from the
recipe's own ``parameters`` defaults, overlaid with CLI ``--param key=value``.
Undefined placeholders raise a clear error (goose-style validation).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, Field, field_validator

_PLACEHOLDER = re.compile(r"\$\{([a-zA-Z0-9_]+)\}")


class RetryPolicy(BaseModel):
    max_attempts: int = 1
    validate_output: bool = True


class Recipe(BaseModel):
    """A validated recon playbook."""

    name: str
    description: str = ""
    model: Optional[str] = None
    intensity: str = "med"
    scope: Optional[str] = None
    phases: list[int] = Field(default_factory=lambda: [1, 2, 3, 4, 5, 6])
    # per-phase extension selection; empty/absent => all available for that phase
    extensions: dict[int, list[str]] = Field(default_factory=dict)
    flags: dict[str, list[str]] = Field(default_factory=dict)
    parameters: dict[str, Any] = Field(default_factory=dict)
    retry: RetryPolicy = Field(default_factory=RetryPolicy)

    @field_validator("intensity")
    @classmethod
    def _valid_intensity(cls, v: str) -> str:
        if v not in {"low", "med", "high"}:
            raise ValueError(f"intensity must be low|med|high, got {v!r}")
        return v

    @field_validator("phases")
    @classmethod
    def _valid_phases(cls, v: list[int]) -> list[int]:
        bad = [p for p in v if p not in range(1, 7)]
        if bad:
            raise ValueError(f"phases must be within 1..6, got invalid {bad}")
        return v


def _substitute(obj: Any, params: dict[str, Any]) -> Any:
    """Recursively replace ${placeholders} in strings using ``params``."""
    if isinstance(obj, str):
        def repl(m: re.Match[str]) -> str:
            name = m.group(1)
            if name not in params:
                raise KeyError(name)
            return str(params[name])

        return _PLACEHOLDER.sub(repl, obj)
    if isinstance(obj, list):
        return [_substitute(x, params) for x in obj]
    if isinstance(obj, dict):
        return {k: _substitute(v, params) for k, v in obj.items()}
    return obj


def load_recipe(path: str | Path, overrides: Optional[dict[str, Any]] = None) -> Recipe:
    """Load, parameter-substitute, and validate a recipe file.

    ``overrides`` (from CLI ``--param``) take precedence over in-file
    ``parameters`` defaults. A ``${placeholder}`` with no value raises
    ``ValueError`` naming the missing parameter.
    """
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    params = dict(raw.get("parameters") or {})
    params.update(overrides or {})

    # normalize dict keys that YAML may parse as strings for phase maps
    if "extensions" in raw and isinstance(raw["extensions"], dict):
        raw["extensions"] = {int(k): v for k, v in raw["extensions"].items()}

    try:
        substituted = _substitute(raw, params)
    except KeyError as missing:
        raise ValueError(
            f"recipe {Path(path).name}: undefined parameter ${{{missing.args[0]}}} "
            f"(provide it with --param {missing.args[0]}=...)"
        ) from None

    substituted["parameters"] = params
    return Recipe(**{k: v for k, v in substituted.items() if k in Recipe.model_fields})


def parse_param_args(items: list[str]) -> dict[str, str]:
    """Parse ``--param key=value`` CLI arguments into a dict."""
    out: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"--param must be key=value, got {item!r}")
        k, _, v = item.partition("=")
        out[k.strip()] = v
    return out
