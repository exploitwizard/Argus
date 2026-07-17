"""Extension registry — the self-registration and lookup layer.

Extensions register themselves with ``@register`` at import time. Phases and the
CLI ask the registry for "all Phase-N extensions" or "all *available* Phase-N
extensions" instead of hardcoding tool calls.
"""

from __future__ import annotations

from argus.core.models import Phase
from argus.extensions.base import Extension

_REGISTRY: dict[str, Extension] = {}


def register(cls: type[Extension]) -> type[Extension]:
    """Class decorator: instantiate and register an extension by its ``name``."""
    instance = cls()
    if not instance.name:
        raise ValueError(f"{cls.__name__} must set a non-empty `name`")
    if instance.name in _REGISTRY:
        raise ValueError(f"duplicate extension name: {instance.name!r}")
    _REGISTRY[instance.name] = instance
    return cls


def all_extensions() -> list[Extension]:
    """Every registered extension, ordered by phase then name."""
    return sorted(_REGISTRY.values(), key=lambda e: (int(e.phase), e.name))


def get(name: str) -> Extension:
    return _REGISTRY[name]


def has(name: str) -> bool:
    return name in _REGISTRY


def for_phase(phase: Phase | int) -> list[Extension]:
    """All extensions declared for ``phase`` (available or not)."""
    p = int(phase)
    return [e for e in all_extensions() if int(e.phase) == p]


def available_for_phase(phase: Phase | int) -> list[Extension]:
    """Only the extensions for ``phase`` whose binary is installed."""
    return [e for e in for_phase(phase) if e.is_available()]
