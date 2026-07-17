"""ARGUS extension system — goose-style pluggable recon-tool interface.

Importing this package eagerly imports every tool module so their ``@register``
decorators populate the registry. Downstream code should import the registry
functions from here.
"""

from __future__ import annotations

from argus.extensions.base import Extension, ExtensionInputs
from argus.extensions.registry import (
    all_extensions,
    available_for_phase,
    for_phase,
    get,
    has,
    register,
)

# Importing these modules triggers self-registration of each extension.
from argus.extensions import (  # noqa: E402,F401  (import-for-side-effects)
    p1_enumeration,
    p2_hosts,
    p3_content,
    p4_analysis,
    p5_vuln,
)

__all__ = [
    "Extension",
    "ExtensionInputs",
    "register",
    "all_extensions",
    "available_for_phase",
    "for_phase",
    "get",
    "has",
]
