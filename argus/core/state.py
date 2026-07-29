"""LangGraph run state and the config that seeds a run.

The state is a plain TypedDict (LangGraph's native shape). Extension results
accumulate through an additive reducer so each phase appends without clobbering
earlier phases.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict

from pydantic import BaseModel, Field

from argus.core.models import ExtensionResult, Weakness
from argus.core.scope import Scope


class RunConfig(BaseModel):
    """Immutable per-run configuration derived from CLI + recipe + scope."""

    run_id: str
    target: str
    model: str
    models: list[str] = Field(default_factory=list)  # ensemble; [] => single `model`
    multi_mode: str = "single"                        # single | per-phase | ensemble
    phase_models: dict[str, str] = Field(default_factory=dict)  # role -> model
    consensus_quorum: int = 1
    intensity: str = "med"
    phases: list[int] = Field(default_factory=lambda: [1, 2, 3, 4, 5, 6])
    selected: dict[int, list[str]] = Field(default_factory=dict)
    flags: dict[str, list[str]] = Field(default_factory=dict)
    dry_run: bool = False
    assume_yes: bool = False
    run_dir: str | None = None
    wordlist: str | None = None
    resolvers: str | None = None
    nuclei_templates: str | None = None
    skills: str = ""  # operator-provided methodology folded into triage context

    model_config = {"arbitrary_types_allowed": True}


class RunState(TypedDict, total=False):
    """Mutable graph state threaded through the phase nodes."""

    config: dict[str, Any]           # RunConfig.model_dump()
    scope: dict[str, Any]            # Scope.model_dump()
    subdomains: Annotated[list[str], operator.add]
    live_hosts: Annotated[list[str], operator.add]
    results: Annotated[list[dict], operator.add]   # ExtensionResult dumps
    dropped: Annotated[list[str], operator.add]    # out-of-scope items, logged
    phase_log: Annotated[list[str], operator.add]
    gate_passed: bool
    aborted: bool
    weaknesses: list[dict]                         # Weakness dumps from triage
    report_markdown: str


def scope_from_state(state: RunState) -> Scope:
    return Scope(**state["scope"])


def config_from_state(state: RunState) -> RunConfig:
    return RunConfig(**state["config"])


def results_from_state(state: RunState) -> list[ExtensionResult]:
    return [ExtensionResult(**r) for r in state.get("results", [])]


def weaknesses_from_state(state: RunState) -> list[Weakness]:
    return [Weakness(**w) for w in state.get("weaknesses", [])]
