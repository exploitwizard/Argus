"""Model planning — resolves which model(s) a run uses, and for which role.

Two multi-model modes (selected by ``--multi-mode``):

* **per-phase** — a cheaper/faster model handles mechanical steps (parsing,
  input selection) while a stronger model handles triage/reporting. The mapping
  comes from ``settings.phase_models`` or a recipe, keyed by *role*.
* **ensemble** — the triage prompt is sent to every listed model in parallel and
  the findings are merged by consensus (see :mod:`argus.core.triage`).

A single ``--model`` run collapses to ``mode="single"`` and every role resolves
to that one model.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

# Roles an LLM step can play. Mechanical steps are cheap; triage/reporting want
# the strongest model. Wherever ARGUS invokes a model it asks the plan by role.
ROLE_MECHANICAL = "mechanical"
ROLE_TRIAGE = "triage"
ROLE_REPORTING = "reporting"
ROLES = (ROLE_MECHANICAL, ROLE_TRIAGE, ROLE_REPORTING)

MODE_SINGLE = "single"
MODE_PER_PHASE = "per-phase"
MODE_ENSEMBLE = "ensemble"


@dataclass
class ModelPlan:
    """Resolved model assignment for a run."""

    primary: str
    ensemble: list[str] = field(default_factory=list)
    mode: str = MODE_SINGLE
    phase_models: dict[str, str] = field(default_factory=dict)
    quorum: int = 1

    def for_role(self, role: str) -> str:
        """The single model to use for ``role`` (used outside ensemble triage)."""
        if self.mode == MODE_PER_PHASE and role in self.phase_models:
            return self.phase_models[role]
        # per-phase with no explicit map: mechanical -> fastest (last listed),
        # triage/reporting -> primary (first listed / strongest by convention).
        if self.mode == MODE_PER_PHASE and self.ensemble:
            if role == ROLE_MECHANICAL:
                return self.ensemble[-1]
            return self.ensemble[0]
        return self.primary

    def triage_models(self) -> list[str]:
        """Models the triage step runs. Ensemble → all; otherwise a single one."""
        if self.mode == MODE_ENSEMBLE and len(self.ensemble) > 1:
            return list(self.ensemble)
        return [self.for_role(ROLE_TRIAGE)]

    @property
    def is_ensemble(self) -> bool:
        return self.mode == MODE_ENSEMBLE and len(self.ensemble) > 1


def default_quorum(n_models: int) -> int:
    """Majority quorum: ``ceil(n/2)``, at least 1."""
    return max(1, math.ceil(n_models / 2))


def resolve_plan(
    *,
    cli_model: str | None,
    cli_models: list[str] | None,
    multi_mode: str,
    default_model: str,
    phase_models: dict[str, str] | None = None,
    recipe_model: str | None = None,
    recipe_models: list[str] | None = None,
    recipe_phase_models: dict[str, str] | None = None,
) -> ModelPlan:
    """Resolve the run's model plan.

    Precedence: CLI > recipe > settings default. ``--models`` (or a recipe's
    ``models``) selects multi-model; ``multi_mode`` picks ensemble vs per-phase.
    """
    ensemble = cli_models or recipe_models or []
    phase_map = dict(phase_models or {})
    if recipe_phase_models:
        phase_map = {**phase_map, **recipe_phase_models}

    if ensemble:
        primary = ensemble[0]
        mode = MODE_PER_PHASE if multi_mode == MODE_PER_PHASE else MODE_ENSEMBLE
        # de-facto single model in a list of one
        if len(ensemble) == 1:
            mode = MODE_SINGLE
        return ModelPlan(
            primary=primary, ensemble=ensemble, mode=mode,
            phase_models=phase_map, quorum=default_quorum(len(ensemble)),
        )

    primary = cli_model or recipe_model or default_model
    return ModelPlan(primary=primary, ensemble=[primary], mode=MODE_SINGLE,
                     phase_models=phase_map, quorum=1)
