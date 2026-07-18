"""The six-phase LangGraph state machine.

Wiring:  START → phase1 → gate → (abort | phase2 → phase3 → phase4 → phase5) →
triage → report → END.

The gate is the human-in-the-loop checkpoint before the first live-traffic phase.
A checkpointer persists state so an interrupted run resumes cleanly.
"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph

from argus import phases
from argus.core.state import RunState


def _gate_router(state: RunState) -> str:
    return "abort" if state.get("aborted") else "continue"


def build_graph(checkpointer: Any | None = None) -> Any:
    """Build and compile the ARGUS pipeline graph."""
    g: StateGraph = StateGraph(RunState)

    g.add_node("phase1", phases.phase1)
    g.add_node("gate", phases.gate)
    g.add_node("phase2", phases.phase2)
    g.add_node("phase3", phases.phase3)
    g.add_node("phase4", phases.phase4)
    g.add_node("phase5", phases.phase5)
    g.add_node("triage", phases.triage)
    g.add_node("report", phases.phase6_report)

    g.add_edge(START, "phase1")
    g.add_edge("phase1", "gate")
    g.add_conditional_edges(
        "gate", _gate_router, {"abort": END, "continue": "phase2"}
    )
    g.add_edge("phase2", "phase3")
    g.add_edge("phase3", "phase4")
    g.add_edge("phase4", "phase5")
    g.add_edge("phase5", "triage")
    g.add_edge("triage", "report")
    g.add_edge("report", END)

    return g.compile(checkpointer=checkpointer)
