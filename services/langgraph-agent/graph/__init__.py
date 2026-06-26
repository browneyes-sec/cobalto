from typing import Literal
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from state import SOCAgentState
from api import (
    triage_agent,
    analysis_agent,
    threat_intel_agent,
    response_agent,
    human_approval_node,
    documentation_agent,
    escalate_agent,
)


def route_after_triage(state: SOCAgentState) -> str:
    fp_prob = state.get("false_positive_probability", 0.0)
    severity = state.get("severity", "LOW")

    if fp_prob > 0.85:
        return "documentation"
    if severity in ("HIGH", "CRITICAL"):
        return "analysis"
    if severity == "MEDIUM":
        return "threat_intel"
    return "documentation"


def route_after_human_gate(
    state: SOCAgentState,
) -> Literal["documentation", "analysis", "escalate"]:
    if state.get("human_approved"):
        return "documentation"
    if state.get("approval_timeout"):
        return "escalate"
    return "analysis"


def build_graph() -> StateGraph:
    graph = StateGraph(SOCAgentState)

    graph.add_node("triage", triage_agent)
    graph.add_node("analysis", analysis_agent)
    graph.add_node("threat_intel", threat_intel_agent)
    graph.add_node("response", response_agent)
    graph.add_node("human_gate", human_approval_node)
    graph.add_node("documentation", documentation_agent)
    graph.add_node("escalate", escalate_agent)

    graph.set_entry_point("triage")

    graph.add_conditional_edges(
        "triage",
        route_after_triage,
        {
            "documentation": "documentation",
            "analysis": "analysis",
            "threat_intel": "threat_intel",
        },
    )

    graph.add_edge("analysis", "threat_intel")
    graph.add_edge("threat_intel", "response")
    graph.add_edge("response", "human_gate")

    graph.add_conditional_edges(
        "human_gate",
        route_after_human_gate,
        {
            "documentation": "documentation",
            "analysis": "analysis",
            "escalate": "escalate",
        },
    )

    graph.add_edge("documentation", END)
    graph.add_edge("escalate", END)

    return graph


memory = MemorySaver()
workflow = build_graph()
agent = workflow.compile(checkpointer=memory)
