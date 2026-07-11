from typing import Annotated
from langgraph.graph.message import add_messages
from langchain_core.messages import BaseMessage
from typing_extensions import TypedDict


def merge_findings(existing: dict, new: dict) -> dict:
    """Merge sub-agent findings into shared state. New values overwrite."""
    if existing is None:
        return new
    return {**existing, **new}


class AgentState(TypedDict):
    """
    State that flows through every node in the graph.
    messages accumulates with add_messages reducer —
    new messages are appended, not replaced.
    """

    # Message history — accumulated across all agent turns
    messages: Annotated[list[BaseMessage], add_messages]
    # Alert context — set once at entry, never modified
    alert_id: str
    service_id: str
    cve_id: str | None
    description: str
    severity_raw: str

    # Sub-agent findings — each agent writes its own key
    cve_findings: Annotated[dict, merge_findings]
    graph_findings: Annotated[dict, merge_findings]
    history_findings: Annotated[dict, merge_findings]
    reachability_findings: Annotated[dict, merge_findings]

    # Routing — supervisor sets this to direct flow
    next_agent: str

    # Final outputs
    confidence_score: float
    mitre_tags: list[dict]
    final_report: dict
