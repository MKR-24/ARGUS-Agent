"""
Multi-agent LangGraph with supervisor routing,
specialist sub-agents, confidence scoring, MITRE tagging,
and HITL interrupt for CRITICAL alerts.
"""

import logging
import time
from typing import Any

from dotenv import load_dotenv
from langgraph.graph import StateGraph, START, END
from langsmith import get_current_run_tree, traceable
from .state import AgentState
from .nodes.supervisor import supervisor_node
from .nodes.cve_agent import cve_agent_node
from .nodes.graph_agent import graph_agent_node
from .nodes.history_agent import history_agent_node
from .nodes.reachability_agent import reachability_agent_node
from .nodes.aggregator import aggregator_node
from .nodes.mitre_tagger import mitre_tagger_node
from .nodes.hitl import hitl_node
from .nodes.visual_intel_agent import visual_intel_agent_node

load_dotenv()
logger = logging.getLogger(__name__)


def build_graph() -> StateGraph:
    """Build and compile the multi-agent investigation graph"""
    builder = StateGraph(AgentState)

    # Add all nodes
    builder.add_node("supervisor", supervisor_node)
    builder.add_node("cve_agent", cve_agent_node)
    builder.add_node("graph_agent", graph_agent_node)
    builder.add_node("history_agent", history_agent_node)
    builder.add_node("visual_intel_agent", visual_intel_agent_node)
    builder.add_node("reachability_agent", reachability_agent_node)
    builder.add_node("aggregator", aggregator_node)
    builder.add_node("mitre_tagger", mitre_tagger_node)
    builder.add_node("hitl_interrupt", hitl_node)

    # Entry point
    builder.add_edge(START, "supervisor")

    # HITL leads to END
    builder.add_edge("hitl_interrupt", END)

    return builder.compile()


_graph = build_graph()


@traceable(name="argus-investigation", project_name="argus-agent")
async def run_investigation(
    alert_id: str,
    service_id: str,
    cve_id: str | None,
    description: str,
    severity_raw: str,
    evidence_images: list[str] | None = None,
    stream=None,
) -> dict[str, Any]:
    """Run multi-agent investigation. Returns IncidentReport as dict."""
    start = time.monotonic()

    initial_state: AgentState = {
        "messages": [],
        "alert_id": alert_id,
        "service_id": service_id,
        "cve_id": cve_id,
        "description": description,
        "severity_raw": severity_raw,
        "cve_findings": {},
        "graph_findings": {},
        "history_findings": {},
        "reachability_findings": {},
        "evidence_images": evidence_images or [],  # NEW
        "visual_findings": {},
        "next_agent": "",
        "confidence_score": 0.0,
        "mitre_tags": [],
        "final_report": {},
    }

    try:
        result = await _graph.ainvoke(initial_state)
    except Exception as e:
        logger.error("Graph invocation failed for alert %s: %s", alert_id, e)
        raise

    elapsed = round(time.monotonic() - start, 2)
    report = result.get("final_report", {})
    report["mean_time_to_investigate_seconds"] = elapsed
    # Get LangSmith trace URL if available
    run = get_current_run_tree()
    if run:
        report["langsmith_trace_url"] = "https://smith.langchain.com"

    logger.info(
        "Investigation complete: alert=%s severity=%s confidence=%.2f time=%.2fs",
        alert_id,
        report.get("severity"),
        (report.get("confidence") or {}).get("overall", 0),
        elapsed,
    )

    return report
