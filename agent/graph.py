"""
Phase 3: Multi-agent LangGraph with supervisor routing,
specialist sub-agents, confidence scoring, MITRE tagging,
and HITL interrupt for CRITICAL alerts.
"""

import logging
import time
from typing import Any

from dotenv import load_dotenv
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver

from .state import AgentState
from .nodes.supervisor import supervisor_node
from .nodes.cve_agent import cve_agent_node
from .nodes.graph_agent import graph_agent_node
from .nodes.history_agent import history_agent_node
from .nodes.reachability_agent import reachability_agent_node
from .nodes.aggregator import aggregator_node
from .nodes.mitre_tagger import mitre_tagger_node
from .nodes.hitl import hitl_node

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
    builder.add_node("reachability_agent", reachability_agent_node)
    builder.add_node("aggregator", aggregator_node)
    builder.add_node("mitre_tagger", mitre_tagger_node)
    builder.add_node("hitl_interrupt", hitl_node)

    # Entry point
    builder.add_edge(START, "supervisor")

    # HITL leads to END
    builder.add_edge("hitl_interrupt", END)

    # Compile with memory checkpointer (required for HITL)
    checkpointer = MemorySaver()
    return builder.compile(
        checkpointer=checkpointer,
        interrupt_before=["hitl_interrupt"],
    )


_graph = build_graph()


async def run_investigation(
    alert_id: str,
    service_id: str,
    cve_id: str | None,
    description: str,
    severity_raw: str,
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
        "next_agent": "",
        "confidence_score": 0.0,
        "mitre_tags": [],
        "final_report": {},
    }

    # Each run needs a unique thread_id for the checkpointer
    config = {"configurable": {"thread_id": alert_id}}

    try:
        result = await _graph.ainvoke(initial_state, config=config)
    except Exception as e:
        logger.error("Graph invocation failed for alert %s: %s", alert_id, e)
        raise

    elapsed = round(time.monotonic() - start, 2)
    report = result.get("final_report", {})
    report["mean_time_to_investigate_seconds"] = elapsed

    logger.info(
        "Investigation complete: alert=%s severity=%s confidence=%.2f time=%.2fs",
        alert_id,
        report.get("severity"),
        (report.get("confidence") or {}).get("overall", 0),
        elapsed,
    )

    return report
