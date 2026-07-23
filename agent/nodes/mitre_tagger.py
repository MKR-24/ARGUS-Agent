"""MITRE ATT&CK tagger node — maps findings to techniques."""

import logging
from langgraph.types import Command
from ..state import AgentState
from ..mitre.mapper import map_to_mitre

logger = logging.getLogger(__name__)


async def mitre_tagger_node(state: AgentState) -> Command:
    """Map investigation findings to MITRE ATT&CK techniques."""
    stream = state.get("stream")
    if stream:
        await stream.emit(
            "agent_start",
            {
                "agent": "mitre_tagger_agent",
                "message": "Mapping MITRE ATT&CK techniques",
                "icon": "🟢",
            },
        )
    findings = {
        "cve_findings": state.get("cve_findings", {}),
        "graph_findings": state.get("graph_findings", {}),
        "history_findings": state.get("history_findings", {}),
    }

    techniques = map_to_mitre(findings)
    logger.info("MITRE tagger: mapped %d techniques", len(techniques))

    # Check if HITL interrupt needed
    report = state.get("final_report", {})
    severity = report.get("severity", "INFORMATIONAL")
    next_node = "hitl_interrupt" if severity == "CRITICAL" else "__end__"

    # Update report with MITRE tags
    report["mitre_attack_tags"] = techniques
    technique_ids = [t["technique_id"] for t in techniques]
    if stream:
        await stream.emit(
            "agent_complete",
            {
                "agent": "mitre_tagger_agent",
                "message": f"{len(techniques)} techniques mapped: {', '.join(technique_ids)}",
                "data": {"technique_ids": technique_ids, "count": len(techniques)},
            },
        )
    return Command(
        update={
            "mitre_tags": techniques,
            "final_report": report,
        },
        goto=next_node,
    )
