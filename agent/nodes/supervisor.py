"""
Supervisor node — decides which sub-agents to run based on alert content.
"""

import logging
from langgraph.types import Command
from ..state import AgentState
from agent.streaming import get_stream

logger = logging.getLogger(__name__)

# Fixed execution order for Phase 3
SUB_AGENT_SEQUENCE = ["cve_agent", "graph_agent", "history_agent", "reachability_agent"]


async def supervisor_node(state: AgentState) -> Command:
    """
    Entry point. Routes to the first sub-agent.
    Each sub-agent routes to the next via Command.
    """
    stream = get_stream(state["alert_id"])
    if stream:
        await stream.emit(
            "agent_start",
            {
                "agent": "supervisor_agent",
                "message": "Routing alert to specialist agents",
                "icon": "🔵",
            },
        )
    logger.info("Supervisor: starting investigation for alert %s", state["alert_id"])
    if stream:
        stream.emit(
            "agent_complete",
            {
                "agent": "supervisor_agent",
                "message": "Dispatching to {SUB_AGENT_SEQUENCE[0]}",
            },
        )
    return Command(goto=SUB_AGENT_SEQUENCE[0])
