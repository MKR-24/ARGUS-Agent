"""
Supervisor node — decides which sub-agents to run based on alert content.
In Phase 3 this runs all four sub-agents unconditionally.
Phase 4 will add conditional routing based on alert type.
"""

import logging
from langgraph.types import Command
from ..state import AgentState

logger = logging.getLogger(__name__)

# Fixed execution order for Phase 3
SUB_AGENT_SEQUENCE = ["cve_agent", "graph_agent", "history_agent", "reachability_agent"]


def supervisor_node(state: AgentState) -> Command:
    """
    Entry point. Routes to the first sub-agent.
    Each sub-agent routes to the next via Command.
    """
    logger.info("Supervisor: starting investigation for alert %s", state["alert_id"])
    return Command(goto=SUB_AGENT_SEQUENCE[0])
