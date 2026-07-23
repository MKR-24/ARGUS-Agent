"""
Human-in-the-loop interrupt node.
For CRITICAL severity alerts, the graph pauses here and waits
for human approval before completing. In the demo this surfaces
as a pending state in the API response.
"""

import logging
from langgraph.types import interrupt, Command
from ..state import AgentState
from agent.streaming import get_stream

logger = logging.getLogger(__name__)


async def hitl_node(state: AgentState) -> Command:
    """
    Interrupt execution for CRITICAL alerts.
    The graph pauses until a human resumes it via the API.
    """
    stream = get_stream(state["alert_id"])
    if stream:
        await stream.emit(
            "hitl_interrupt",
            {
                "agent": "hitl",
                "message": "CRITICAL alert — awaiting human approval",
                "icon": "⚠️",
            },
        )
    report = state.get("final_report", {})
    logger.warning(
        "HITL interrupt: CRITICAL alert %s requires human review before finalising",
        state["alert_id"],
    )

    # interrupt() pauses the graph and surfaces this value to the caller
    human_decision = interrupt(
        {
            "alert_id": state["alert_id"],
            "severity": report.get("severity"),
            "summary": report.get("summary"),
            "message": "CRITICAL severity alert requires human approval. Resume to finalise report.",
        }
    )
    # When resumed, human_decision contains the reviewer's input
    logger.info("HITL resumed by human. Decision: %s", human_decision)

    return Command(goto="__end__")
