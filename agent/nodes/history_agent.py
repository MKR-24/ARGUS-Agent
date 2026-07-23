"""History specialist sub-agent — searches Qdrant for prior exposures."""

import logging
import sys
from langgraph.types import Command
from langchain_mcp_adapters.client import MultiServerMCPClient
from ..state import AgentState
from .utils import extract_tool_result
from agent.streaming import get_stream

logger = logging.getLogger(__name__)


async def history_agent_node(state: AgentState) -> Command:
    """Calls Qdrant MCP server and writes history findings to state."""
    stream = get_stream(state["alert_id"])
    if stream:
        await stream.emit(
            "agent_start",
            {
                "agent": "history_agent",
                "message": "Searching Qdrant scan history",
                "icon": "🟢",
            },
        )
    service_id = state["service_id"]
    cve_id = state.get("cve_id")

    client = MultiServerMCPClient(
        {
            "history": {
                "command": sys.executable,
                "args": ["-m", "mcp_servers.history.server"],
                "transport": "stdio",
            }
        }
    )

    try:
        tools = await client.get_tools()
        history_tool = next(
            (t for t in tools if t.name == "search_historical_scans"), None
        )

        result = extract_tool_result(
            await history_tool.ainvoke(
                {
                    "service_id": service_id,
                    "cve_id": cve_id,
                }
            )
        )
        total_prior_findings = result.get("total_prior_findings", 0)
        unresolved = result.get("unresolved", 0)
        logger.info(
            "History agent: %d prior findings (%d unresolved) for %s",
            total_prior_findings,
            unresolved,
            service_id,
        )
        if stream:
            await stream.emit(
                "agent_complete",
                {
                    "agent": "history_agent",
                    "message": f"Total Prior findings ={total_prior_findings}, Unresolved={unresolved}",
                    "data": {
                        "Total Prior Findings": total_prior_findings,
                        "Unresolved": unresolved,
                    },
                },
            )
        return Command(
            update={
                "history_findings": {
                    "total_prior_findings": result.get("total_prior_findings", 0),
                    "resolved": result.get("resolved", 0),
                    "unresolved": result.get("unresolved", 0),
                    "records": result.get("records", []),
                    "success": True,
                }
            },
            goto="visual_intel_agent",
        )

    except Exception as e:
        logger.error("History agent failed: %s", e)
        if stream:
            await stream.emit(
                "agent_error",
                {
                    "agent": "history_agent",
                    "message": f"History search failed: {e}",
                },
            )
        return Command(
            update={"history_findings": {"success": False, "error": str(e)}},
            goto="visual_intel_agent",
        )
