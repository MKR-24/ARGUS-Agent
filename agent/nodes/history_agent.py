"""History specialist sub-agent — searches Qdrant for prior exposures."""

import logging
import sys
from langgraph.types import Command
from langchain_mcp_adapters.client import MultiServerMCPClient
from ..state import AgentState
from .utils import extract_tool_result

logger = logging.getLogger(__name__)


async def history_agent_node(state: AgentState) -> Command:
    """Calls Qdrant MCP server and writes history findings to state."""
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

        logger.info(
            "History agent: %d prior findings (%d unresolved) for %s",
            result.get("total_prior_findings", 0),
            result.get("unresolved", 0),
            service_id,
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
            goto="reachability_agent",
        )

    except Exception as e:
        logger.error("History agent failed: %s", e)
        return Command(
            update={"history_findings": {"success": False, "error": str(e)}},
            goto="reachability_agent",
        )
