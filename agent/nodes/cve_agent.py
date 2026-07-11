"""CVE specialist sub-agent — fetches CVE details and EPSS score."""

import logging
import sys
from langgraph.types import Command
from langchain_mcp_adapters.client import MultiServerMCPClient
from ..state import AgentState
from .utils import extract_tool_result

logger = logging.getLogger(__name__)


async def cve_agent_node(state: AgentState) -> Command:
    """Calls NVD MCP server and writes findings to state."""
    cve_id = state.get("cve_id")

    if not cve_id:
        logger.info("CVE agent: no CVE ID in alert, skipping")
        return Command(
            update={"cve_findings": {"skipped": True, "reason": "No CVE ID"}},
            goto="graph_agent",
        )

    client = MultiServerMCPClient(
        {
            "nvd": {
                "command": sys.executable,
                "args": ["-m", "mcp_servers.nvd.server"],
                "transport": "stdio",
            }
        }
    )

    try:
        tools = await client.get_tools()
        cve_tool = next((t for t in tools if t.name == "get_cve_details"), None)

        if not cve_tool:
            raise ValueError("get_cve_details tool not found")

        result = extract_tool_result(await cve_tool.ainvoke({"cve_id": cve_id}))
        logger.info(
            "CVE agent: got CVSS=%.1f EPSS=%.3f for %s",
            result.get("cvss_v3_score", 0),
            result.get("epss_score", 0),
            cve_id,
        )

        return Command(
            update={
                "cve_findings": {
                    "cve_id": cve_id,
                    "cvss_score": result.get("cvss_v3_score"),
                    "epss_score": result.get("epss_score"),
                    "description": result.get("description"),
                    "published": result.get("published"),
                    "success": True,
                }
            },
            goto="graph_agent",
        )

    except Exception as e:
        logger.error("CVE agent failed: %s", e)
        return Command(
            update={"cve_findings": {"success": False, "error": str(e)}},
            goto="graph_agent",
        )
