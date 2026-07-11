"""Graph specialist sub-agent — queries Neo4j for attack paths."""

import logging
import sys
from langgraph.types import Command
from langchain_mcp_adapters.client import MultiServerMCPClient
from ..state import AgentState
from .utils import extract_tool_result

logger = logging.getLogger(__name__)


async def graph_agent_node(state: AgentState) -> Command:
    """Calls Neo4j MCP server and writes graph findings to state."""
    service_id = state["service_id"]

    client = MultiServerMCPClient(
        {
            "graph": {
                "command": sys.executable,
                "args": ["-m", "mcp_servers.graph.server"],
                "transport": "stdio",
            }
        }
    )

    try:
        tools = await client.get_tools()

        service_tool = next((t for t in tools if t.name == "get_service_info"), None)
        paths_tool = next((t for t in tools if t.name == "find_attack_paths"), None)

        service_info = extract_tool_result(
            await service_tool.ainvoke({"service_id": service_id})
        )
        paths_info = extract_tool_result(
            await paths_tool.ainvoke({"target_service_id": service_id})
        )
        paths = paths_info.get("paths", [])
        hop_count = min((p.get("hop_count") for p in paths), default=None)

        logger.info(
            "Graph agent: service=%s reachable=%s hops=%s",
            service_id,
            paths_info.get("reachable_from_internet"),
            hop_count,
        )

        return Command(
            update={
                "graph_findings": {
                    "service_info": service_info,
                    "reachable_from_internet": paths_info.get(
                        "reachable_from_internet", False
                    ),
                    "attack_paths": [p.get("path", []) for p in paths],
                    "hop_count": hop_count,
                    "success": True,
                }
            },
            goto="history_agent",
        )

    except Exception as e:
        logger.error("Graph agent failed: %s", e)
        return Command(
            update={"graph_findings": {"success": False, "error": str(e)}},
            goto="history_agent",
        )
