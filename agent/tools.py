"""
Load all MCP servers and return their tools as LangChain-compatible tools.
Each MCP server is started as a subprocess communicating via stdio.
"""

import sys
from langchain_mcp_adapters.client import MultiServerMCPClient


def get_mcp_client() -> MultiServerMCPClient:
    """
    Returns a configured MCP client pointing at all four servers.
    The client starts each server as a subprocess when used as async context manager.
    """
    python = sys.executable  # use the same venv python

    return MultiServerMCPClient(
        {
            "nvd": {
                "command": python,
                "args": ["-m", "mcp_servers.nvd.server"],
                "transport": "stdio",
            },
            "graph": {
                "command": python,
                "args": ["-m", "mcp_servers.graph.server"],
                "transport": "stdio",
            },
            "history": {
                "command": python,
                "args": ["-m", "mcp_servers.history.server"],
                "transport": "stdio",
            },
        }
    )
