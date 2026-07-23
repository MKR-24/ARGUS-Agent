"""
Visual intelligence sub-agent.
Runs only when alert contains evidence_images.
"""

import logging
import sys
from langgraph.types import Command
from langchain_mcp_adapters.client import MultiServerMCPClient

from ..state import AgentState
from .utils import extract_tool_result
from agent.streaming import get_stream

logger = logging.getLogger(__name__)


async def visual_intel_agent_node(state: AgentState) -> Command:
    """Analyse visual evidence if present in the alert."""
    stream = get_stream(state["alert_id"])
    if stream:
        await stream.emit(
            "agent_start",
            {
                "agent": "visual_intel_agent",
                "message": "Analysing screenshot evidence",
                "icon": "🟢",
            },
        )
    images = state.get("evidence_images", [])
    logger.info("Visual intel agent: received %d images", len(images))
    if not images:
        if stream:
            await stream.emit(
                "agent_complete",
                {
                    "agent": "visual_intel_agent",
                    "message": "No images attached — skipping visual analysis",
                },
            )
        return Command(
            update={
                "visual_findings": {"skipped": True, "reason": "No images provided"}
            },
            goto="aggregator",
        )
    cve_id = state.get("cve_id", "unknown")
    service_id = state["service_id"]
    alert_context = f"{cve_id} on {service_id}"

    client = MultiServerMCPClient(
        {
            "visual_intel": {
                "command": sys.executable,
                "args": ["-m", "mcp_servers.visual_intel.server"],
                "transport": "stdio",
            }
        }
    )
    try:
        tools = await client.get_tools()
        visual_tool = next(
            (t for t in tools if t.name == "analyze_visual_evidence"), None
        )
        if not visual_tool:
            raise ValueError("analyze_visual_evidence tool not found")

        raw = await visual_tool.ainvoke(
            {
                "images_b64": images,
                "alert_context": alert_context,
            }
        )
        result = extract_tool_result(raw)
        img_count = result.get("image_count", 0)
        overall_risk_signal = result.get("overall_risk_signal")
        logger.info(
            "Visual intel agent: %d images analysed, risk=%s",
            img_count,
            overall_risk_signal,
        )
        if stream:
            await stream.emit(
                "agent_complete",
                {
                    "agent": "visual_intel_agent",
                    "message": f"{img_count} images processed with overall risk signal={overall_risk_signal}",
                    "data": {
                        "Image Count": img_count,
                        "Overall Risk signal": overall_risk_signal,
                    },
                },
            )
        return Command(
            update={"visual_findings": {**result, "success": True}},
            goto="aggregator",
        )
    except Exception as e:
        logger.error("Visual intel agent failed: %s", e)
        if stream:
            await stream.emit(
                "agent_error",
                {
                    "agent": "visual_intel_agent",
                    "message": f"Visual analysis failed: {e}",
                },
            )
        return Command(
            update={"visual_findings": {"success": False, "error": str(e)}},
            goto="aggregator",
        )
