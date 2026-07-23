"""
Reachability specialist sub-agent.

"""

import logging
from langgraph.types import Command
from ..state import AgentState
from agent.streaming import get_stream

logger = logging.getLogger(__name__)

# Known vulnerable package-to-language mappings
VULNERABLE_PACKAGES = {
    "log4j": ["java"],
    "spring-webmvc": ["java"],
    "spring-core": ["java"],
    "postgresql": ["python", "java", "go", "node"],
    "requests": ["python"],
    "lodash": ["node"],
}


async def reachability_agent_node(state: AgentState) -> Command:
    """
    Checks if the vulnerable package is plausibly used by the service
    based on its language metadata from the graph findings.
    """
    stream = get_stream(state["alert_id"])
    if stream:
        await stream.emit(
            "agent_start",
            {
                "agent": "reachability_agent",
                "message": "Checking code path reachability",
                "icon": "🟢",
            },
        )

    cve_id = state.get("cve_id")
    graph = state.get("graph_findings", {})
    service_info = graph.get("service_info", {})
    language = service_info.get("language", "").lower()

    if not cve_id or not language:
        if stream:
            await stream.emit(
                "agent_complete",
                {
                    "agent": "reachability_agent",
                    "message": "Insufficient data for reachability check — skipping",
                },
            )

        return Command(
            update={
                "reachability_findings": {
                    "code_path_reachable": None,
                    "confidence": 0.0,
                    "reason": "Insufficient data for reachability check",
                }
            },
            goto="aggregator",
        )

    # Check if any known vulnerable package matches the service language
    reachable = False
    matched_package = None

    for package, langs in VULNERABLE_PACKAGES.items():
        if language in langs:
            # Check if this package is associated with the CVE in graph findings
            cves = service_info.get("cves", [])
            if cve_id in cves:
                reachable = True
                matched_package = package
                break
    service = state["service_id"]
    logger.info(
        "Reachability agent: service=%s language=%s reachable=%s",
        service,
        language,
        reachable,
    )
    if stream:
        await stream.emit(
            "agent_complete",
            {
                "agent": "reachability_agent",
                "message": f"Service={service} in {language} language is reachable in status {reachable}",
                "data": {"Service": service},
            },
        )
    return Command(
        update={
            "reachability_findings": {
                "code_path_reachable": reachable,
                "language": language,
                "matched_package": matched_package,
                "confidence": 0.8 if matched_package else 0.3,
                "reason": f"Package {matched_package} known to affect {language}"
                if matched_package
                else "No direct package match found",
            }
        },
        goto="aggregator",
    )
