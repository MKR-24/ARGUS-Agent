"""
Aggregator node — combines all sub-agent findings into a structured
IncidentReport with confidence scores.
"""

import logging
from langgraph.types import Command
from ..state import AgentState
from ..models import IncidentReport, Severity, ConfidenceBreakdown
from agent.streaming import get_stream

logger = logging.getLogger(__name__)


def calculate_severity(
    cvss: float | None,
    epss: float | None,
    reachable: bool,
) -> Severity:
    if cvss is None:
        return Severity.informational
    if cvss >= 9.0 and reachable:
        return Severity.critical
    if cvss >= 7.0 or (reachable and (epss or 0) > 0.3):
        return Severity.high
    if cvss >= 4.0 or reachable:
        return Severity.medium
    return Severity.low


def calculate_confidence(
    cve_findings: dict,
    graph_findings: dict,
    history_findings: dict,
) -> ConfidenceBreakdown:
    cve_conf = 0.9 if cve_findings.get("success") else 0.1
    graph_conf = 0.9 if graph_findings.get("success") else 0.1
    history_conf = 0.7 if history_findings.get("success") else 0.1

    # Weighted average: CVE and graph data matter most
    overall = (cve_conf * 0.4) + (graph_conf * 0.4) + (history_conf * 0.2)

    return ConfidenceBreakdown(
        cve_data=cve_conf,
        graph_data=graph_conf,
        history_data=history_conf,
        overall=round(overall, 2),
    )


def generate_remediation(
    cve_id: str | None,
    severity: Severity,
    reachable: bool,
    description: str | None,
) -> list[str]:
    steps = []
    desc = (description or "").lower()

    if reachable:
        steps.append("Immediately restrict network access to the affected service")

    if "log4j" in desc or "log4shell" in desc or cve_id == "CVE-2021-44228":
        steps.extend(
            [
                "Upgrade Apache Log4j2 to version 2.17.1 or later",
                "Apply WAF rules blocking JNDI lookup patterns: ${jndi:...}",
                "Audit all Java services for Log4j2 dependency",
            ]
        )
    elif "spring" in desc:
        steps.extend(
            [
                "Upgrade Spring Framework to 5.3.18+ or 5.2.20+",
                "Set spring.mvc.pathmatch.use-suffix-pattern=false",
            ]
        )
    elif "postgres" in desc or (cve_id or "").startswith("CVE-2024-0985"):
        steps.extend(
            [
                "Apply PostgreSQL security patch immediately",
                "Audit database user privileges and revoke unnecessary grants",
            ]
        )

    if not steps:
        steps.append("Apply vendor security patch for the affected component")

    if severity in (Severity.critical, Severity.high):
        steps.append(
            "Escalate to security team and initiate incident response procedure"
        )

    return steps


async def aggregator_node(state: AgentState) -> Command:
    """Combine all findings into a structured IncidentReport."""
    stream = get_stream(state["alert_id"])
    if stream:
        await stream.emit(
            "agent_start",
            {
                "agent": "aggregator_agent",
                "message": "Computing confidence scores",
                "icon": "🟢",
            },
        )
    cve = state.get("cve_findings", {})
    graph = state.get("graph_findings", {})
    history = state.get("history_findings", {})
    # reach = state.get("reachability_findings", {})

    cvss = cve.get("cvss_score")
    epss = cve.get("epss_score")
    reachable = graph.get("reachable_from_internet", False)
    paths = graph.get("attack_paths", [])
    hop_count = graph.get("hop_count")

    severity = calculate_severity(cvss, epss, reachable)
    confidence = calculate_confidence(cve, graph, history)

    remediation = generate_remediation(
        cve_id=state.get("cve_id"),
        severity=severity,
        reachable=reachable,
        description=cve.get("description"),
    )

    summary = (
        (
            f"{severity.value}: {state.get('cve_id', 'Unknown CVE')} detected in "
            f"{state['service_id']}. "
            f"CVSS {cvss or 'N/A'}, EPSS {f'{epss:.2%}' if epss is not None else 'N/A'} exploit probability. "
            f"{'Reachable from internet' if reachable else 'Not directly internet-reachable'}. "
            f"Confidence: {confidence.overall:.0%}."
        )
        if cvss
        else f"Alert investigated. Insufficient CVE data. Confidence: {confidence.overall:.0%}."
    )
    visual = state.get("visual_findings", {})
    report = IncidentReport(
        alert_id=state["alert_id"],
        service_id=state["service_id"],
        cve_id=state.get("cve_id"),
        cvss_score=cvss,
        epss_score=epss,
        cve_description=cve.get("description"),
        reachable_from_internet=reachable,
        attack_paths=paths,
        hop_count=hop_count,
        prior_exposure_count=history.get("total_prior_findings", 0),
        unresolved_prior=history.get("unresolved", 0),
        severity=severity,
        remediation=remediation,
        summary=summary,
        confidence=confidence,
    )
    report_dict = report.model_dump()
    report_dict["visual_findings"] = (
        visual if visual and not visual.get("skipped") else None
    )

    logger.info(
        "Aggregator: severity=%s confidence=%.2f",
        severity.value,
        confidence.overall,
    )
    if stream:
        await stream.emit(
            "agent_complete",
            {
                "agent": "aggregator_agent",
                "message": f"Severity: {severity.value} ,Confidence={confidence.overall}",
                "data": {"Severity": severity.value, "Confidence": confidence.overall},
            },
        )
    return Command(
        update={"final_report": report_dict},
        goto="mitre_tagger",
    )
