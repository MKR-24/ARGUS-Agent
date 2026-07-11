# tests/phase3/test_confidence.py

from agent.nodes.aggregator import calculate_confidence, calculate_severity
from agent.models import ConfidenceBreakdown, Severity


def test_full_confidence_all_sources_successful():
    """All three sources succeed — confidence should be high."""
    conf = calculate_confidence(
        cve_findings={"success": True},
        graph_findings={"success": True},
        history_findings={"success": True},
    )
    assert isinstance(conf, ConfidenceBreakdown)
    assert conf.cve_data == 0.9
    assert conf.graph_data == 0.9
    assert conf.history_data == 0.7
    assert conf.overall > 0.8


def test_confidence_cve_fails():
    """CVE source fails — overall should drop significantly (CVE weighted 40%)."""
    conf = calculate_confidence(
        cve_findings={"success": False},
        graph_findings={"success": True},
        history_findings={"success": True},
    )
    assert conf.cve_data == 0.1
    assert conf.graph_data == 0.9
    assert conf.overall < 0.6


def test_confidence_graph_fails():
    """Graph source fails — overall should drop significantly (graph weighted 40%)."""
    conf = calculate_confidence(
        cve_findings={"success": True},
        graph_findings={"success": False},
        history_findings={"success": True},
    )
    assert conf.graph_data == 0.1
    assert conf.overall < 0.6


def test_confidence_only_history_fails():
    """History fails — smaller impact since weighted 20%."""
    conf = calculate_confidence(
        cve_findings={"success": True},
        graph_findings={"success": True},
        history_findings={"success": False},
    )
    assert conf.history_data == 0.1
    assert conf.overall > 0.6  # CVE + graph still provide strong signal


def test_confidence_all_fail():
    """All sources fail — confidence should be very low."""
    conf = calculate_confidence(
        cve_findings={"success": False},
        graph_findings={"success": False},
        history_findings={"success": False},
    )
    assert conf.overall < 0.2


def test_confidence_overall_capped_at_one():
    """Overall score must never exceed 1.0."""
    conf = calculate_confidence(
        cve_findings={"success": True},
        graph_findings={"success": True},
        history_findings={"success": True},
    )
    assert conf.overall <= 1.0


def test_confidence_overall_non_negative():
    """Overall score must never be negative."""
    conf = calculate_confidence(
        cve_findings={"success": False},
        graph_findings={"success": False},
        history_findings={"success": False},
    )
    assert conf.overall >= 0.0


def test_confidence_breakdown_is_pydantic_model():
    """Return type must be ConfidenceBreakdown, not a plain dict."""
    conf = calculate_confidence(
        cve_findings={"success": True},
        graph_findings={"success": True},
        history_findings={"success": True},
    )
    assert isinstance(conf, ConfidenceBreakdown)


# ── Severity tests alongside confidence ───────────────────────────────────────


def test_severity_critical_requires_high_cvss_and_reachable():
    assert calculate_severity(10.0, 0.99, True) == Severity.critical
    assert calculate_severity(9.0, 0.5, True) == Severity.critical


def test_severity_not_critical_if_not_reachable():
    """CVSS 10 but not internet-reachable should not be CRITICAL."""
    result = calculate_severity(10.0, 0.99, False)
    assert result != Severity.critical


def test_severity_high_by_cvss_alone():
    assert calculate_severity(7.5, 0.1, False) == Severity.high
    assert calculate_severity(8.0, 0.0, False) == Severity.high


def test_severity_high_by_epss_and_reachable():
    """Low CVSS but high EPSS + reachable should be HIGH."""
    assert calculate_severity(5.0, 0.5, True) == Severity.high


def test_severity_medium():
    assert calculate_severity(5.0, 0.1, False) == Severity.medium
    assert calculate_severity(2.0, 0.0, True) == Severity.medium


def test_severity_low():
    """CVE present, not reachable, low CVSS."""
    assert calculate_severity(3.0, 0.01, False) == Severity.low


def test_severity_informational_no_cvss():
    assert calculate_severity(None, None, False) == Severity.informational
    assert calculate_severity(None, 0.99, True) == Severity.informational
