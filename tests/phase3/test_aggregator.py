from agent.nodes.aggregator import calculate_severity, calculate_confidence
from agent.models import Severity


def test_critical_severity():
    assert calculate_severity(10.0, 0.99, True) == Severity.critical


def test_high_severity_by_cvss():
    assert calculate_severity(7.5, 0.1, False) == Severity.high


def test_informational_no_cvss():
    assert calculate_severity(None, None, False) == Severity.informational


def test_confidence_all_success():
    conf = calculate_confidence(
        {"success": True},
        {"success": True},
        {"success": True},
    )
    assert conf.overall > 0.8


def test_confidence_all_failure():
    conf = calculate_confidence(
        {"success": False},
        {"success": False},
        {"success": False},
    )
    assert conf.overall < 0.2
