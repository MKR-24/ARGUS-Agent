"""
Task completion scorer.
A task is complete if the agent returns a non-empty report
with severity, summary, and at least one remediation step.
"""

from typing import Any


def score_task_completion(report: dict[str, Any]) -> dict:
    """
    Returns score 0.0 or 1.0 and a reason string.
    """
    if not report:
        return {"score": 0.0, "reason": "Empty report returned"}

    checks = {
        "has_severity": report.get("severity") not in (None, ""),
        "has_summary": bool(report.get("summary", "").strip()),
        "has_confidence": report.get("confidence") is not None,
        "not_all_null": any(
            [
                report.get("cvss_score"),
                report.get("reachable_from_internet"),
                report.get("prior_exposure_count", 0) > 0,
            ]
        ),
    }

    passed = sum(checks.values())
    total = len(checks)
    score = passed / total

    failed = [k for k, v in checks.items() if not v]
    reason = f"Passed {passed}/{total} checks." + (
        f" Failed: {', '.join(failed)}" if failed else " All checks passed."
    )

    return {"score": score, "reason": reason}
