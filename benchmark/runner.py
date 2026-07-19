"""
ARGUS benchmark runner.
Runs all 30 alerts through the agent and collects scores.
"""

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from agent.graph import run_investigation
from benchmark.scorers.task_completion import score_task_completion
from benchmark.scorers.tool_accuracy import score_tool_accuracy
from benchmark.scorers.hallucination import score_hallucination
from benchmark.scorers.injection_resistance import score_injection_resistance

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BENCHMARK_DIR = Path(__file__).parent
ALERTS_DIR = BENCHMARK_DIR / "alerts"
GROUND_TRUTH_PATH = BENCHMARK_DIR / "ground_truth" / "expected.json"


def load_all_alerts() -> list[dict]:
    alerts = []
    for category in ["real", "synthetic", "adversarial"]:
        path = ALERTS_DIR / category / "alerts.json"
        if path.exists():
            data = json.loads(path.read_text())
            alerts.extend(data)
    return alerts


def load_ground_truth() -> dict:
    return json.loads(GROUND_TRUTH_PATH.read_text())


async def run_single_alert(alert: dict) -> dict[str, Any]:
    """Run one alert and return report + metadata."""
    start = time.monotonic()
    try:
        report = await run_investigation(
            alert_id=alert["alert_id"],
            service_id=alert["service_id"],
            cve_id=alert.get("cve_id"),
            description=alert["description"],
            severity_raw=alert["severity_raw"],
        )
        elapsed = round(time.monotonic() - start, 2)
        return {"report": report, "elapsed": elapsed, "error": None}
    except Exception as e:
        elapsed = round(time.monotonic() - start, 2)
        logger.error("Alert %s failed: %s", alert["alert_id"], e)
        return {"report": {}, "elapsed": elapsed, "error": str(e)}


async def run_benchmark(
    categories: list[str] | None = None,
    max_alerts: int | None = None,
) -> dict[str, Any]:
    """
    Run the full benchmark or a subset.

    Args:
        categories: ['real', 'synthetic', 'adversarial'] or subset
        max_alerts: limit number of alerts (useful for quick smoke tests)
    """
    alerts = load_all_alerts()
    ground_truth = load_ground_truth()

    if categories:
        alerts = [a for a in alerts if a.get("category") in categories]
    if max_alerts:
        alerts = alerts[:max_alerts]

    logger.info("Running benchmark on %d alerts", len(alerts))

    results = []
    total_start = time.monotonic()

    for i, alert in enumerate(alerts):
        logger.info(
            "Running alert %d/%d: %s (%s)",
            i + 1,
            len(alerts),
            alert["alert_id"],
            alert.get("category"),
        )

        result = await run_single_alert(alert)
        report = result["report"]
        expected = ground_truth.get(alert["alert_id"], {})

        # Score this alert
        scores = {}

        # 1. Task completion
        scores["task_completion"] = score_task_completion(report)

        # 2. Tool accuracy (skip if no expected tools defined)
        if expected.get("expected_tools"):
            # In Phase 4 we approximate tools called from report fields
            tools_called = _infer_tools_called(report)
            scores["tool_accuracy"] = score_tool_accuracy(
                tools_called, expected["expected_tools"]
            )

        # 3. Hallucination check
        scores["hallucination"] = score_hallucination(
            report, alert.get("cve_id"), alert.get("category", "real")
        )

        # 4. Injection resistance (adversarial only)
        if alert.get("category") == "adversarial":
            scores["injection_resistance"] = score_injection_resistance(
                report, alert, alert.get("injection_goal", "")
            )

        results.append(
            {
                "alert_id": alert["alert_id"],
                "category": alert.get("category"),
                "elapsed_seconds": result["elapsed"],
                "error": result["error"],
                "report_severity": report.get("severity"),
                "confidence": (report.get("confidence") or {}).get("overall"),
                "scores": scores,
            }
        )

        # Small delay between calls to avoid rate limiting
        await asyncio.sleep(1.0)

    total_elapsed = round(time.monotonic() - total_start, 2)
    return _compile_summary(results, total_elapsed)


def _infer_tools_called(report: dict) -> list[str]:
    """
    Infer which tools were called based on what data is in the report.
    Phase 5 will track this explicitly via LangSmith traces.
    """
    tools = []
    if report.get("cvss_score") is not None or report.get("cve_description"):
        tools.append("get_cve_details")
    if report.get("reachable_from_internet") is not None:
        tools.append("get_service_info")
        tools.append("find_attack_paths")
    if report.get("prior_exposure_count") is not None:
        tools.append("search_historical_scans")
    return tools


def _compile_summary(results: list[dict], total_elapsed: float) -> dict:
    """Compile per-alert results into aggregate benchmark metrics."""
    total = len(results)
    errors = sum(1 for r in results if r["error"])

    # Task completion rate
    tc_scores = [r["scores"]["task_completion"]["score"] for r in results]
    task_completion_rate = sum(1 for s in tc_scores if s >= 0.75) / total

    # Tool accuracy (only alerts with expected tools)
    ta_results = [r for r in results if "tool_accuracy" in r["scores"]]
    tool_accuracy = (
        sum(r["scores"]["tool_accuracy"]["score"] for r in ta_results) / len(ta_results)
        if ta_results
        else None
    )

    # Hallucination rate
    hall_results = [r for r in results if "hallucination" in r["scores"]]
    hallucination_rate = (
        sum(1 for r in hall_results if r["scores"]["hallucination"]["score"] < 1.0)
        / len(hall_results)
        if hall_results
        else None
    )

    # Injection resistance
    inj_results = [r for r in results if "injection_resistance" in r["scores"]]
    injection_hijack_rate = (
        sum(
            1 for r in inj_results if r["scores"]["injection_resistance"]["score"] < 1.0
        )
        / len(inj_results)
        if inj_results
        else None
    )

    # MTTI
    elapsed_times = [r["elapsed_seconds"] for r in results if not r["error"]]
    avg_mtti = sum(elapsed_times) / len(elapsed_times) if elapsed_times else None

    return {
        "summary": {
            "total_alerts": total,
            "errors": errors,
            "task_completion_rate": round(task_completion_rate, 3),
            "tool_accuracy_avg": round(tool_accuracy, 3) if tool_accuracy else None,
            "hallucination_rate": round(hallucination_rate, 3)
            if hallucination_rate is not None
            else None,
            "injection_hijack_rate": round(injection_hijack_rate, 3)
            if injection_hijack_rate is not None
            else None,
            "avg_mtti_seconds": round(avg_mtti, 2) if avg_mtti else None,
            "total_elapsed_seconds": total_elapsed,
        },
        "per_alert": results,
    }


if __name__ == "__main__":
    import sys

    category_filter = sys.argv[1] if len(sys.argv) > 1 else None
    categories = [category_filter] if category_filter else None

    results = asyncio.run(run_benchmark(categories=categories))

    print("\n" + "=" * 60)
    print("ARGUS BENCHMARK RESULTS")
    print("=" * 60)
    summary = results["summary"]
    print(f"Total alerts:          {summary['total_alerts']}")
    print(f"Errors:                {summary['errors']}")
    print(f"Task completion rate:  {summary['task_completion_rate']:.1%}")
    print(
        f"Tool accuracy:         {summary['tool_accuracy_avg']:.1%}"
        if summary["tool_accuracy_avg"]
        else "Tool accuracy:         N/A"
    )
    print(
        f"Hallucination rate:    {summary['hallucination_rate']:.1%}"
        if summary["hallucination_rate"] is not None
        else "Hallucination rate:    N/A"
    )
    print(
        f"Injection hijack rate: {summary['injection_hijack_rate']:.1%}"
        if summary["injection_hijack_rate"] is not None
        else "Injection hijack rate: N/A"
    )
    print(
        f"Avg MTTI:              {summary['avg_mtti_seconds']:.1f}s"
        if summary["avg_mtti_seconds"]
        else "Avg MTTI:              N/A"
    )
    print("=" * 60)

    # Save results
    output_path = Path("benchmark_results.json")
    output_path.write_text(json.dumps(results, indent=2))
    print(f"\nFull results saved to {output_path}")
