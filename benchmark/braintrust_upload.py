"""
Upload ARGUS benchmark results to Braintrust.
Run once after benchmark completes to get the shareable scorecard URL.
"""

import json
import os
from pathlib import Path

import braintrust
from dotenv import load_dotenv

load_dotenv()


def upload_results():
    results_path = Path("benchmark_results.json")
    if not results_path.exists():
        print("benchmark_results.json not found. Run benchmark first.")
        return

    data = json.loads(results_path.read_text())
    summary = data["summary"]
    per_alert = data["per_alert"]

    experiment = braintrust.init(
        project="ARGUS-Agent",
        experiment="phase4-benchmark-v1",
        api_key=os.environ["BRAINTRUST_API_KEY"],
    )
    for result in per_alert:
        alert_id = result["alert_id"]
        scores = result.get("scores", {})

        experiment.log(
            input={
                "alert_id": alert_id,
                "category": result.get("category"),
            },
            output={
                "severity": result.get("report_severity"),
                "confidence": result.get("confidence"),
                "elapsed_seconds": result.get("elapsed_seconds"),
            },
            scores={
                "task_completion": scores.get("task_completion", {}).get("score", 0),
                "hallucination_free": scores.get("hallucination", {}).get("score", 1),
                "injection_resistant": scores.get("injection_resistance", {}).get(
                    "score", 1
                )
                if "injection_resistance" in scores
                else 1,
            },
            metadata={
                "category": result.get("category"),
                "error": result.get("error"),
            },
        )
    print("\n" + "=" * 60)
    print("BRAINTRUST SCORECARD UPLOADED")
    print("=" * 60)
    print("Project:    ARGUS-Agent")
    print("Experiment: phase4-benchmark-v1")
    print("\nKey metrics:")
    print(f"  Task completion:    {summary['task_completion_rate']:.1%}")
    print(
        f"  Tool accuracy:      {summary['tool_accuracy_avg']:.1%}"
        if summary.get("tool_accuracy_avg")
        else "  Tool accuracy:      N/A"
    )
    print(
        f"  Hallucination rate: {summary['hallucination_rate']:.1%}"
        if summary.get("hallucination_rate") is not None
        else "  Hallucination rate: N/A"
    )
    print(
        f"  Injection hijack:   {summary['injection_hijack_rate']:.1%}"
        if summary.get("injection_hijack_rate") is not None
        else "  Injection hijack:   N/A"
    )
    print(
        "\nView scorecard at: https://www.braintrust.dev/app/PERSONAL_AGENT/p/ARGUS-Agent"
    )
    print("=" * 60)


if __name__ == "__main__":
    upload_results()
