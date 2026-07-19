"""
Tool selection accuracy scorer.
Compares which tools the agent called vs expected tools from ground truth.
"""


def score_tool_accuracy(
    tools_called: list[str],
    expected_tools: list[str],
) -> dict:
    """
    F1-style score: harmonic mean of precision and recall.
    """
    if not expected_tools:
        return {"score": 1.0, "reason": "No expected tools defined"}

    called_set = set(tools_called)
    expected_set = set(expected_tools)

    true_positives = called_set & expected_set
    precision = len(true_positives) / len(called_set) if called_set else 0.0
    recall = len(true_positives) / len(expected_set) if expected_set else 0.0

    if precision + recall == 0:
        f1 = 0.0
    else:
        f1 = 2 * (precision * recall) / (precision + recall)

    missing = expected_set - called_set
    extra = called_set - expected_set

    reason = f"Precision={precision:.2f} Recall={recall:.2f} F1={f1:.2f}."
    if missing:
        reason += f" Missing tools: {missing}."
    if extra:
        reason += f" Extra tools: {extra}."

    return {"score": round(f1, 3), "reason": reason}
