import json


def extract_tool_result(raw) -> dict:
    """Normalise MCP tool output to a plain dict regardless of adapter version."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, list):
        for block in raw:
            if isinstance(block, dict) and block.get("type") == "text":
                try:
                    return json.loads(block["text"])
                except (json.JSONDecodeError, KeyError):
                    return {"raw": block.get("text", "")}
            if hasattr(block, "text"):
                try:
                    return json.loads(block.text)
                except (json.JSONDecodeError, ValueError):
                    return {"raw": block.text}
    return {}
