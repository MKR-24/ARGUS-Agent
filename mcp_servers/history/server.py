"""MCP server — semantic search over historical scan records."""

import os
import logging
from typing import Any

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from qdrant_client import QdrantClient

load_dotenv()
logger = logging.getLogger(__name__)
mcp = FastMCP("history-server")

COLLECTION = os.environ.get("QDRANT_COLLECTION", "scan_history")

_client: QdrantClient | None = None


def get_client() -> QdrantClient:
    global _client
    if _client is None:
        _client = QdrantClient(url=os.environ["QDRANT_URL"])
    return _client


@mcp.tool()
async def search_historical_scans(
    service_id: str, cve_id: str | None = None
) -> dict[str, Any]:
    """
    Search historical scan records for a service, optionally filtered by CVE.
    Returns prior exposure history, resolution status, and recurrence count.
    """
    service_id = service_id.strip()
    if not service_id:
        return {"error": "service_id required"}
    # Phase 1: filter by payload (exact match). Phase 3: replace with embedding search.
    from qdrant_client.models import Filter, FieldCondition, MatchValue

    must = [FieldCondition(key="service", match=MatchValue(value=service_id))]
    if cve_id:
        must.append(
            FieldCondition(key="cve", match=MatchValue(value=cve_id.strip().upper()))
        )

    results = get_client().scroll(
        collection_name=COLLECTION,
        scroll_filter=Filter(must=must),
        limit=20,
        with_payload=True,
    )[0]
    records = [r.payload for r in results]
    resolved_count = sum(1 for r in records if r.get("resolved"))

    return {
        "service_id": service_id,
        "total_prior_findings": len(records),
        "resolved": resolved_count,
        "unresolved": len(records) - resolved_count,
        "records": records[:10],  # cap response size
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")
