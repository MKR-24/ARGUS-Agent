"""MCP server — NVD CVE lookup with EPSS enrichment."""

import os
import logging
from typing import Any

import httpx
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

from .models import CVEDetail

load_dotenv()
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_BASE = "https://api.first.org/data/v1/epss"
API_KEY = os.environ.get(
    "NVD_API_KEY"
)  # getenv not environ so it doesn't crash if absent

mcp = FastMCP("nvd-server")


class CVELookupInput(BaseModel):
    cve_id: str


@mcp.tool()
async def get_cve_details(cve_id: str) -> dict[str, Any]:
    """
    Fetch CVE details from NVD and enrich with EPSS probability score.
    Returns CVSS severity, description, and 30-day exploit probability.
    """
    # Validate format before hitting the API — prevents injection via CVE ID field
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        return {"error": f"Invalid CVE ID format: {cve_id}"}

    headers = {"User-Agent": "soc-agent/1.0"}
    if API_KEY:
        headers["apiKey"] = API_KEY  # header, not query param

    async with httpx.AsyncClient(timeout=15.0) as client:
        # NVD lookup
        try:
            nvd_resp = await client.get(
                NVD_BASE,
                params={"cveId": cve_id},
                headers=headers,
            )
            nvd_resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            logger.error("NVD API error for %s: %s", cve_id, e.response.status_code)
            return {"error": f"NVD API returned {e.response.status_code}"}
        except httpx.RequestError as e:
            logger.error("NVD network error: %s", e)
            return {"error": "NVD API unreachable"}

        nvd_data = nvd_resp.json()
        vulns = nvd_data.get("vulnerabilities", [])
        if not vulns:
            return {"error": f"{cve_id} not found in NVD"}

        cve_item = vulns[0]["cve"]
        descriptions = cve_item.get("descriptions", [])
        desc = next(
            (d["value"] for d in descriptions if d["lang"] == "en"), "No description"
        )

        # Extract CVSS v3
        cvss_score = None
        cvss_vector = None
        metrics = cve_item.get("metrics", {})
        if "cvssMetricV31" in metrics:
            m = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_score = m.get("baseScore")
            cvss_vector = m.get("vectorString")

        refs = [r["url"] for r in cve_item.get("references", [])[:5]]  # cap at 5

        # EPSS lookup
        epss_score = epss_percentile = None
        try:
            epss_resp = await client.get(EPSS_BASE, params={"cve": cve_id})
            epss_resp.raise_for_status()
            epss_data = epss_resp.json().get("data", [])
            if epss_data:
                epss_score = float(epss_data[0].get("epss", 0))
                epss_percentile = float(epss_data[0].get("percentile", 0))
        except Exception as e:
            logger.warning("EPSS lookup failed for %s: %s", cve_id, e)
            # Non-fatal — return CVE data without EPSS

        result = CVEDetail(
            cve_id=cve_id,
            description=desc,
            cvss_v3_score=cvss_score,
            cvss_v3_vector=cvss_vector,
            epss_score=epss_score,
            epss_percentile=epss_percentile,
            published=cve_item.get("published"),
            references=refs,
        )
        return result.model_dump()


if __name__ == "__main__":
    mcp.run(transport="stdio")
