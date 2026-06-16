"""
ARGUS alert ingestion API.
Receives security alerts and triggers autonomous investigation.
"""

import logging
import os
import time
import traceback

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from agent.graph import run_investigation

load_dotenv()
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)


# Request schema
class AlertRequest(BaseModel):
    alert_id: str = Field(..., min_length=1, max_length=100)
    service_id: str = Field(..., min_length=1, max_length=100)
    cve_id: str | None = Field(None, pattern=r"^CVE-\d{4}-\d+$")
    scanner: str = Field(..., min_length=1, max_length=50)
    severity_raw: str = Field(..., min_length=1, max_length=20)
    description: str = Field(..., min_length=1, max_length=2000)

    @field_validator("description")
    @classmethod
    def sanitise_descriptions(cls, v: str) -> str:
        """
        Reject descriptions containing obvious prompt injection patterns.
        The agent has its own guardrails, but we filter at ingestion too.
        Defence in depth.
        """
        injection_patterns = [
            "ignore previous instructions",
            "ignore all instructions",
            "you are now",
            "disregard",
            "new instructions",
            "system prompt",
        ]
        lower = v.lower()
        for pattern in injection_patterns:
            if pattern in lower:
                raise ValueError(
                    f"Alert description contains disallowed pattern: '{pattern}'. "
                    "Possible prompt injection attempt."
                )
        return v


# APP
app = FastAPI(
    title="ARGUS — Autonomous Security Investigation Agent",
    version="0.2.0",
    description="Submit security alerts for autonomous multi-tool investigation.",
)


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.2.0"}


@app.post("/alerts", status_code=200)
async def investigate_alert(alert: AlertRequest, request: Request):
    """
    Submit a security alert for autonomous investigation.
    Returns a structured incident report.
    """
    start = time.monotonic()
    logger.info("Received alert %s for service %s", alert.alert_id, alert.service_id)

    try:
        report = await run_investigation(
            alert_id=alert.alert_id,
            service_id=alert.service_id,
            cve_id=alert.cve_id,
            description=alert.description,
            severity_raw=alert.severity_raw,
        )
    except Exception as e:
        logger.error(
            "Investigation failed for alert %s: %s",
            alert.alert_id,
            traceback.format_exc(),
        )
        raise HTTPException(status_code=500, detail=f"Investigation failed: {e}")
    elapsed = round(time.monotonic() - start, 2)
    logger.info("Alert %s investigated in %.2fs", alert.alert_id, elapsed)

    return {
        "report": report,
        "investigation_time_seconds": elapsed,
    }
