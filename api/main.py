"""
ARGUS alert ingestion API.
Receives security alerts and triggers autonomous investigation.
"""

import asyncio
import logging
import os
import time
import traceback

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
import base64
from agent.graph import run_investigation
from fastapi.responses import StreamingResponse
from agent.streaming import create_stream, get_stream, remove_stream

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
    evidence_images: list[str] = Field(
        default_factory=list,
        description="Base64-encoded PNG/JPEG screenshots. Max 5.",
    )

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

    @field_validator("evidence_images")
    @classmethod
    def validate_images(cls, images: list[str]) -> list[str]:
        if len(images) > 5:
            raise ValueError("Maximum 5 evidence images per alert")
        for img in images:
            try:
                base64.b64decode(img, validate=True)
            except Exception:
                raise ValueError("evidence_images must be valid base64")
        return images


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


@app.post("/alerts/stream")
async def investigate_alert_stream(alert: AlertRequest):
    """
    Submit alert and receive SSE stream of agent progress.
    Connect to /alerts/{alert_id}/events for the event stream.
    """
    stream = create_stream(alert.alert_id)

    asyncio.create_task(_run_with_stream(alert, stream))

    return {
        "alert_id": alert.alert_id,
        "stream_url": f"/alerts/{alert.alert_id}/events",
    }


@app.get("/alerts/{alert_id}/events")
async def alert_events(alert_id: str):
    """SSE endpoint — streams agent progress events."""
    stream = get_stream(alert_id)
    if not stream:
        return {"error": "Stream not found"}

    return StreamingResponse(
        stream.events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


async def _run_with_stream(alert: AlertRequest, stream):
    try:
        report = await run_investigation(
            alert_id=alert.alert_id,
            service_id=alert.service_id,
            cve_id=alert.cve_id,
            description=alert.description,
            severity_raw=alert.severity_raw,
            evidence_images=alert.evidence_images,
            stream=stream,
        )
        await stream.emit("complete", {"report": report})
    except Exception as e:
        await stream.emit("error", {"message": str(e)})
    finally:
        await stream.done()
        remove_stream(alert.alert_id)
