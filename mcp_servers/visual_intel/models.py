from pydantic import BaseModel
from enum import Enum


class EvidenceType(str, Enum):
    dashboard = "dashboard"
    packet_capture = "packet_capture"
    attack_graph = "attack_graph"
    siem_panel = "siem_panel"
    cve_poc = "cve_poc"
    unknown = "unknown"


class VisualFinding(BaseModel):
    evidence_type: EvidenceType
    summary: str
    indicators: list[str]
    severity_signal: str | None = None
    confidence: float
    raw_extraction: str


class VisualAnalysisResult(BaseModel):
    findings: list[VisualFinding]
    overall_risk_signal: str
    analyst_note: str
    image_count: int
