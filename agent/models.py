from pydantic import BaseModel, Field
from enum import Enum


class Severity(str, Enum):
    critical = "CRITICAL"
    high = "HIGH"
    medium = "MEDIUM"
    low = "LOW"
    informational = "INFORMATIONAL"


class BasicIncidentReport(BaseModel):
    alert_id: str
    service_id: str
    cve_id: str | None = None

    # CVE findings
    cvss_score: float | None = None
    epss_score: float | None = None
    cve_description: str | None = None

    # Graph findings
    reachable_from_internet: bool = False
    attack_paths: list[list[str]] = Field(default_factory=list)
    hop_count: int | None = None

    # History findings:
    prior_exposure_count: int = 0
    unresolved_prior: int = 0

    # Verdict
    severity: Severity = Severity.informational
    remediation: list[str] = Field(default_factory=list)
    summary: str = ""

    # Audit
    langsmith_trace_url: str | None = None
