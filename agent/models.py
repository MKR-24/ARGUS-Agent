from pydantic import BaseModel, Field
from enum import Enum


class Severity(str, Enum):
    critical = "CRITICAL"
    high = "HIGH"
    medium = "MEDIUM"
    low = "LOW"
    informational = "INFORMATIONAL"


class MitreAttackTag(BaseModel):
    technique_id: str  # eg: "T1190"
    technique_name: str  # eg: "Exploit Public-Facing Application"
    tactic: str  # eg: "Initial Access"
    url: str  # eg: "https://attack.mitre.org/techniques/T1190"


class ConfidenceBreakdown(BaseModel):
    cve_data: float = Field(ge=0.0, le=1.0, description="Confidence in CVE findings")
    graph_data: float = Field(
        ge=0.0, le=1.0, description="Confidence in graph findings"
    )
    history_data: float = Field(
        ge=0.0, le=1.0, description="Confidence in history findings"
    )
    overall: float = Field(ge=0.0, le=1.0, description="Weighted overall confidence")


class IncidentReport(BaseModel):
    # Identity
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

    confidence: ConfidenceBreakdown | None = None
    mitre_attack_tags: list[MitreAttackTag] = Field(default_factory=list)
    mean_time_to_investigate_seconds: float | None = None

    # Audit
    langsmith_trace_url: str | None = None
    report_version: str = "2.0"
