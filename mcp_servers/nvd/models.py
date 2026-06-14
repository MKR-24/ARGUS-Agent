from pydantic import BaseModel, Field


class CVEDetail(BaseModel):
    cve_id: str
    description: str
    cvss_v3_score: float | None = None
    cvss_v3_vector: str | None = None
    epss_score: float | None = None  # probability of exploit in 30 days
    epss_percentile: float | None = None
    published: str | None = None
    references: list[str] = Field(default_factory=list)
