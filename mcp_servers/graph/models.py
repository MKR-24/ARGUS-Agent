from pydantic import BaseModel


class AttackPath(BaseModel):
    path: list[str]
    hop_count: int
    reachable_from_internet: bool


class ServiceInfo(BaseModel):
    id: str
    name: str
    type: str
    version: str | None = None
    cves: list[str] = []
