"""FastAPI endpoint tests."""

from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_alert_missing_required_fields():
    response = client.post("/alerts", json={"alert_id": "X"})
    assert response.status_code == 422


def test_invalid_cve_format_rejected():
    response = client.post(
        "/alerts",
        json={
            "alert_id": "ALERT-002",
            "service_id": "user-svc",
            "cve_id": "NOT-A-CVE",  # invalid format
            "scanner": "trivy",
            "severity_raw": "HIGH",
            "description": "Some vulnerability found",
        },
    )
    assert response.status_code == 422
