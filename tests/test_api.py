from __future__ import annotations

from fastapi.testclient import TestClient

from secure_data_clean_room.api import create_app
from secure_data_clean_room.service import CleanRoomService
from secure_data_clean_room.settings import Settings


def test_api_auth_roles_query_and_security_headers(
    service: CleanRoomService, settings: Settings
) -> None:
    client = TestClient(create_app(settings))
    health = client.get("/healthz")
    assert health.status_code == 200
    assert health.json()["dataset"] == "workforce-v1"
    assert health.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in health.headers["content-security-policy"]

    missing_auth = client.post("/v1/query", json={"sql": "SELECT COUNT(*) FROM employees"})
    assert missing_auth.status_code == 401
    assert (
        client.post(
            "/v1/query",
            headers={"X-API-Key": "invalid-token-00000"},
            json={"sql": "SELECT COUNT(*) FROM employees"},
        ).status_code
        == 401
    )
    response = client.post(
        "/v1/query",
        headers={"X-API-Key": "test-analyst-key-0001"},
        json={"sql": "SELECT department, AVG(salary) FROM employees GROUP BY department"},
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"
    assert response.json()["rows"]

    forbidden = client.get("/v1/audit/verify", headers={"X-API-Key": "test-analyst-key-0001"})
    assert forbidden.status_code == 403
    audit = client.get("/v1/audit/verify", headers={"X-API-Key": "test-auditor-key-0001"})
    assert audit.status_code == 200 and audit.json()["valid"] is True


def test_api_explain_budget_metrics_and_dashboard(
    service: CleanRoomService, settings: Settings
) -> None:
    client = TestClient(create_app(settings))
    headers = {"X-API-Key": "test-analyst-key-0001"}
    explain = client.post(
        "/v1/policy/explain",
        headers=headers,
        json={"sql": "SELECT region, AVG(salary) FROM employees WHERE active = 1 GROUP BY region"},
    )
    assert explain.status_code == 200
    assert explain.json()["parameters"] == [1, 10, 100]
    budget = client.get("/v1/budget", headers=headers)
    assert budget.status_code == 200 and budget.json()["spent"] == 0

    metrics = client.get("/metrics", headers={"X-API-Key": "test-privacy-key-0001"})
    assert metrics.status_code == 200
    assert "clean_room_audit_chain_valid 1" in metrics.text
    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert "Never receive raw rows" in dashboard.text
    assert client.get("/assets/app.js").status_code == 200
