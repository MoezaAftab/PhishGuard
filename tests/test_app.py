import pytest
import json
from app import app
import database as db


@pytest.fixture
def client():
    app.config["TESTING"] = True
    db.clear_all_scans()
    with app.test_client() as client:
        yield client


def test_index_route(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"PhishGuard" in response.data
    assert b"URL Inspector" in response.data


def test_scan_url_post(client):
    response = client.post("/scan/url", data={"url": "https://google.com"})
    assert response.status_code == 200
    assert b"Threat Assessment Report" in response.data


def test_scan_email_post(client):
    response = client.post("/scan/email", data={
        "subject": "Important Account Update",
        "body": "Please review recent transactions.",
        "sender": "alert@bank.com"
    })
    assert response.status_code == 200
    assert b"Threat Assessment Report" in response.data


def test_api_scan_json(client):
    payload = {"url": "http://192.168.1.100/login"}
    response = client.post(
        "/api/v1/scan",
        data=json.dumps(payload),
        content_type="application/json"
    )
    assert response.status_code == 200
    data = response.get_json()
    assert "scan_id" in data
    assert "overall_score" in data
    assert data["overall_score"] > 40.0


def test_individual_agent_apis(client):
    # Test URL Agent API
    res_url = client.post("/api/v1/agents/url", json={"url": "https://google.com"})
    assert res_url.status_code == 200
    assert res_url.get_json()["score"] < 25.0

    # Test Content Agent API
    res_content = client.post("/api/v1/agents/content", json={"body": "Hello world team update", "subject": "Update"})
    assert res_content.status_code == 200

    # Test Header Agent API
    res_header = client.post("/api/v1/agents/header", json={"headers": {"From": "test@domain.com"}})
    assert res_header.status_code == 200

    # Test Threat Intel Agent API
    res_ti = client.post("/api/v1/agents/threat-intel", json={"url": "https://google.com"})
    assert res_ti.status_code == 200

    # Test ML Agent API
    res_ml = client.post("/api/v1/agents/ml", json={"url": "https://google.com"})
    assert res_ml.status_code == 200


def test_api_health(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "healthy"
    assert data["agents_count"] == 5
    assert len(data["agents_active"]) == 5
    assert "database" in data


def test_api_stats(client):
    response = client.get("/api/v1/stats")
    assert response.status_code == 200
    data = response.get_json()
    assert "total_scans" in data
    assert "safe_count" in data


def test_history_and_export(client):
    # Perform a scan first
    client.post("/scan/url", data={"url": "https://example.com"})
    scans = db.get_all_scans()
    assert len(scans) >= 1
    scan_id = scans[0]["scan_id"]

    # Check history page
    hist_resp = client.get("/history")
    assert hist_resp.status_code == 200
    assert scan_id.encode() in hist_resp.data

    # Check export route
    exp_resp = client.get(f"/export/{scan_id}")
    assert exp_resp.status_code == 200
    assert exp_resp.content_type == "application/json"
