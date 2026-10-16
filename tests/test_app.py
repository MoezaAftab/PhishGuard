import pytest
import json
from app import app, scan_history


@pytest.fixture
def client():
    app.config["TESTING"] = True
    scan_history.clear()
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
        "/api/scan",
        data=json.dumps(payload),
        content_type="application/json"
    )
    assert response.status_code == 200
    data = response.get_json()
    assert "scan_id" in data
    assert "overall_score" in data
    assert data["overall_score"] > 40.0


def test_api_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "healthy"
    assert len(data["agents_available"]) >= 4


def test_history_and_export(client):
    # Perform a scan first
    client.post("/scan/url", data={"url": "https://example.com"})
    assert len(scan_history) == 1
    scan_id = scan_history[0]["scan_id"]

    # Check history page
    hist_resp = client.get("/history")
    assert hist_resp.status_code == 200
    assert scan_id.encode() in hist_resp.data

    # Check export route
    exp_resp = client.get(f"/export/{scan_id}")
    assert exp_resp.status_code == 200
    assert exp_resp.content_type == "application/json"
