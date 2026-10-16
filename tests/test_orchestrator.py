import pytest
from agents.orchestrator import PhishGuardOrchestrator


@pytest.fixture
def orchestrator():
    return PhishGuardOrchestrator()


def test_orchestrator_url_scan(orchestrator):
    payload = {"url": "http://secure-login.paypa1-update.xyz/login"}
    report = orchestrator.scan(payload)
    
    assert "scan_id" in report
    assert "overall_score" in report
    assert report["verdict"] in ["HIGH_RISK", "CRITICAL"]
    assert "url_agent" in report["agent_results"]
    assert len(report["recommendations"]) > 0


def test_orchestrator_email_scan(orchestrator):
    payload = {
        "subject": "Urgent Security Alert",
        "body": "Dear Customer, immediate action required. Verify your password now.",
        "headers": {"Authentication-Results": "spf=fail dkim=fail"}
    }
    report = orchestrator.scan(payload)
    
    assert report["overall_score"] >= 60.0
    assert "content_agent" in report["agent_results"]
    assert "header_agent" in report["agent_results"]


def test_orchestrator_raw_eml_scan(orchestrator):
    raw_email = (
        "From: alerts@netflix-payment-update.xyz\n"
        "To: victim@example.com\n"
        "Subject: Your Netflix membership is on hold\n"
        "Authentication-Results: spf=fail\n"
        "\n"
        "Dear Customer, update your payment details immediately within 24 hours:\n"
        "http://netflix-billing-update.xyz/login"
    )
    report = orchestrator.scan({"raw_email": raw_email})
    assert report["overall_score"] >= 65.0
    assert report["verdict"] in ["HIGH_RISK", "CRITICAL"]
