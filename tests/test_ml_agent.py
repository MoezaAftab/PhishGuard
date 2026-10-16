import pytest
from agents.ml_agent import MLAgent


@pytest.fixture
def agent():
    return MLAgent()


def test_ml_clean_sample(agent):
    payload = {
        "url": "https://docs.python.org",
        "subject": "Python 3.12 Release Notes",
        "body": "Here are the new features and bug fixes in Python 3.12."
    }
    result = agent.analyze(payload)
    assert result.score < 25.0
    assert result.verdict in ["SAFE", "LOW_RISK"]


def test_ml_phishing_sample_explainability(agent):
    payload = {
        "url": "http://192.168.1.1/verify?tld=bad",
        "subject": "URGENT ACCOUNT SUSPENSION NOTICE",
        "body": "DEAR CUSTOMER, YOUR ACCOUNT HAS BEEN SUSPENDED. VERIFY YOUR PASSWORD WITHIN 24 HOURS IMMEDIATELY.",
        "headers": {"Authentication-Results": "spf=fail"}
    }
    result = agent.analyze(payload)
    assert result.score >= 60.0
    assert "top_risk_drivers" in result.details
    assert len(result.details["top_risk_drivers"]) > 0
