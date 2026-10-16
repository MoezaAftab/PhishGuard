import pytest
from agents.content_agent import ContentAgent


@pytest.fixture
def agent():
    return ContentAgent()


def test_benign_email_content(agent):
    payload = {
        "subject": "Weekly Team Status Sync",
        "body": "Hi Alex, here are the updates from our standup today. Have a great weekend!"
    }
    result = agent.analyze(payload)
    assert result.score < 20.0
    assert result.verdict == "SAFE"


def test_urgency_and_credential_phishing(agent):
    payload = {
        "subject": "URGENT: Your account has been suspended",
        "body": "Dear Customer, immediate action required within 24 hours. Click here to verify your password and identity."
    }
    result = agent.analyze(payload)
    assert result.score >= 45.0
    assert any("urgency" in flag.lower() for flag in result.flags)
    assert any("credential" in flag.lower() for flag in result.flags)


def test_html_link_mismatch(agent):
    html_body = '<p>Check your invoice: <a href="http://malicious-trap.net/steal">https://chase.com/billing</a></p>'
    payload = {
        "subject": "Invoice Notice",
        "body": html_body
    }
    result = agent.analyze(payload)
    assert result.score >= 30.0
    assert any("mismatch" in flag.lower() for flag in result.flags)
