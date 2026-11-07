import pytest
from agents.threat_intel_agent import ThreatIntelAgent


@pytest.fixture
def agent():
    return ThreatIntelAgent()


def test_clean_legitimate_domain(agent):
    payload = {"url": "https://www.google.com"}
    result = agent.analyze(payload)
    assert result.score < 30.0
    assert result.verdict in ["SAFE", "LOW_RISK"]


def test_dynamic_dns_detection(agent):
    payload = {"url": "http://evil-tracker.duckdns.org/login"}
    result = agent.analyze(payload)
    assert result.score >= 40.0
    assert any("dynamic DNS" in f.lower() or "duckdns" in f.lower() for f in result.flags)


def test_private_ip_ssrf_flagging(agent):
    payload = {"url": "http://127.0.0.1:8080/dashboard"}
    result = agent.analyze(payload)
    assert result.score >= 80.0
    assert result.verdict in ["HIGH_RISK", "CRITICAL"]
    assert any("internal/private IP" in f or "SSRF" in f for f in result.flags)


def test_empty_target_handling(agent):
    payload = {}
    result = agent.analyze(payload)
    assert result.score == 0.0
    assert result.verdict == "SAFE"
