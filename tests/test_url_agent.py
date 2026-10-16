import pytest
from agents.url_agent import UrlAgent


@pytest.fixture
def agent():
    return UrlAgent()


def test_clean_legitimate_url(agent):
    payload = {"url": "https://www.google.com"}
    result = agent.analyze(payload)
    assert result.score < 25.0
    assert result.verdict in ["SAFE", "LOW_RISK"]


def test_ip_address_host_url(agent):
    payload = {"url": "http://192.168.1.1/login"}
    result = agent.analyze(payload)
    assert result.score >= 40.0
    assert any("raw numerical IP address" in flag for flag in result.flags)


def test_typosquatting_brand_spoofing(agent):
    payload = {"url": "http://paypa1-security.xyz/login"}
    result = agent.analyze(payload)
    assert result.score >= 60.0
    assert any("typosquatting" in flag.lower() or "mimicry" in flag.lower() or "xyz" in flag.lower() for flag in result.flags)


def test_punycode_and_suspicious_tld(agent):
    payload = {"url": "http://xn--pple-43d.top/account/verify"}
    result = agent.analyze(payload)
    assert result.score >= 50.0
    assert any("Punycode" in flag for flag in result.flags)
    assert any(".top" in flag for flag in result.flags)


def test_empty_url_handling(agent):
    payload = {}
    result = agent.analyze(payload)
    assert result.score == 0.0
    assert result.verdict == "SAFE"
