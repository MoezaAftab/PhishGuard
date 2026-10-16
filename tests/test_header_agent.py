import pytest
from agents.header_agent import HeaderAgent


@pytest.fixture
def agent():
    return HeaderAgent()


def test_clean_spf_dkim_headers(agent):
    headers = {
        "From": "billing@stripe.com",
        "Reply-To": "billing@stripe.com",
        "Authentication-Results": "spf=pass dkim=pass dmarc=pass",
        "Message-ID": "<unique123@stripe.com>",
        "Date": "Wed, 16 Oct 2026 12:00:00 +0000"
    }
    result = agent.analyze({"headers": headers})
    assert result.score < 20.0
    assert result.verdict == "SAFE"


def test_spf_fail_and_spoofing(agent):
    headers = {
        "From": "PayPal Security <security@paypal-notice.xyz>",
        "Reply-To": "attacker@inbox.ru",
        "Authentication-Results": "spf=fail (IP not permitted) dkim=fail",
        "Message-ID": "<test@evil.xyz>",
        "Date": "Wed, 16 Oct 2026 12:00:00 +0000"
    }
    result = agent.analyze({"headers": headers})
    assert result.score >= 60.0
    assert any("SPF" in flag for flag in result.flags)
    assert any("Reply-To Mismatch" in flag for flag in result.flags)


def test_raw_header_parsing(agent):
    raw = (
        "From: admin@bank.com\n"
        "Reply-To: badguy@external.org\n"
        "Authentication-Results: dkim=fail\n"
    )
    result = agent.analyze({"headers": raw})
    assert result.score > 30.0
    assert any("Reply-To Mismatch" in flag for flag in result.flags)
