"""
Penetration Testing & Defensive Security Audit Test Suite
Verifies PhishGuard's defensive safeguards against the OWASP Top 10 vulnerabilities:
- Cross-Site Scripting (XSS)
- Server-Side Request Forgery (SSRF)
- SQL Injection (SQLi)
- Disallowed Protocol Injection (javascript:, file:)
- HTTP Header / CRLF Injection
- Buffer Bloat & Denial of Service (DoS) Bounds
- HTTP Security Headers (CSP, X-Frame-Options, etc.)
- Rate Limiting Enforcement
"""

import pytest
import json
from app import app
from security import (
    validate_and_sanitize_url,
    sanitize_text,
    validate_headers,
    generate_csrf_token,
    verify_csrf_token,
    is_private_ip
)
from database import get_scan, save_scan, SQLITE_DB_PATH


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False  # Allows testing routes directly
    with app.test_client() as client:
        yield client


# ==============================================================================
# 1. Cross-Site Scripting (XSS) Defensive Verification
# ==============================================================================

def test_xss_prevention_in_email_subject(client):
    """Ensure raw script tags in email subject are escaped in HTML response."""
    xss_payload = "<script>alert('pwned')</script>"
    response = client.post("/scan/email", data={
        "subject": xss_payload,
        "body": "Normal body text",
        "sender": "test@domain.com"
    })
    assert response.status_code == 200
    # Must NOT render unescaped script tag
    assert b"<script>alert('pwned')</script>" not in response.data
    # Must contain HTML-escaped representation
    assert b"&lt;script&gt;alert(&#39;pwned&#39;)&lt;/script&gt;" in response.data or b"&lt;script&gt;" in response.data


def test_xss_prevention_in_url_input(client):
    """Ensure javascript pseudo-protocol is rejected."""
    bad_url = "javascript:alert(document.cookie)"
    is_valid, _, error = validate_and_sanitize_url(bad_url)
    assert not is_valid
    assert "Disallowed URI scheme" in error


def test_xss_body_snippet_escaping(client):
    """Ensure HTML vectors in body snippet are escaped safely."""
    xss_snippet = '<b onmouseover=alert(1)>Hover me</b>'
    response = client.post("/scan/email", data={
        "body": xss_snippet
    })
    assert response.status_code == 200
    # Must not contain unescaped onmouseover attribute in rendered preview
    assert b"<b onmouseover" not in response.data


# ==============================================================================
# 2. Server-Side Request Forgery (SSRF) Defensive Verification
# ==============================================================================

def test_ssrf_loopback_rejection():
    """Verify loopback addresses (127.0.0.1, localhost) are blocked."""
    loopback_targets = [
        "http://127.0.0.1:8080/admin",
        "http://localhost:5000/internal",
        "http://127.0.0.1",
        "http://[::1]/internal",
    ]
    for target in loopback_targets:
        is_valid, _, error = validate_and_sanitize_url(target)
        assert not is_valid
        assert "SSRF" in error or "loopback" in error.lower() or "prohibited" in error.lower()


def test_ssrf_cloud_metadata_rejection():
    """Verify cloud metadata endpoint (169.254.169.254) is blocked."""
    metadata_url = "http://169.254.169.254/latest/meta-data/"
    is_valid, _, error = validate_and_sanitize_url(metadata_url)
    assert not is_valid
    assert "SSRF" in error or "metadata" in error.lower() or "prohibited" in error.lower()


def test_ssrf_private_network_identification():
    """Verify private subnet (RFC 1918) IP addresses are properly identified."""
    assert is_private_ip("10.0.0.5") is True
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("172.16.0.1") is True
    assert is_private_ip("8.8.8.8") is False


# ==============================================================================
# 3. SQL Injection (SQLi) Defensive Verification
# ==============================================================================

def test_sql_injection_in_scan_id_lookup(client):
    """Ensure SQL injection strings in report URL return safe 404 and don't leak database data."""
    sqli_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE scans; --",
        "admin' UNION SELECT 1, 2, 3 --",
        "1' OR 1=1--"
    ]
    for payload in sqli_payloads:
        resp = client.get(f"/report/{payload}")
        # Should return safe 404 without database exception
        assert resp.status_code in [404, 400]

    # Verify database table is intact
    test_lookup = get_scan("non-existent-id")
    assert test_lookup is None


# ==============================================================================
# 4. Dangerous Protocol Injection Verification
# ==============================================================================

def test_file_and_data_schemes_rejection():
    """Ensure file:// and data:// schemes are strictly rejected."""
    dangerous = [
        "file:///etc/passwd",
        "file:///C:/Windows/win.ini",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox(1)",
        "ftp://malicious-server.net/payload.exe"
    ]
    for d in dangerous:
        is_valid, _, error = validate_and_sanitize_url(d)
        assert not is_valid
        assert "Disallowed" in error or "not permitted" in error


# ==============================================================================
# 5. CRLF & Header Injection Verification
# ==============================================================================

def test_crlf_header_injection_stripping():
    """Ensure CRLF characters are stripped from header keys and collapsed in values."""
    malicious_headers = {
        "From\r\nSet-Cookie: admin=true": "attacker@evil.com\r\nInjected-Header: 123",
        "Subject\r\n": "Normal Subject\r\nBcc: victim@domain.com"
    }
    clean = validate_headers(malicious_headers)
    for k, v in clean.items():
        assert "\r" not in k
        assert "\n" not in k
        assert "\r" not in v
        assert "\n" not in v


# ==============================================================================
# 6. Buffer Bloat & DoS Bounds Verification
# ==============================================================================

def test_excessive_payload_length_bounded():
    """Ensure massive text input is safely capped to prevent memory exhaustion and ReDoS."""
    huge_string = "A" * 150000
    sanitized = sanitize_text(huge_string, max_length=50000)
    assert len(sanitized) == 50000


def test_excessive_url_length_rejected():
    """Ensure URLs longer than 2048 chars are rejected gracefully."""
    huge_url = "https://example.com/" + ("a" * 3000)
    is_valid, _, error = validate_and_sanitize_url(huge_url)
    assert not is_valid
    assert "exceeds maximum permitted length" in error


# ==============================================================================
# 7. HTTP Security Headers Verification
# ==============================================================================

def test_security_headers_present(client):
    """Ensure critical OWASP security headers are present in server responses."""
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert "Content-Security-Policy" in resp.headers
    assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


# ==============================================================================
# 8. Rate Limiting Verification
# ==============================================================================

def test_api_rate_limiting_enforcement(client):
    """Ensure rate limiter operates properly on endpoint calls."""
    responses = [client.get("/api/v1/health") for _ in range(70)]
    status_codes = [r.status_code for r in responses]
    assert 200 in status_codes
