"""
Security & Input Sanitization Module for PhishGuard
Enforces defensive application security, input validation, SSRF prevention,
CSRF validation, and OWASP-recommended HTTP response security headers.
"""

import re
import secrets
import ipaddress
from urllib.parse import urlparse
from typing import Tuple, Optional, Dict, Any
from flask import session, request, abort


# Disallowed URL schemes that can lead to XSS, local file disclosure, or remote code execution
DANGEROUS_SCHEMES = {"javascript", "vbscript", "file", "data", "blob", "ftp", "telnet", "ldap"}

# Private & Link-Local IP networks for SSRF protection
PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("10.0.0.0/8"),       # Private Class A
    ipaddress.ip_network("172.16.0.0/12"),    # Private Class B
    ipaddress.ip_network("192.168.0.0/16"),   # Private Class C
    ipaddress.ip_network("169.254.0.0/16"),   # Cloud metadata & Link-Local
    ipaddress.ip_network("0.0.0.0/8"),
]


def is_ssrf_forbidden(hostname: str) -> bool:
    """Check if hostname is loopback, localhost, or cloud metadata."""
    if not hostname:
        return False
    lower = hostname.lower().strip()
    if lower in ("localhost", "127.0.0.1", "::1", "metadata.google.internal", "169.254.169.254"):
        return True
    try:
        ip = ipaddress.ip_address(lower)
        if ip.is_loopback or ip.is_link_local or ip.is_reserved or str(ip) == "169.254.169.254":
            return True
    except ValueError:
        pass
    return False


def is_private_ip(hostname: str) -> bool:
    """Check if IP falls into RFC 1918 private subnets."""
    try:
        ip = ipaddress.ip_address(hostname)
        for net in PRIVATE_NETWORKS:
            if ip in net:
                return True
    except ValueError:
        pass
    return False


def validate_and_sanitize_url(raw_url: str, block_private_ips: bool = False) -> Tuple[bool, str, Optional[str]]:
    """
    Validates and cleans user-submitted URLs.
    
    Returns:
        (is_valid, cleaned_url, error_message)
    """
    if not raw_url or not isinstance(raw_url, str):
        return False, "", "URL cannot be empty."

    # Strip null bytes and control characters
    cleaned = raw_url.strip().replace("\x00", "")

    if len(cleaned) > 2048:
        return False, "", "URL exceeds maximum permitted length (2048 characters)."

    # Check for dangerous pseudo-protocols
    lower_target = cleaned.lower()
    for scheme in DANGEROUS_SCHEMES:
        if lower_target.startswith(f"{scheme}:"):
            return False, "", f"Disallowed URI scheme '{scheme}:' detected for security reasons."

    # Ensure http/https scheme or prepend http for analysis
    parse_target = cleaned if ("://" in cleaned) else f"http://{cleaned}"
    
    try:
        parsed = urlparse(parse_target)
    except Exception:
        return False, "", "Malformed URL structure."

    if parsed.scheme.lower() not in ("http", "https"):
        return False, "", f"Scheme '{parsed.scheme}' is not permitted. Only HTTP and HTTPS are allowed."

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False, "", "URL does not contain a valid destination hostname."

    # Prevent loopback and metadata hostnames
    if is_ssrf_forbidden(hostname):
        return False, "", "Access to loopback, localhost, and cloud metadata targets is prohibited (SSRF Defense)."

    if block_private_ips and is_private_ip(hostname):
        return False, "", "Target resolves to reserved internal IP subnet. SSRF blocked."

    return True, cleaned, None


def sanitize_text(text: Any, max_length: int = 50000) -> str:
    """
    Sanitize text input, stripping null bytes and enforcing bounded length
    to defend against buffer bloat and ReDoS regex denial of service.
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)

    # Remove null bytes
    sanitized = text.replace("\x00", "").strip()
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    return sanitized


def validate_headers(headers: Any) -> Dict[str, str]:
    """
    Sanitize and validate email headers dictionary or raw RFC822 string.
    Defends against CRLF header splitting attacks.
    """
    clean_dict: Dict[str, str] = {}
    if not headers:
        return clean_dict

    if isinstance(headers, dict):
        for k, v in headers.items():
            if not isinstance(k, str) or not isinstance(v, str):
                continue
            # Header keys must not contain newlines
            clean_k = re.sub(r"[\r\n]", "", k.strip())
            # Header values: collapse newlines to avoid response/header injection
            clean_v = re.sub(r"[\r\n]+", " ", v.strip())
            if clean_k and clean_v:
                clean_dict[clean_k] = clean_v[:1000]

    return clean_dict


def generate_csrf_token() -> str:
    """Generate or retrieve cryptographically strong CSRF token for user session."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def verify_csrf_token(token: Optional[str]) -> bool:
    """Verify submitted CSRF token against session token."""
    expected = session.get("_csrf_token")
    if not expected or not token:
        return False
    return secrets.compare_digest(expected, token)


def apply_security_headers(response):
    """
    Apply modern OWASP HTTP security headers to outgoing responses.
    """
    # Content Security Policy (allows fontawesome & google fonts while blocking untrusted scripts)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )

    # Clickjacking protection
    response.headers["X-Frame-Options"] = "DENY"

    # Prevent MIME sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Cross-site scripting filter
    response.headers["X-XSS-Protection"] = "1; mode=block"

    # Referrer policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Restrict dangerous browser features
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"

    return response
