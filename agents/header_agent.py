"""
Header & Authentication Verifier Agent
Specialized agent for inspecting email headers, SPF/DKIM/DMARC authentication results,
and sender address alignment / spoofing.
"""

import re
from typing import Dict, Any, List, Optional
from email.utils import parseaddr
from .base_agent import BaseAgent, AgentResult


class HeaderAgent(BaseAgent):
    """Analyzes email headers for SPF, DKIM, DMARC, and sender impersonation."""

    def __init__(self, weight: float = 1.3):
        super().__init__(name="Header & Authentication Verifier", weight=weight)

    def analyze(self, data: Dict[str, Any]) -> AgentResult:
        headers = data.get("headers", {})

        # If raw text headers were passed, parse into dict if needed
        if isinstance(headers, str):
            headers = self._parse_raw_headers(headers)

        if not headers:
            return AgentResult(
                agent_name=self.name,
                score=0.0,
                verdict="SAFE",
                confidence=0.4,
                flags=["No email headers provided for verification"],
                details={},
                summary="Headers were omitted or not supplied in scan."
            )

        score = 0.0
        flags = []
        details: Dict[str, Any] = {}

        # Normalize headers dictionary to lowercase keys
        norm_headers = {k.lower(): str(v) for k, v in headers.items()}

        # 1. From Address vs Reply-To / Return-Path Mismatch
        from_header = norm_headers.get("from", "")
        reply_to = norm_headers.get("reply-to", "")
        return_path = norm_headers.get("return-path", "")

        from_name, from_email = parseaddr(from_header)
        _, reply_email = parseaddr(reply_to)
        _, return_email = parseaddr(return_path)

        details["from"] = from_email
        details["reply_to"] = reply_email or "Not set"
        details["return_path"] = return_email or "Not set"

        from_domain = self._get_domain(from_email)
        reply_domain = self._get_domain(reply_email)
        return_domain = self._get_domain(return_email)

        # Check Display Name Spoofing: e.g. "PayPal Support <evil@xyz.com>"
        if from_name and ("@" in from_name or any(brand in from_name.lower() for brand in ["paypal", "microsoft", "google", "apple", "chase", "bank"])):
            if from_domain and not any(brand in from_domain for brand in ["paypal", "microsoft", "google", "apple", "chase"]):
                score += 45.0
                flags.append(f"Display Name Spoofing: Name '{from_name}' claims trusted brand but actual sender domain is '{from_domain}'")

        # Check From vs Reply-To Domain Mismatch
        if reply_domain and from_domain and reply_domain != from_domain:
            score += 35.0
            flags.append(f"Reply-To Mismatch: Responses route to external domain '{reply_domain}' instead of sender '{from_domain}'")

        # Check From vs Return-Path Domain Mismatch
        if return_domain and from_domain and return_domain != from_domain:
            score += 20.0
            flags.append(f"Return-Path Discrepancy: Bounce path '{return_domain}' does not align with sender domain '{from_domain}'")

        # 2. Authentication-Results & SPF Checks
        auth_results = norm_headers.get("authentication-results", "")
        received_spf = norm_headers.get("received-spf", "")

        combined_auth = f"{auth_results} {received_spf}".lower()

        # Check SPF status
        spf_status = self._check_auth_status(combined_auth, "spf")
        details["spf"] = spf_status
        if spf_status == "fail":
            score += 50.0
            flags.append("SPF Authentication HARD FAIL: Sending IP is not authorized by domain SPF policy")
        elif spf_status in ["softfail", "neutral"]:
            score += 25.0
            flags.append(f"SPF Inconclusive ({spf_status}): Domain policy does not strictly validate the origin")

        # Check DKIM status
        dkim_status = self._check_auth_status(combined_auth, "dkim")
        details["dkim"] = dkim_status
        if dkim_status == "fail":
            score += 40.0
            flags.append("DKIM Signature FAIL: Cryptographic signature verification failed; possible body or header tampering")

        # Check DMARC status
        dmarc_status = self._check_auth_status(combined_auth, "dmarc")
        details["dmarc"] = dmarc_status
        if dmarc_status == "fail":
            score += 45.0
            flags.append("DMARC Policy FAIL: Message failed domain alignment and authentication enforcement")

        # 3. Missing Mandatory RFC Headers
        if "message-id" not in norm_headers:
            score += 15.0
            flags.append("Missing standard 'Message-ID' RFC header")
        if "date" not in norm_headers:
            score += 10.0
            flags.append("Missing standard 'Date' header")

        # 4. Suspicious Relay in Received Hops
        received_headers = [v for k, v in headers.items() if k.lower() == "received"]
        if received_headers:
            details["hop_count"] = len(received_headers)
            for hop in received_headers:
                if any(kw in hop.lower() for kw in ["dynamic.pool", "unknown [", "dsl.", "broadband"]):
                    score += 20.0
                    flags.append("Routing anomaly: Sent via unauthenticated residential/dynamic IP pool relay")
                    break

        final_score = min(max(score, 0.0), 100.0)
        verdict = self.score_to_verdict(final_score)

        summary = (
            f"Header verification complete. Security score: {final_score:.1f}/100 ({verdict}). "
            f"SPF: {spf_status or 'N/A'}, DKIM: {dkim_status or 'N/A'}, DMARC: {dmarc_status or 'N/A'}."
        )

        return AgentResult(
            agent_name=self.name,
            score=round(final_score, 1),
            verdict=verdict,
            confidence=0.95 if auth_results or received_spf else 0.75,
            flags=flags,
            details=details,
            summary=summary
        )

    def _get_domain(self, email_str: str) -> str:
        if "@" in email_str:
            return email_str.split("@")[-1].strip().lower()
        return ""

    def _check_auth_status(self, text: str, protocol: str) -> Optional[str]:
        """Extract pass/fail status for spf, dkim, or dmarc."""
        patterns = [
            rf"{protocol}=([a-z]+)",
            rf"{protocol}\s+([a-z]+)",
        ]
        for p in patterns:
            match = re.search(p, text)
            if match:
                return match.group(1).lower()
        return None

    def _parse_raw_headers(self, raw_headers: str) -> Dict[str, str]:
        """Convert raw RFC822 multiline headers into dictionary."""
        parsed: Dict[str, str] = {}
        current_key = None
        for line in raw_headers.splitlines():
            if not line.strip():
                continue
            if line[0] in (" ", "\t") and current_key:
                parsed[current_key] += " " + line.strip()
            elif ":" in line:
                k, v = line.split(":", 1)
                current_key = k.strip()
                parsed[current_key] = v.strip()
        return parsed
