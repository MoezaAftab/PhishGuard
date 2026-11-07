"""
Threat Intelligence & DNS Infrastructure Agent
Specialized agent for domain reputation, DNS MX/A infrastructure validation,
dynamic DNS detection, SSRF/private IP screening, and external threat intelligence feeds.
"""

import os
import re
import ipaddress
from urllib.parse import urlparse
from typing import Dict, Any, List, Tuple, Optional
from .base_agent import BaseAgent, AgentResult

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class ThreatIntelAgent(BaseAgent):
    """
    Validates domain DNS infrastructure, MX mail routing readiness,
    dynamic DNS/tunneling abuse, IP threat classifications, and external OSINT feeds.
    """

    # Dynamic DNS and tunneling providers frequently abused in phishing staging
    DYNAMIC_DNS_DOMAINS = {
        "duckdns.org", "no-ip.com", "ddns.net", "hopto.org", "zapto.org",
        "ngrok.io", "ngrok-free.app", "localtunnel.me", "serveo.net",
        "firebaseapp.com", "web.app", "glitch.me", "workers.dev", "pages.dev"
    }

    # Known suspicious nameserver or host patterns
    HIGH_RISK_HOST_KEYWORDS = [
        "freecluster", "000webhost", "infinityfree", "epizy", "byethost"
    ]

    def __init__(self, weight: float = 1.25):
        super().__init__(name="Threat Intelligence & DNS Verifier", weight=weight)
        self.virustotal_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

    def analyze(self, data: Dict[str, Any]) -> AgentResult:
        """
        Analyze target domains extracted from URL or sender email headers.
        """
        domains_to_check = self._extract_target_domains(data)

        if not domains_to_check:
            return AgentResult(
                agent_name=self.name,
                score=0.0,
                verdict="SAFE",
                confidence=0.5,
                flags=["No target domains available for DNS & threat intelligence check"],
                details={"domains_checked": []},
                summary="No external domains found to query against threat intelligence."
            )

        worst_score = 0.0
        all_flags = []
        details_list = []

        is_email_context = bool(data.get("headers") or data.get("subject") or data.get("raw_email"))

        for domain in domains_to_check:
            d_score, d_flags, d_details = self._inspect_domain(domain, is_email_context=is_email_context)
            details_list.append(d_details)
            all_flags.extend(d_flags)
            if d_score > worst_score:
                worst_score = d_score

        # Check for optional external VirusTotal lookup if URL is present and key is set
        url = data.get("url")
        if url and self.virustotal_key:
            vt_score, vt_flags = self._query_virustotal_url(url)
            if vt_flags:
                all_flags.extend(vt_flags)
                worst_score = max(worst_score, vt_score)

        unique_flags = list(dict.fromkeys(all_flags))
        final_score = min(max(worst_score, 0.0), 100.0)
        verdict = self.score_to_verdict(final_score)

        summary = (
            f"Threat intelligence inspected {len(domains_to_check)} domain(s). "
            f"Risk score: {final_score:.1f}/100 ({verdict}). "
            f"Identified {len(unique_flags)} infrastructure/reputation indicator(s)."
        )

        return AgentResult(
            agent_name=self.name,
            score=round(final_score, 1),
            verdict=verdict,
            confidence=0.90,
            flags=unique_flags,
            details={
                "domains_inspected": details_list,
                "virustotal_queried": bool(self.virustotal_key and url)
            },
            summary=summary
        )

    def _inspect_domain(self, domain: str, is_email_context: bool = False) -> Tuple[float, List[str], Dict[str, Any]]:
        score = 0.0
        flags = []
        diagnostics = {
            "domain": domain,
            "has_mx": None,
            "has_a": None,
            "ip_addresses": [],
            "is_dynamic_dns": False,
            "is_private_ip": False
        }

        # 1. Dynamic DNS and Fast-Flux Tunneling Detection
        for ddns in self.DYNAMIC_DNS_DOMAINS:
            if domain == ddns or domain.endswith("." + ddns):
                score += 45.0
                flags.append(f"Domain uses dynamic DNS / tunneling service ({ddns}), frequently abused to evade domain registration scrutiny")
                diagnostics["is_dynamic_dns"] = True
                break

        # 2. Free / Disposable Hosting Provider patterns
        for keyword in self.HIGH_RISK_HOST_KEYWORDS:
            if keyword in domain:
                score += 35.0
                flags.append(f"Domain hosted on disposable/free shared tier ({keyword}), high frequency of malicious phishing campaigns")
                break

        # 3. Raw IP check & SSRF / Internal Network Detection
        ip_obj = self._parse_ip(domain)
        if ip_obj:
            diagnostics["is_ip"] = True
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
                score += 85.0
                flags.append(f"CRITICAL: Host resolves to internal/private IP address ({domain}). Potential Server-Side Request Forgery (SSRF) trap")
                diagnostics["is_private_ip"] = True
            else:
                score += 35.0
                flags.append(f"Host uses unmapped public IP address ({domain}) without registered DNS domain name")
            return score, flags, diagnostics

        # 4. Live DNS Resolution (A and MX records)
        if DNS_AVAILABLE:
            a_records, nxdomain = self._resolve_dns(domain, "A")
            diagnostics["ip_addresses"] = a_records
            diagnostics["has_a"] = len(a_records) > 0

            if nxdomain:
                score += 50.0
                flags.append(f"DNS Resolution Failed: Domain '{domain}' does not exist (NXDOMAIN) or is unregistered")
            elif a_records:
                for ip_str in a_records:
                    ip = self._parse_ip(ip_str)
                    if ip and (ip.is_private or ip.is_loopback):
                        score += 80.0
                        flags.append(f"DNS points domain to internal/private IP ({ip_str}), potential SSRF vector")
                        diagnostics["is_private_ip"] = True

            # In email context: check if sending domain has valid MX (Mail Exchanger) records
            if is_email_context and not nxdomain:
                mx_records, _ = self._resolve_dns(domain, "MX")
                diagnostics["has_mx"] = len(mx_records) > 0
                diagnostics["mx_records"] = mx_records
                if not mx_records:
                    score += 40.0
                    flags.append(f"Missing MX Records: Sender domain '{domain}' cannot receive mail, characteristic of one-way spoofing domains")

        return score, flags, diagnostics

    def _extract_target_domains(self, data: Dict[str, Any]) -> List[str]:
        """Extract all candidate hostnames/domains from inputs."""
        domains = set()

        # From URL
        url = data.get("url")
        if url:
            target = url if ("://" in url) else f"http://{url}"
            parsed = urlparse(target)
            if parsed.hostname:
                domains.add(parsed.hostname.lower())

        # From email headers
        headers = data.get("headers", {})
        if isinstance(headers, dict):
            sender = headers.get("From") or headers.get("from") or ""
            if "@" in sender:
                match = re.search(r"@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", sender)
                if match:
                    domains.add(match.group(1).lower())

        # From body links
        body = data.get("body", "")
        if body:
            matches = re.findall(r"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", body)
            for m in matches[:3]:  # Top 3 links in body
                domains.add(m.lower())

        return list(domains)

    def _resolve_dns(self, domain: str, rtype: str) -> Tuple[List[str], bool]:
        """Safely resolve DNS records with low timeout."""
        if not DNS_AVAILABLE:
            return [], False

        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.0

        try:
            answers = resolver.resolve(domain, rtype)
            results = [str(r.to_text()).strip() for r in answers]
            return results, False
        except dns.resolver.NXDOMAIN:
            return [], True
        except (dns.resolver.NoAnswer, dns.resolver.Timeout, Exception):
            return [], False

    def _parse_ip(self, s: str) -> Optional[ipaddress.IPv4Address]:
        try:
            return ipaddress.IPv4Address(s)
        except ValueError:
            return None

    def _query_virustotal_url(self, url: str) -> Tuple[float, List[str]]:
        """Optional query to VirusTotal API if API key is present."""
        import base64
        import requests
        try:
            # VT URL identifier is base64 without padding
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            headers = {"x-apikey": self.virustotal_key}
            res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=3.0)
            if res.status_code == 200:
                stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                if malicious > 0:
                    score = min(malicious * 25.0 + 40.0, 100.0)
                    return score, [f"VirusTotal Threat Feed: Flagged malicious by {malicious} antivirus vendor(s)"]
                elif suspicious > 0:
                    return 35.0, [f"VirusTotal Threat Feed: Flagged suspicious by {suspicious} vendor(s)"]
        except Exception:
            pass
        return 0.0, []
