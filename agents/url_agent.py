"""
URL Analyzer Agent
Specialized agent for inspecting URLs, domains, structural anomalies, typosquatting, and obfuscation.
"""

import math
import re
from urllib.parse import urlparse, unquote
from typing import Dict, Any, List, Tuple
from .base_agent import BaseAgent, AgentResult


class UrlAgent(BaseAgent):
    """Inspects target URLs for phishing indicators, deceptive patterns, and structural anomalies."""

    SUSPICIOUS_TLDS = {
        "xyz", "top", "work", "click", "loan", "fit", "gq", "cf", "tk", "ml", 
        "cam", "zip", "mov", "buzz", "rest", "support", "country", "kim", "science"
    }

    TARGET_BRANDS = [
        "paypal", "microsoft", "google", "apple", "amazon", "chase", "wellsfargo",
        "bankofamerica", "netflix", "facebook", "instagram", "linkedin", "binance",
        "coinbase", "dropbox", "dhl", "fedex", "ups", "usps", "steam", "citibank"
    ]

    SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
        "rebrand.ly", "cutt.ly", "tiny.cc", "goo.gl", "rotf.lol"
    }

    SUSPICIOUS_KEYWORDS = [
        "login", "signin", "verify", "verification", "secure", "account", "update",
        "banking", "security", "wallet", "password", "credential", "confirm",
        "billing", "invoice", "auth", "recover", "authenticate", "suspended"
    ]

    def __init__(self, weight: float = 1.2):
        super().__init__(name="URL Security Inspector", weight=weight)

    def analyze(self, data: Dict[str, Any]) -> AgentResult:
        """
        Analyze either a direct URL or URLs embedded within content.
        """
        raw_url = data.get("url")
        urls_to_scan = []

        if raw_url:
            urls_to_scan.append(raw_url.strip())
        
        # If body is provided, also extract embedded links
        body = data.get("body", "")
        if body:
            extracted = self._extract_urls(body)
            for u in extracted:
                if u not in urls_to_scan:
                    urls_to_scan.append(u)

        if not urls_to_scan:
            return AgentResult(
                agent_name=self.name,
                score=0.0,
                verdict="SAFE",
                confidence=0.5,
                flags=["No URLs identified for inspection"],
                details={"scanned_urls": [], "url_count": 0},
                summary="No URLs found in the provided payload."
            )

        worst_score = 0.0
        all_flags = []
        details_list = []

        for u in urls_to_scan:
            u_score, u_flags, u_details = self._inspect_single_url(u)
            details_list.append(u_details)
            all_flags.extend(u_flags)
            if u_score > worst_score:
                worst_score = u_score

        # Deduplicate flags while preserving order
        unique_flags = list(dict.fromkeys(all_flags))
        verdict = self.score_to_verdict(worst_score)

        summary = (
            f"Analyzed {len(urls_to_scan)} URL(s). "
            f"Maximum risk score: {worst_score:.1f}/100 ({verdict}). "
            f"Identified {len(unique_flags)} potential threat indicator(s)."
        )

        return AgentResult(
            agent_name=self.name,
            score=round(worst_score, 1),
            verdict=verdict,
            confidence=0.92,
            flags=unique_flags,
            details={
                "url_count": len(urls_to_scan),
                "inspections": details_list
            },
            summary=summary
        )

    def _inspect_single_url(self, url: str) -> Tuple[float, List[str], Dict[str, Any]]:
        score = 0.0
        flags = []
        diagnostics = {"url": url}

        # Normalize schema if missing for parsing
        parse_target = url if ("://" in url) else f"http://{url}"
        parsed = urlparse(parse_target)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path.lower()
        query = parsed.query.lower()

        diagnostics["hostname"] = hostname
        diagnostics["path"] = path

        # 1. IP address in Hostname
        ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if re.match(ip_pattern, hostname):
            score += 45.0
            flags.append(f"Host is a raw numerical IP address ({hostname}) rather than a registered domain")

        # 2. '@' Symbol in URL (credential trap / browser redirect spoofing)
        if "@" in url:
            score += 35.0
            flags.append("URL contains '@' symbol, which can mask the true destination authority")

        # 3. URL Shortener detection
        if hostname in self.SHORTENERS:
            score += 25.0
            flags.append(f"URL uses known shortening service ({hostname}) to disguise final destination")

        # 4. Punycode / IDN Homograph check
        if "xn--" in hostname:
            score += 40.0
            flags.append(f"Punycode (IDN) detected ({hostname}), often used for visual spoofing")

        # 5. Non-ASCII characters in host
        non_ascii = [c for c in hostname if ord(c) > 127]
        if non_ascii:
            score += 40.0
            flags.append(f"Domain contains non-ASCII internationalized characters ({''.join(set(non_ascii))})")

        # 6. High-risk / suspicious TLD
        tld = hostname.split(".")[-1] if "." in hostname else ""
        if tld in self.SUSPICIOUS_TLDS:
            score += 30.0
            flags.append(f"Uses high-abuse top-level domain: .{tld}")

        # 7. Subdomain depth / excessive dot count
        dot_count = hostname.count(".")
        if dot_count >= 4:
            score += 25.0
            flags.append(f"Excessive subdomain nesting ({dot_count} dots in host)")

        # 8. Shannon entropy of host
        entropy = self._shannon_entropy(hostname.replace(".", ""))
        diagnostics["hostname_entropy"] = round(entropy, 2)
        if entropy > 4.2 and len(hostname) > 15:
            score += 20.0
            flags.append(f"High hostname lexical entropy ({entropy:.2f}), suggests randomized DGA or obfuscated name")

        # 9. Brand Impersonation / Typosquatting
        brand_match = self._check_brand_impersonation(hostname, path)
        if brand_match:
            score += 45.0
            flags.append(brand_match)

        # 10. Phishing keywords in path or query
        detected_keywords = [kw for kw in self.SUSPICIOUS_KEYWORDS if kw in path or kw in query]
        if detected_keywords:
            score += min(len(detected_keywords) * 10.0, 30.0)
            flags.append(f"Suspicious credential/security keywords detected: {', '.join(detected_keywords[:4])}")

        # 11. Abnormal length
        if len(url) > 120:
            score += 15.0
            flags.append(f"Abnormally long URL ({len(url)} characters)")
        elif len(url) > 75:
            score += 8.0

        # 12. Non-standard port
        if parsed.port and parsed.port not in (80, 443):
            score += 20.0
            flags.append(f"URL specifies uncommon web port ({parsed.port})")

        # 13. Open redirect patterns
        if any(token in query for token in ["url=", "redirect=", "next=", "dest=", "target="]):
            score += 20.0
            flags.append("Contains open redirection query parameters")

        # Cap score at 100.0
        final_score = min(max(score, 0.0), 100.0)
        diagnostics["risk_score"] = round(final_score, 1)
        diagnostics["flags"] = flags

        return final_score, flags, diagnostics

    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs from plain text or HTML."""
        pattern = r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\-.~:?#[\]@!$&'()*+,;=]*"
        matches = re.findall(pattern, text)
        return list(dict.fromkeys(matches))

    def _shannon_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in prob)

    def _check_brand_impersonation(self, hostname: str, path: str) -> str:
        """Detect brand spoofing in subdomains, path, or typosquatting."""
        domain_parts = hostname.split(".")
        tld = domain_parts[-1] if domain_parts else ""
        main_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else hostname

        # Extract all subparts and hyphenated tokens (e.g. paypa1-update -> [paypa1, update])
        tokens = set()
        for dp in domain_parts[:-1]:  # exclude tld
            tokens.add(dp)
            for part in re.split(r"[-_]", dp):
                if part:
                    tokens.add(part)

        for brand in self.TARGET_BRANDS:
            # Check if brand appears in hostname when it's not the official root domain
            if brand in hostname and main_domain != f"{brand}.{tld}":
                return f"Deceptive brand mimicry: '{brand}' targeted in host '{hostname}'"
            
            # Check token level for exact brand usage in non-brand domain
            for token in tokens:
                if token == brand and main_domain != f"{brand}.{tld}":
                    return f"Brand impersonation: '{brand}' utilized in deceptive domain '{hostname}'"

                # Check typosquatting edit distance (e.g., paypa1 vs paypal)
                dist = self._levenshtein_distance(token, brand)
                if 1 <= dist <= 2 and len(brand) >= 4 and abs(len(token) - len(brand)) <= 2:
                    return f"Potential typosquatting of brand '{brand}': host contains deceptive variant '{token}'"

        return ""

    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """Compute edit distance between two strings."""
        if len(s1) < len(s2):
            return UrlAgent._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]
