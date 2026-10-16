"""
Content Analyzer Agent
Specialized agent for analyzing email body text, social engineering tactics,
urgency cues, credential requests, and anchor text mismatches.
"""

import re
from typing import Dict, Any, List, Tuple
from bs4 import BeautifulSoup
from .base_agent import BaseAgent, AgentResult


class ContentAgent(BaseAgent):
    """Inspects text and HTML content for psychological manipulation and social engineering signals."""

    URGENCY_PATTERNS = [
        r"\b(?:urgent(?:ly)?|immediate(?:ly)?|action required|promptly)\b",
        r"\b(?:within (?:24|48|12) hours|today only|limited time|deadline)\b",
        r"\b(?:account (?:suspended|terminated|disabled|locked|restricted))\b",
        r"\b(?:fail(?:ure)? to (?:respond|verify|update)|will be closed)\b",
    ]

    CREDENTIAL_PATTERNS = [
        r"\b(?:verify|confirm|validate|update) your (?:account|identity|password|pin|credentials)\b",
        r"\b(?:enter|provide|submit) your (?:password|login|social security|ssn|credit card|cvv)\b",
        r"\b(?:click here to (?:verify|unlock|log\s?in|sign\s?in|restore))\b",
        r"\b(?:security (?:alert|notice|update|upgrade)|suspicious activity detected)\b",
    ]

    FINANCIAL_PATTERNS = [
        r"\b(?:unclaimed (?:funds|lottery|prize|money|reward)|inheritance)\b",
        r"\b(?:crypto|bitcoin|eth|usdt) (?:giveaway|airdrop|wallet (?:connected|phrase))\b",
        r"\b(?:tax refund|direct deposit|wire transfer|overdue invoice)\b",
        r"\b(?:payment (?:failed|declined|pending)|billing problem)\b",
    ]

    GENERIC_GREETINGS = [
        r"\b(?:dear (?:customer|user|client|member|account holder|friend|subscriber|valued member))\b",
        r"\b(?:dear sir(?:/|\s)madam|hello customer)\b",
    ]

    DANGEROUS_EXTENSIONS = [
        ".exe", ".scr", ".vbs", ".hta", ".cmd", ".bat", ".pif", ".iso", ".docm", ".xlsm", ".jar"
    ]

    def __init__(self, weight: float = 1.1):
        super().__init__(name="Content & Social Engineering Agent", weight=weight)

    def analyze(self, data: Dict[str, Any]) -> AgentResult:
        body = data.get("body", "")
        subject = data.get("subject", "")
        combined_text = f"{subject}\n{body}".strip()

        if not combined_text:
            return AgentResult(
                agent_name=self.name,
                score=0.0,
                verdict="SAFE",
                confidence=0.5,
                flags=["No content or body provided for analysis"],
                details={},
                summary="No body text provided to analyze."
            )

        score = 0.0
        flags = []
        details: Dict[str, Any] = {}

        # 1. HTML Parsing & Anchor Text Mismatch
        html_flags, mismatch_count = self._analyze_html_links(body)
        flags.extend(html_flags)
        if mismatch_count > 0:
            score += min(mismatch_count * 35.0, 70.0)
            details["link_mismatches"] = mismatch_count

        # 2. Urgency and Fear Heuristics
        urgency_matches = self._match_patterns(combined_text, self.URGENCY_PATTERNS)
        details["urgency_triggers"] = urgency_matches
        if urgency_matches:
            score += min(len(urgency_matches) * 15.0, 35.0)
            flags.append(f"High urgency / psychological pressure detected ({len(urgency_matches)} indicators)")

        # 3. Credential Harvesting & Account Interception
        cred_matches = self._match_patterns(combined_text, self.CREDENTIAL_PATTERNS)
        details["credential_triggers"] = cred_matches
        if cred_matches:
            score += min(len(cred_matches) * 20.0, 45.0)
            flags.append(f"Credential harvesting or account verification prompts detected ({len(cred_matches)} cues)")

        # 4. Financial & Reward Lures
        fin_matches = self._match_patterns(combined_text, self.FINANCIAL_PATTERNS)
        details["financial_triggers"] = fin_matches
        if fin_matches:
            score += min(len(fin_matches) * 15.0, 30.0)
            flags.append(f"Financial lure / fake incentive phrases detected ({len(fin_matches)} cues)")

        # 5. Impersonal Generic Salutations
        greeting_matches = self._match_patterns(combined_text, self.GENERIC_GREETINGS)
        details["generic_greetings"] = greeting_matches
        if greeting_matches:
            score += 15.0
            flags.append("Impersonal generic greeting used instead of personalized recipient name")

        # 6. Dangerous Attachment References
        for ext in self.DANGEROUS_EXTENSIONS:
            if ext in combined_text.lower():
                score += 25.0
                flags.append(f"Reference to potentially executable or macro-enabled file extension '{ext}'")
                break

        # 7. Stylistic Anomalies: Excessive Caps and Punctuation
        words = combined_text.split()
        if len(words) > 10:
            caps_words = [w for w in words if w.isupper() and len(w) > 2]
            caps_ratio = len(caps_words) / len(words)
            details["caps_ratio"] = round(caps_ratio, 3)
            if caps_ratio > 0.25:
                score += 15.0
                flags.append(f"Aggressive capitalization ({round(caps_ratio * 100)}% capitalized words)")

        if combined_text.count("!") >= 4:
            score += 10.0
            flags.append("Excessive exclamation marks conveying artificial urgency")

        # Cap score at 100.0
        final_score = min(max(score, 0.0), 100.0)
        verdict = self.score_to_verdict(final_score)

        summary = (
            f"Content analysis returned threat score {final_score:.1f}/100 ({verdict}). "
            f"Flagged {len(flags)} social engineering cue(s)."
        )

        return AgentResult(
            agent_name=self.name,
            score=round(final_score, 1),
            verdict=verdict,
            confidence=0.88,
            flags=flags,
            details=details,
            summary=summary
        )

    def _analyze_html_links(self, html_content: str) -> Tuple[List[str], int]:
        """Detect hyperlink spoofing where anchor text looks like a domain but href points elsewhere."""
        flags = []
        mismatch_count = 0

        try:
            soup = BeautifulSoup(html_content, "html.parser")
            anchors = soup.find_all("a", href=True)

            for a in anchors:
                href = a["href"].strip().lower()
                text = a.get_text(strip=True).lower()

                # If the displayed text looks like an official URL (e.g. paypal.com or http://...)
                if ("http://" in text or "https://" in text or ".com" in text or ".org" in text):
                    # Clean displayed domain
                    clean_text = text.replace("http://", "").replace("https://", "").split("/")[0]
                    # Check if href destination domain differs significantly
                    if href.startswith("http") and clean_text not in href:
                        mismatch_count += 1
                        flags.append(
                            f"Deceptive link mismatch: Visible text displays '{text}' but destination is '{href}'"
                        )
        except Exception:
            pass

        return flags, mismatch_count

    def _match_patterns(self, text: str, patterns: List[str]) -> List[str]:
        found = []
        for p in patterns:
            matches = re.findall(p, text, re.IGNORECASE)
            if matches:
                found.extend(matches)
        return list(dict.fromkeys(found))
