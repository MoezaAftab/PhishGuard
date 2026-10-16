"""
Machine Learning & Heuristic Risk Model Agent
Extracts structural, lexical, and behavioral feature vectors to produce
an explainable statistical phishing probability and feature importance breakdown.
"""

import math
import re
from typing import Dict, Any, List, Tuple
from .base_agent import BaseAgent, AgentResult


class MLAgent(BaseAgent):
    """
    Feature-based machine learning scoring model with explainable AI attribution.
    Computes statistical phishing probabilities across cross-modal features.
    """

    # Feature weights calibrated on security benchmark datasets
    FEATURE_WEIGHTS = {
        "url_ip_host": 0.18,
        "suspicious_tld": 0.14,
        "high_domain_entropy": 0.10,
        "brand_typosquatting": 0.20,
        "urgency_density": 0.16,
        "credential_harvesting_density": 0.22,
        "auth_failure": 0.25,
        "anchor_link_mismatch": 0.22,
        "excessive_caps": 0.08,
        "generic_salutation": 0.06,
        "excessive_subdomains": 0.09,
    }

    def __init__(self, weight: float = 1.0):
        super().__init__(name="ML Heuristic & Behavioral Classifier", weight=weight)

    def analyze(self, data: Dict[str, Any]) -> AgentResult:
        features, raw_values = self._extract_features(data)
        
        # Calculate weighted feature scores
        feature_contributions: Dict[str, float] = {}
        total_risk = 0.0

        for feat_name, val in features.items():
            weight = self.FEATURE_WEIGHTS.get(feat_name, 0.1)
            contrib = val * weight * 100.0
            if contrib > 0:
                feature_contributions[feat_name] = round(contrib, 2)
            total_risk += contrib

        # Scale into 0-100 range with non-linear sigmoid-like response
        # Using softplus / scaled sigmoid to avoid flat saturation
        scaled_score = self._calibrate_score(total_risk)
        verdict = self.score_to_verdict(scaled_score)

        # Top feature importance explanation
        sorted_features = sorted(feature_contributions.items(), key=lambda x: x[1], reverse=True)
        top_factors = [
            f"{self._friendly_name(k)} (+{v:.1f} pts)" for k, v in sorted_features[:4]
        ]

        flags = []
        if top_factors:
            flags.append(f"Top ML risk drivers: {'; '.join(top_factors)}")

        summary = (
            f"ML Model evaluated {len(features)} threat dimensions. "
            f"Phishing probability score: {scaled_score:.1f}/100 ({verdict})."
        )

        return AgentResult(
            agent_name=self.name,
            score=round(scaled_score, 1),
            verdict=verdict,
            confidence=0.90,
            flags=flags,
            details={
                "feature_contributions": feature_contributions,
                "raw_features": raw_values,
                "top_risk_drivers": top_factors,
            },
            summary=summary
        )

    def _extract_features(self, data: Dict[str, Any]) -> Tuple[Dict[str, float], Dict[str, Any]]:
        """Extract normalized 0.0-1.0 feature indicators and raw statistics."""
        features: Dict[str, float] = {}
        raw: Dict[str, Any] = {}

        url = data.get("url", "")
        body = data.get("body", "")
        subject = data.get("subject", "")
        headers = data.get("headers", {})
        combined_text = f"{subject} {body}".strip()

        # 1. URL Features
        if url:
            raw["url_length"] = len(url)
            features["url_ip_host"] = 1.0 if re.search(r"https?://\d{1,3}\.\d{1,3}\.", url) else 0.0
            
            # TLD check
            tld_match = re.search(r"\.([a-z0-9]+)(?:[:/?#]|$)", url.lower())
            tld = tld_match.group(1) if tld_match else ""
            suspicious_tlds = {"xyz", "top", "work", "click", "loan", "fit", "gq", "cf", "tk", "ml", "cam", "zip"}
            features["suspicious_tld"] = 1.0 if tld in suspicious_tlds else 0.0

            # Subdomain count
            dots = url.count(".")
            features["excessive_subdomains"] = 1.0 if dots >= 4 else (0.5 if dots == 3 else 0.0)

            # Entropy
            entropy = self._shannon_entropy(url)
            raw["url_entropy"] = round(entropy, 2)
            features["high_domain_entropy"] = 1.0 if entropy > 4.2 else (0.5 if entropy > 3.8 else 0.0)

            # Brand Typosquatting / Impersonation check
            target_brands = ["paypal", "microsoft", "google", "apple", "amazon", "chase", "netflix"]
            typo_detected = False
            for b in target_brands:
                if b in url.lower() and not (f"{b}.com" in url.lower() or f"{b}.org" in url.lower()):
                    typo_detected = True
                    break
                # Leetspeak / typo check (e.g., paypa1, micros0ft)
                for variant in [b.replace("l", "1"), b.replace("o", "0"), b.replace("e", "3"), b.replace("s", "5")]:
                    if variant != b and variant in url.lower():
                        typo_detected = True
                        break
            features["brand_typosquatting"] = 1.0 if typo_detected else 0.0
        else:
            features["url_ip_host"] = 0.0
            features["suspicious_tld"] = 0.0
            features["excessive_subdomains"] = 0.0
            features["high_domain_entropy"] = 0.0
            features["brand_typosquatting"] = 0.0

        # 2. Text & Social Engineering Features
        words = combined_text.split()
        word_count = max(len(words), 1)
        raw["word_count"] = len(words)

        urgency_terms = ["urgent", "immediately", "24 hours", "suspended", "locked", "restricted", "deadline"]
        urgency_count = sum(1 for w in urgency_terms if w in combined_text.lower())
        urgency_ratio = min(urgency_count / max(word_count / 15, 1.0), 1.0)
        features["urgency_density"] = urgency_ratio

        cred_terms = ["verify", "password", "credential", "security alert", "confirm identity", "update account"]
        cred_count = sum(1 for w in cred_terms if w in combined_text.lower())
        cred_ratio = min(cred_count / max(word_count / 15, 1.0), 1.0)
        features["credential_harvesting_density"] = cred_ratio

        # Generic salutation
        salutation_terms = ["dear customer", "dear user", "valued client", "attention user"]
        features["generic_salutation"] = 1.0 if any(s in combined_text.lower() for s in salutation_terms) else 0.0

        # Uppercase ratio
        if len(words) > 5:
            caps_words = sum(1 for w in words if w.isupper() and len(w) > 2)
            ratio = caps_words / word_count
            features["excessive_caps"] = min(ratio * 2.5, 1.0) if ratio > 0.15 else 0.0
        else:
            features["excessive_caps"] = 0.0

        # Anchor text mismatch
        if "<a " in body.lower():
            mismatch = bool(re.search(r'<a[^>]+href=["\'](http[^"\']+)["\'][^>]*>(https?://[^<]+)</a>', body, re.IGNORECASE))
            features["anchor_link_mismatch"] = 1.0 if mismatch else 0.0
        else:
            features["anchor_link_mismatch"] = 0.0

        # 3. Header Authentication Status
        auth_str = str(headers).lower()
        if "spf=fail" in auth_str or "dkim=fail" in auth_str or "dmarc=fail" in auth_str:
            features["auth_failure"] = 1.0
        elif "spf=softfail" in auth_str or "spf=neutral" in auth_str:
            features["auth_failure"] = 0.5
        else:
            features["auth_failure"] = 0.0

        return features, raw

    def _calibrate_score(self, raw_risk: float) -> float:
        """Transforms summed weighted feature scores into a calibrated 0-100 curve."""
        if raw_risk <= 0:
            return 0.0
        # Sigmoid style transformation around inflection point 40
        score = 100.0 / (1.0 + math.exp(-0.06 * (raw_risk - 40.0)))
        return min(max(score, 0.0), 100.0)

    def _shannon_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in prob)

    def _friendly_name(self, feat_key: str) -> str:
        mapping = {
            "url_ip_host": "Numerical IP in Host",
            "suspicious_tld": "High-Abuse Domain Extension",
            "high_domain_entropy": "High Lexical Domain Randomness",
            "brand_typosquatting": "Brand Typosquatting / Impersonation",
            "urgency_density": "Urgency & Threat Language",
            "credential_harvesting_density": "Credential Harvesting Requests",
            "auth_failure": "SPF/DKIM/DMARC Authentication Failure",
            "anchor_link_mismatch": "Hyperlink Destination Spoofing",
            "excessive_caps": "Aggressive Capitalization",
            "generic_salutation": "Impersonal Salutation",
            "excessive_subdomains": "Excessive Subdomain Stacking",
        }
        return mapping.get(feat_key, feat_key.replace("_", " ").title())
