"""
PhishGuard Multi-Agent Orchestrator
Coordinates 5 specialized autonomous security agents, synthesizes findings, resolves conflicts,
computes ensemble threat scores, and generates actionable user advisories.
"""

import email
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from .base_agent import AgentResult, BaseAgent
from .url_agent import UrlAgent
from .content_agent import ContentAgent
from .header_agent import HeaderAgent
from .threat_intel_agent import ThreatIntelAgent
from .ml_agent import MLAgent


class PhishGuardOrchestrator:
    """Supervisory orchestrator coordinating the 5-agent detection pipeline."""

    def __init__(self):
        self.url_agent = UrlAgent(weight=1.2)
        self.content_agent = ContentAgent(weight=1.1)
        self.header_agent = HeaderAgent(weight=1.3)
        self.threat_intel_agent = ThreatIntelAgent(weight=1.25)
        self.ml_agent = MLAgent(weight=1.0)
        self.agents: List[BaseAgent] = [
            self.url_agent,
            self.content_agent,
            self.header_agent,
            self.threat_intel_agent,
            self.ml_agent,
        ]

    def scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute full multi-agent scan across target payload using all 5 agents.
        
        Args:
            payload: Dict with any combination of 'url', 'body', 'subject', 'headers', 'raw_email'
            
        Returns:
            Dict containing comprehensive evaluation, agent reports, indicators, and mitigation advice.
        """
        scan_id = str(uuid.uuid4())[:8]
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

        # 1. Parse raw email if provided
        processed_data = self._preprocess_payload(payload)

        # 2. Execute each agent
        agent_results: Dict[str, AgentResult] = {}
        active_weights: Dict[str, float] = {}
        all_flags: List[str] = []

        # Determine which context vectors are active
        has_url = bool(processed_data.get("url") or ("http" in processed_data.get("body", "")))
        has_content = bool(processed_data.get("body") or processed_data.get("subject"))
        has_headers = bool(processed_data.get("headers"))

        # Agent 1: URL Security Inspector
        if has_url:
            res = self.url_agent.analyze(processed_data)
            agent_results["url_agent"] = res
            active_weights["url_agent"] = self.url_agent.weight
            all_flags.extend(res.flags)

        # Agent 2: Social Engineering & Content Agent
        if has_content:
            res = self.content_agent.analyze(processed_data)
            agent_results["content_agent"] = res
            active_weights["content_agent"] = self.content_agent.weight
            all_flags.extend(res.flags)

        # Agent 3: Header & Authentication Verifier
        if has_headers:
            res = self.header_agent.analyze(processed_data)
            agent_results["header_agent"] = res
            active_weights["header_agent"] = self.header_agent.weight
            all_flags.extend(res.flags)

        # Agent 4: Threat Intelligence & DNS Infrastructure Agent
        # Runs whenever there is a URL, email domain, or network target
        if has_url or has_headers or processed_data.get("domain"):
            ti_res = self.threat_intel_agent.analyze(processed_data)
            agent_results["threat_intel_agent"] = ti_res
            active_weights["threat_intel_agent"] = self.threat_intel_agent.weight
            all_flags.extend(ti_res.flags)

        # Agent 5: ML Heuristic & Explainable Classifier (always evaluates cross-modal context)
        ml_res = self.ml_agent.analyze(processed_data)
        agent_results["ml_agent"] = ml_res
        active_weights["ml_agent"] = self.ml_agent.weight
        all_flags.extend(ml_res.flags)

        # 3. Calculate ensemble weighted score
        total_weight = sum(active_weights.values()) or 1.0
        weighted_sum = sum(agent_results[k].score * active_weights[k] for k in agent_results)
        raw_ensemble_score = weighted_sum / total_weight

        # Critical threat escalation rule:
        # If any specialized agent finds a critical smoking gun (>85), ensure ensemble doesn't dilute below high risk
        max_agent_score = max((r.score for r in agent_results.values()), default=0.0)
        if max_agent_score >= 85.0 and raw_ensemble_score < 75.0:
            raw_ensemble_score = max_agent_score * 0.90
        elif max_agent_score >= 70.0 and raw_ensemble_score < 60.0:
            raw_ensemble_score = max_agent_score * 0.85

        final_score = round(min(max(raw_ensemble_score, 0.0), 100.0), 1)
        overall_verdict = BaseAgent.score_to_verdict(final_score)

        # Deduplicate indicators
        clean_indicators = list(dict.fromkeys(all_flags))

        # 4. Generate recommendations
        recommendations = self._generate_recommendations(overall_verdict, clean_indicators, processed_data)

        # 5. Format output
        report = {
            "scan_id": scan_id,
            "timestamp": timestamp,
            "overall_score": final_score,
            "verdict": overall_verdict,
            "verdict_badge_class": self._verdict_to_badge_class(overall_verdict),
            "threat_summary": self._generate_executive_summary(overall_verdict, final_score, clean_indicators),
            "agents_executed_count": len(agent_results),
            "agent_results": {k: v.to_dict() for k, v in agent_results.items()},
            "indicators": clean_indicators,
            "recommendations": recommendations,
            "input_preview": {
                "url": processed_data.get("url", ""),
                "subject": processed_data.get("subject", ""),
                "sender": processed_data.get("headers", {}).get("from", "") if isinstance(processed_data.get("headers"), dict) else "",
                "body_snippet": (processed_data.get("body", "")[:150] + "...") if len(processed_data.get("body", "")) > 150 else processed_data.get("body", "")
            }
        }

        return report

    def _preprocess_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Parse raw RFC822 email format if supplied."""
        data = dict(payload)
        raw_email = data.get("raw_email")

        if raw_email and isinstance(raw_email, str):
            try:
                msg = email.message_from_string(raw_email)
                data["subject"] = msg.get("Subject", data.get("subject", ""))
                
                # Extract headers
                headers = {}
                for k in ["From", "To", "Subject", "Date", "Reply-To", "Return-Path", "Authentication-Results", "Received-SPF", "Message-ID"]:
                    val = msg.get(k)
                    if val:
                        headers[k] = val
                data["headers"] = headers

                # Extract body
                body_parts = []
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        content_disposition = str(part.get("Content-Disposition", ""))
                        if "attachment" not in content_disposition and content_type in ["text/plain", "text/html"]:
                            try:
                                payload_bytes = part.get_payload(decode=True)
                                if payload_bytes:
                                    body_parts.append(payload_bytes.decode(errors="replace"))
                            except Exception:
                                pass
                else:
                    try:
                        payload_bytes = msg.get_payload(decode=True)
                        if payload_bytes:
                            body_parts.append(payload_bytes.decode(errors="replace"))
                        else:
                            body_parts.append(msg.get_payload() or "")
                    except Exception:
                        body_parts.append(msg.get_payload() or "")

                if body_parts:
                    data["body"] = "\n".join(body_parts)
            except Exception:
                pass

        return data

    def _verdict_to_badge_class(self, verdict: str) -> str:
        mapping = {
            "SAFE": "badge-safe",
            "LOW_RISK": "badge-low",
            "SUSPICIOUS": "badge-suspicious",
            "HIGH_RISK": "badge-high",
            "CRITICAL": "badge-critical",
        }
        return mapping.get(verdict, "badge-secondary")

    def _generate_executive_summary(self, verdict: str, score: float, indicators: List[str]) -> str:
        if verdict == "SAFE":
            return "No suspicious or malicious phishing patterns were identified. Payload appears legitimate."
        elif verdict == "LOW_RISK":
            return f"Low risk level ({score}/100). Minor anomalies noted, but no definitive malicious traits."
        elif verdict == "SUSPICIOUS":
            return f"Suspicious activity observed ({score}/100). Contains {len(indicators)} risk factor(s) that resemble phishing behavior."
        elif verdict == "HIGH_RISK":
            return f"High risk phishing threat ({score}/100). Significant social engineering, domain spoofing, or infrastructure anomalies detected."
        else:
            return f"CRITICAL PHISHING ATTACK DETECTED ({score}/100). Severe credential harvesting, domain spoofing, authentication failure, or malicious infrastructure present."

    def _generate_recommendations(self, verdict: str, indicators: List[str], data: Dict[str, Any]) -> List[str]:
        recs = []
        if verdict in ["CRITICAL", "HIGH_RISK"]:
            recs.append("DO NOT click any links, open attachments, or reply to this communication.")
            recs.append("Do NOT submit any passwords, MFA codes, or financial credentials.")
            recs.append("Report and quarantine this message in your organization's email security gateway.")
            if data.get("url"):
                recs.append("Add the target domain/IP to network firewall, EDR, and DNS blocklists.")
        elif verdict == "SUSPICIOUS":
            recs.append("Exercise heightened caution. Verify the sender through an independent, verified out-of-band channel.")
            recs.append("Check link destinations by inspecting full URLs without clicking.")
            recs.append("Avoid entering sensitive information if prompted by this source.")
        else:
            recs.append("No immediate threats found. Maintain standard operational cybersecurity awareness.")
        return recs
