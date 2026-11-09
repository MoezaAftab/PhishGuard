"""
LLM Security Analyst Agent
Uses GPT-OSS 20B through Groq to synthesize findings from PhishGuard's
specialized security agents and generate an explainable security assessment.
"""

import json
import os
from typing import Dict, Any

from dotenv import load_dotenv
from groq import Groq


load_dotenv()


class LLMSecurityAnalyst:
    """
    LLM-powered security analyst.

    This component does not replace the deterministic security agents.
    It interprets and synthesizes their findings into a human-readable
    security assessment.
    """

    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY", "").strip()
        self.model = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")

        self.client = None

        if self.api_key:
            self.client = Groq(api_key=self.api_key)

    def analyze(
        self,
        agent_results: Dict[str, Any],
        overall_score: float,
        overall_verdict: str,
        indicators: list
    ) -> Dict[str, Any]:
        """
        Analyze the findings produced by the specialized agents.

        Returns a structured dictionary containing the LLM's assessment.
        """

        if not self.client:
            return {
                "enabled": False,
                "status": "unavailable",
                "message": "GROQ_API_KEY is not configured."
            }

        evidence = self._prepare_evidence(
            agent_results,
            overall_score,
            overall_verdict,
            indicators
        )

        system_prompt = """
You are the AI Security Analyst for PhishGuard, a multi-agent phishing
detection platform.

Your job is to analyze evidence produced by specialized cybersecurity
agents and synthesize their findings.

IMPORTANT RULES:

1. Treat the specialized agent findings as evidence.
2. Do not invent security findings that are not present in the evidence.
3. Do not replace or change the deterministic overall score.
4. Explain why the message or URL received its risk classification.
5. Identify the strongest phishing indicators.
6. Mention conflicting evidence when agents disagree.
7. Give practical defensive recommendations.
8. Be concise and professional.
9. This is a defensive cybersecurity system.
10. Do not claim that an attack is confirmed unless the evidence supports
    that conclusion.

Return your answer as valid JSON with exactly these fields:

{
    "risk_assessment": "short assessment",
    "confidence": 0.0,
    "summary": "human-readable explanation",
    "key_findings": [
        "finding 1",
        "finding 2"
    ],
    "recommended_actions": [
        "action 1",
        "action 2"
    ]
}

The confidence value must be between 0.0 and 1.0.
"""

        user_prompt = f"""
Analyze this PhishGuard scan.

DETERMINISTIC OVERALL SCORE:
{overall_score}/100

DETERMINISTIC OVERALL VERDICT:
{overall_verdict}

INDICATORS:
{json.dumps(indicators, indent=2)}

SPECIALIZED AGENT EVIDENCE:
{json.dumps(evidence, indent=2)}
"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": system_prompt
                    },
                    {
                        "role": "user",
                        "content": user_prompt
                    }
                ],
                temperature=0.2,
                max_tokens=700
            )

            content = response.choices[0].message.content

            if not content:
                return {
                    "enabled": True,
                    "status": "error",
                    "message": "LLM returned an empty response."
                }

            parsed = self._parse_json_response(content)

            return {
                "enabled": True,
                "status": "success",
                "model": self.model,
                "analysis": parsed
            }

        except Exception as exc:
            return {
                "enabled": True,
                "status": "error",
                "message": f"LLM analysis failed: {str(exc)}"
            }

    def _prepare_evidence(
        self,
        agent_results: Dict[str, Any],
        overall_score: float,
        overall_verdict: str,
        indicators: list
    ) -> Dict[str, Any]:
        """
        Prepare a controlled evidence package for the LLM.

        We intentionally send only the useful structured findings instead
        of the original email/body contents.
        """

        evidence = {}

        for agent_name, result in agent_results.items():
            if hasattr(result, "to_dict"):
                result = result.to_dict()

            evidence[agent_name] = {
                "agent_name": result.get("agent_name"),
                "score": result.get("score"),
                "verdict": result.get("verdict"),
                "confidence": result.get("confidence"),
                "flags": result.get("flags", []),
                "details": result.get("details", {}),
                "summary": result.get("summary", "")
            }

        return evidence

    def _parse_json_response(self, content: str) -> Dict[str, Any]:
        """
        Safely parse JSON returned by the LLM.

        Handles responses where the model surrounds JSON with
        markdown code fences.
        """

        cleaned = content.strip()

        if cleaned.startswith("```"):
            cleaned = cleaned.replace("```json", "", 1)
            cleaned = cleaned.replace("```", "", 1)
            cleaned = cleaned.strip()

        try:
            return json.loads(cleaned)

        except json.JSONDecodeError:
            return {
                "risk_assessment": "LLM returned a non-structured response.",
                "confidence": 0.0,
                "summary": cleaned,
                "key_findings": [],
                "recommended_actions": []
            }