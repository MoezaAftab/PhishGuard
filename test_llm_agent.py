from agents.llm_agent import LLMSecurityAnalyst


analyst = LLMSecurityAnalyst()

mock_results = {
    "url_agent": {
        "agent_name": "URL Security Inspector",
        "score": 85.0,
        "verdict": "CRITICAL",
        "confidence": 0.92,
        "flags": [
            "Suspicious TLD detected",
            "Possible brand impersonation"
        ],
        "details": {
            "url_count": 1
        },
        "summary": "The URL contains multiple suspicious characteristics."
    },
    "content_agent": {
        "agent_name": "Content & Social Engineering Agent",
        "score": 78.0,
        "verdict": "HIGH_RISK",
        "confidence": 0.88,
        "flags": [
            "Urgency language detected",
            "Credential harvesting language detected"
        ],
        "details": {},
        "summary": "The message contains common phishing language."
    }
}


result = analyst.analyze(
    agent_results=mock_results,
    overall_score=82.0,
    overall_verdict="HIGH_RISK",
    indicators=[
        "Suspicious TLD detected",
        "Possible brand impersonation",
        "Urgency language detected",
        "Credential harvesting language detected"
    ]
)


print("\n===== LLM SECURITY ANALYST RESULT =====\n")
print(result)
