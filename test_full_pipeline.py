from agents.orchestrator import PhishGuardOrchestrator

orchestrator = PhishGuardOrchestrator()

payload = {
    "url": "http://paypa1-login.xyz/verify",
    "subject": "Urgent: Verify your account",
    "body": (
        "Dear customer, your account has been suspended. "
        "Click here to verify your password immediately."
    ),
    "headers": {
        "From": "security@paypa1-login.xyz",
        "Reply-To": "attacker@paypa1-login.xyz",
        "Return-Path": "attacker@paypa1-login.xyz",
        "Received": "from suspicious-server.example"
    }
}

result = orchestrator.scan(payload)

print("\n========== PHISHGUARD RESULT ==========\n")

print("Overall Score:", result["overall_score"])
print("Verdict:", result["verdict"])

print("\n--- Agents Executed ---")
print(result["agents_executed_count"])

print("\n--- Indicators ---")
for indicator in result["indicators"]:
    print("-", indicator)

print("\n--- LLM Analysis ---")
print(result["llm_analysis"])