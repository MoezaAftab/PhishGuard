# 🛡️ PhishGuard - Multi-Agent Phishing Detection Platform

**PhishGuard** is an advanced, production-ready cybersecurity application that uses a **Multi-Agent Architecture** to identify, inspect, and evaluate phishing attacks across URLs, email bodies, and email headers (RFC822).

---

## 🚀 Key Features & Multi-Agent Architecture

PhishGuard coordinates four specialized autonomous security agents:

```
                          ┌─────────────────────────────┐
                          │   PhishGuard Orchestrator   │
                          └──────────────┬──────────────┘
                                         │
        ┌──────────────────┬─────────────┴────────────┬──────────────────┐
        ▼                  ▼                          ▼                  ▼
┌───────────────┐  ┌───────────────┐          ┌───────────────┐  ┌───────────────┐
│   URL Agent   │  │ Content Agent │          │ Header Agent  │  │   ML Agent    │
├───────────────┤  ├───────────────┤          ├───────────────┤  ├───────────────┤
│ • IP in Host  │  │ • Urgency/Fear│          │ • SPF / DKIM  │  │ • Statistical │
│ • Entropy     │  │ • Credential  │          │ • DMARC Auth  │  │   Probabilities
│ • Typosquats  │  │   Harvesting  │          │ • Sender vs   │  │ • Feature     │
│ • Punycode/IDN│  │ • Link spoof  │          │   Reply-To    │  │   Importance  │
│ • Risky TLDs  │  │ • Attachments │          │ • Routing Hop │  │ • Explainable │
└───────────────┘  └───────────────┘          └───────────────┘  └───────────────┘
```

1. **URL Security Inspector (`UrlAgent`)**:
   - Analyzes lexical domain entropy (randomized strings & DGA detection).
   - Detects brand typosquatting using Levenshtein distance across domain tokens (`paypa1`, `micros0ft`).
   - Identifies Punycode / Internationalized Domain Name (IDN) homoglyph spoofing.
   - Detects numerical IP hosts, suspicious TLDs (`.xyz`, `.top`, `.click`, `.cam`), URL shorteners, and credential paths.

2. **Social Engineering & Content Agent (`ContentAgent`)**:
   - Detects psychological manipulation (artificial urgency, panic cues, account suspension threats).
   - Identifies credential harvesting requests and financial lures.
   - Flags hyperlink destination mismatches (visible text vs actual `href`).
   - Identifies references to dangerous and macro-enabled executable extensions.

3. **Header & Authentication Verifier (`HeaderAgent`)**:
   - Parses and validates SPF, DKIM, and DMARC enforcement statuses.
   - Detects `From` vs `Reply-To` and `Return-Path` domain mismatches.
   - Identifies Display Name impersonation traps.
   - Analyzes intermediate relay hops for unauthenticated residential/dynamic IPs.

4. **Explainable ML Classifier (`MLAgent`)**:
   - Extracts structural, lexical, and behavioral feature vectors.
   - Computes calibrated probabilistic threat scores.
   - Provides **Explainable AI (XAI)** feature importance breakdown showing which signals drove the risk score.

5. **Multi-Agent Orchestrator (`PhishGuardOrchestrator`)**:
   - Dynamically weights active agents based on input context.
   - Enforces escalation rules for critical indicators.
   - Generates actionable mitigation guidance and tailored incident response steps.

---

## 📁 Project Structure

```
PhishGuard/
├── agents/                     # Multi-Agent Detection Subsystem
│   ├── __init__.py
│   ├── base_agent.py          # Abstract Agent base class & AgentResult schema
│   ├── url_agent.py           # URL & domain lexical analysis
│   ├── content_agent.py       # Natural language & social engineering heuristics
│   ├── header_agent.py        # SPF/DKIM/DMARC & header spoofing verifier
│   ├── ml_agent.py            # Feature vector ML scoring & explainable AI
│   └── orchestrator.py        # Multi-agent coordinator & consensus engine
├── static/
│   ├── css/
│   │   └── style.css          # Modern dark-cyber responsive theme
│   └── js/
│       └── main.js            # Frontend tabs, demo loader, clipboard utilities
├── templates/
│   ├── base.html              # Cyber-themed navigation & footer
│   ├── index.html             # Scanner dashboard & demo scenario triggers
│   ├── report.html            # Threat gauge, mitigation steps, agent breakdown
│   └── history.html           # Searchable security audit log
├── tests/
│   ├── test_app.py            # Flask route & REST API tests
│   ├── test_content_agent.py  # Social engineering test cases
│   ├── test_header_agent.py   # Header & auth verification tests
│   ├── test_ml_agent.py       # Feature model tests
│   ├── test_orchestrator.py   # Pipeline orchestration tests
│   └── test_url_agent.py      # URL analysis heuristics tests
├── .env.example               # Configuration template
├── app.py                     # Flask web server & REST API
└── requirements.txt           # Python dependencies
```

---

## ⚡ Quick Start

### 1. Activate Environment & Install Dependencies

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Run the Application

```powershell
.\.venv\Scripts\python.exe app.py
```

Open your browser to:
**`http://localhost:5000`**

---

## 🧪 Running Automated Tests

Run the full pytest suite:

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

All 22 unit and integration tests validate URL heuristics, content analysis, header spoofing, ML explainability, and Flask endpoints.

---

## 📡 REST API Documentation

### Scan Payload (`POST /api/scan`)

Send a JSON payload to analyze URLs, email text, or raw RFC822 messages:

```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://secure-login.paypa1-update.xyz/login",
    "subject": "URGENT: Verify your account immediately",
    "body": "Dear customer, your account will be locked within 24 hours.",
    "headers": {
      "Authentication-Results": "spf=fail dkim=fail"
    }
  }'
```

**Response:**
```json
{
  "scan_id": "a9310bf2",
  "timestamp": "2026-10-16 16:30:00Z",
  "overall_score": 92.5,
  "verdict": "CRITICAL",
  "threat_summary": "CRITICAL PHISHING ATTACK DETECTED (92.5/100)...",
  "agent_results": { ... },
  "indicators": [ ... ],
  "recommendations": [ ... ]
}
```

### Health Check (`GET /api/health`)

```bash
curl http://localhost:5000/api/health
```
