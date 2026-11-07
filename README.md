# 🛡️ PhishGuard - Multi-Agent Phishing Detection Platform

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask%203-lightgrey.svg)](https://flask.palletsprojects.com/)
[![Database](https://img.shields.io/badge/Database-Supabase%20%2F%20SQLite-green.svg)](https://supabase.com/)
[![Security](https://img.shields.io/badge/Security-OWASP%20Hardened-red.svg)](https://owasp.org/)
[![Tests](https://img.shields.io/badge/Tests-41%20Passed-brightgreen.svg)](tests/)

**PhishGuard** is an enterprise-grade, production-ready cybersecurity platform that uses an **Autonomous 5-Agent Architecture** to identify, inspect, and evaluate phishing attacks across URLs, email bodies, and email headers (RFC822).

Includes cloud database integration (**Supabase** with local **SQLite** fallback), dedicated REST APIs for each agent, security penetration hardening, and full **Vercel** serverless readiness.

> 🎓 **New to Python or Cybersecurity?**  
> Check out the comprehensive [`BEGINNER_LEARNING_GUIDE.md`](BEGINNER_LEARNING_GUIDE.md) explaining all concepts, Python syntax, and step-by-step code flow in simple words!

---

## 🚀 Key Features & 5-Agent Architecture

PhishGuard coordinates five specialized autonomous security agents:

```
                          ┌─────────────────────────────┐
                          │   PhishGuard Orchestrator   │
                          └──────────────┬──────────────┘
                                         │
        ┌──────────────────┬─────────────┼────────────┬──────────────────┐
        ▼                  ▼             ▼            ▼                  ▼
┌───────────────┐  ┌───────────────┐ ┌───────────┐ ┌───────────┐  ┌───────────────┐
│   URL Agent   │  │ Content Agent │ │HeaderAgent│ │ThreatIntel│  │   ML Agent    │
├───────────────┤  ├───────────────┤ ├───────────┤ ├───────────┤  ├───────────────┤
│ • IP in Host  │  │ • Urgency/Fear│ │• SPF/DKIM │ │• DNS MX/A │  │ • Statistical │
│ • Entropy     │  │ • Credential  │ │• DMARC    │ │• Dynamic  │  │   Probabilities
│ • Typosquats  │  │   Harvesting  │ │• Sender vs│ │  DNS / Dyn│  │ • Feature     │
│ • Punycode/IDN│  │ • Link spoof  │ │  Reply-To │ │• SSRF Trap│  │   Importance  │
│ • Risky TLDs  │  │ • Attachments │ │• Relays   │ │• ThreatFeed│ │ • Explainable │
└───────────────┘  └───────────────┘ └───────────┘ └───────────┘  └───────────────┘
```

1. **URL Security Inspector (`UrlAgent`)**:
   - Analyzes lexical domain entropy (randomized strings & DGA detection).
   - Detects brand typosquatting using Levenshtein distance across domain tokens (`paypa1`, `micros0ft`).
   - Identifies Punycode / Internationalized Domain Name (IDN) homoglyph spoofing.
   - Detects numerical IP hosts, suspicious TLDs (`.xyz`, `.top`, `.click`, `.cam`), URL shorteners, and credential paths.

2. **Social Engineering & Content Analyst (`ContentAgent`)**:
   - Detects psychological manipulation (artificial urgency, panic cues, account suspension threats).
   - Identifies credential harvesting requests and financial lures.
   - Flags hyperlink destination mismatches (visible text vs actual `href`).
   - Identifies references to dangerous and macro-enabled executable extensions.

3. **Header & Authentication Verifier (`HeaderAgent`)**:
   - Parses and validates SPF, DKIM, and DMARC enforcement statuses.
   - Detects `From` vs `Reply-To` and `Return-Path` domain mismatches.
   - Identifies Display Name impersonation traps.
   - Analyzes intermediate relay hops for unauthenticated residential/dynamic IPs.

4. **Threat Intelligence & DNS Verifier (`ThreatIntelAgent`)**:
   - Verifies DNS MX (Mail Exchanger) records for sender domains to detect burner spoof domains.
   - Resolves DNS A records and detects NXDOMAIN unregistered hosts.
   - Detects dynamic DNS and tunneling abuse (`duckdns.org`, `ngrok.io`, `localtunnel`).
   - Flags private IP addresses and cloud metadata endpoints to prevent Server-Side Request Forgery (SSRF).
   - Integrates with external threat feeds (VirusTotal) when configured.

5. **Explainable ML Classifier (`MLAgent`)**:
   - Extracts structural, lexical, and behavioral feature vectors.
   - Computes calibrated probabilistic threat scores.
   - Provides **Explainable AI (XAI)** feature importance breakdown showing which signals drove the risk score.

6. **Multi-Agent Orchestrator (`PhishGuardOrchestrator`)**:
   - Dynamically weights active agents based on input context.
   - Enforces escalation rules for critical indicators (score > 85).
   - Generates actionable mitigation guidance and tailored incident response steps.

---

## 🔒 Defensive Security & Penetration Testing Hardening

PhishGuard is hardened against the OWASP Top 10 vulnerabilities:

* **XSS Prevention:** Automatic HTML escaping in Jinja2 templates, sanitizing user inputs.
* **SSRF Prevention:** Restricts URL scanning to HTTP/HTTPS schemes, blocking access to loopback (`127.0.0.1`, `localhost`) and cloud metadata (`169.254.169.254`).
* **SQL Injection Immunity:** Parameterized queries (`?`) in SQLite and PostgREST client in Supabase.
* **CSRF Protection:** Cryptographic session tokens (`secrets.token_hex(32)`) validate all form submissions.
* **Rate Limiting:** `Flask-Limiter` throttles abuse and protects against Denial-of-Service attacks.
* **HTTP Security Headers:** Automatic injection of `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy`.

---

## 🗄️ Database: Supabase Cloud & SQLite Fallback

PhishGuard includes a unified database adapter in [`database.py`](database.py):

* **Supabase Cloud Mode:** When `SUPABASE_URL` and `SUPABASE_KEY` are provided in `.env`, scans and audit history are automatically saved into Supabase Cloud PostgreSQL.
* **SQLite Fallback:** When no credentials are provided or running offline, the application automatically persists records into a local SQLite database (`phishguard.db`) without any setup required!
* See [`schema.sql`](schema.sql) to initialize your Supabase table in seconds.

---

## 📁 Project Structure

```
PhishGuard/
├── agents/                     # 5 Autonomous Security Agents
│   ├── __init__.py
│   ├── base_agent.py          # Abstract Agent base class & AgentResult schema
│   ├── url_agent.py           # Agent 1: URL & domain lexical analysis
│   ├── content_agent.py       # Agent 2: NLP & social engineering heuristics
│   ├── header_agent.py        # Agent 3: SPF/DKIM/DMARC & header spoofing verifier
│   ├── threat_intel_agent.py  # Agent 4: DNS MX/A infrastructure & threat feeds
│   ├── ml_agent.py            # Agent 5: Feature vector ML & explainable AI
│   └── orchestrator.py        # Multi-agent coordinator & consensus engine
├── api/
│   └── index.py               # Vercel Serverless Function entry point
├── static/
│   ├── css/style.css          # Modern dark-cyber responsive theme
│   └── js/main.js             # Frontend tabs, demo loader, clipboard utilities
├── templates/
│   ├── base.html              # Cyber navbar with live agent & DB badges
│   ├── index.html             # Scanner dashboard, stats bar & demo triggers
│   ├── report.html            # Threat gauge, mitigation steps, agent breakdown
│   ├── history.html           # Searchable security audit log & stats
│   └── api_docs.html          # Interactive REST API explorer
├── tests/
│   ├── test_app.py            # Flask route & REST API tests
│   ├── test_content_agent.py  # Social engineering test cases
│   ├── test_header_agent.py   # Header & auth verification tests
│   ├── test_ml_agent.py       # Feature model tests
│   ├── test_orchestrator.py   # Pipeline orchestration tests
│   ├── test_security_audit.py # Penetration testing & OWASP audit suite
│   ├── test_threat_intel_agent.py # DNS & threat intel tests
│   └── test_url_agent.py      # URL analysis heuristics tests
├── .env.example               # Configuration template
├── app.py                     # Flask web server & REST API
├── database.py                # Dual-mode persistence (Supabase / SQLite)
├── security.py                # Defensive security, sanitization & CSRF
├── schema.sql                 # Supabase PostgreSQL schema script
├── vercel.json                # Vercel deployment configuration
├── wsgi.py                    # Production WSGI entry point
├── Procfile                   # Container / PaaS deployment
├── requirements.txt           # Python dependencies
└── BEGINNER_LEARNING_GUIDE.md # Complete beginner's learning guide
```

---

## ⚡ Quick Start

### 1. Activate Environment & Install Dependencies

```powershell
cd c:\Users\User\Desktop\PhishGuard
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

Run the full pytest suite (41 unit, integration, and security audit tests):

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

---

## 📡 REST API Reference

PhishGuard provides dedicated REST API endpoints for each agent as well as the unified ensemble:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/scan` | Unified 5-agent ensemble scan across any combination of inputs |
| `POST` | `/api/v1/agents/url` | Direct invocation of Agent 1 (URL Inspector) |
| `POST` | `/api/v1/agents/content` | Direct invocation of Agent 2 (Social Engineering Analyst) |
| `POST` | `/api/v1/agents/header` | Direct invocation of Agent 3 (Header & Auth Verifier) |
| `POST` | `/api/v1/agents/threat-intel` | Direct invocation of Agent 4 (Threat Intel & DNS) |
| `POST` | `/api/v1/agents/ml` | Direct invocation of Agent 5 (ML Risk Attribution) |
| `GET` | `/api/v1/scans` | Retrieve historical scan reports |
| `GET` | `/api/v1/scans/<id>` | Retrieve specific scan report by ID |
| `GET` | `/api/v1/stats` | Retrieve aggregate threat intelligence statistics |
| `GET` | `/api/v1/health` | Operational health and active agent statuses |

View interactive examples at **`http://localhost:5000/api-docs`**.

---

## ☁️ Deployment

### Deploy to Vercel
1. Push code to GitHub.
2. Import project into [Vercel](https://vercel.com).
3. Set environment variables (`SECRET_KEY`, `SUPABASE_URL`, `SUPABASE_KEY`).
4. Vercel automatically deploys using [`vercel.json`](vercel.json) and [`api/index.py`](api/index.py).

### Deploy to Render / Railway
1. Connect repository to [Render](https://render.com).
2. Set Build Command: `pip install -r requirements.txt`
3. Set Start Command: `gunicorn wsgi:app`
4. Set environment variables and launch!
