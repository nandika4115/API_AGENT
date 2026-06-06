# 🛡️ Automated API Security Monitoring Agent

> A continuous REST API security monitoring agent with a live web dashboard, built for the VAPT Lab Mini Project (23CYL65) — CSE (Cyber Security), Ramaiah Institute of Technology.

---

## Problem Statement

Modern applications expose REST APIs that are vulnerable to attacks like Broken Object Level Authorization (BOLA), JWT manipulation, SSRF, and rate limit bypass. These vulnerabilities often go undetected because security testing is done manually and infrequently. Existing automated scanners are either too generic, too expensive, or require significant configuration.

This agent solves that by continuously monitoring API endpoints, detecting real vulnerabilities automatically, and displaying results on a live dashboard — using only free and open-source tools.

---

## What We Built

An automated agent that:

- Scans REST API endpoints for **9 vulnerability classes** derived from the OWASP API Security Top 10
- Displays results on a **live web dashboard** with real-time SocketIO updates
- Supports **dynamic URL input** — scan any API by entering its URL
- **Auto-discovers endpoints** from OpenAPI/Swagger specs
- Tracks **remediation status** across scans (NEW / PERSISTS / RESOLVED)
- Maintains **scan history** with per-scan severity summaries
- Exports findings as **PDF and JSON reports**
- Runs **continuously** — re-scans every 60 seconds in the background

### Vulnerabilities Detected

| Check | OWASP Category | Severity Range |
|-------|---------------|----------------|
| Insecure Endpoints | API1 - BOLA | HIGH |
| Broken Authentication | API2 - Broken Auth | CRITICAL |
| Rate Limit Bypass | API4 - Lack of Resources | HIGH |
| Parameter Tampering | API3 - Excessive Data Exposure | MEDIUM |
| BOLA / IDOR | API1 - BOLA | CRITICAL |
| Mass Assignment | API6 - Mass Assignment | CRITICAL |
| JWT None Algorithm | API2 - Broken Auth | CRITICAL |
| SSRF | API7 - Security Misconfiguration | HIGH |
| Excessive Data Exposure | API3 - Excessive Data Exposure | MEDIUM |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Web Dashboard                        │
│              Flask + SocketIO (port 5000)               │
│   URL Input │ Scan Now │ Filters │ History │ Export     │
└────────────────────────┬────────────────────────────────┘
                         │ HTTP + WebSocket
┌────────────────────────▼────────────────────────────────┐
│                   Agent Core                            │
│                                                         │
│  ┌─────────────┐    ┌──────────────────────────────┐   │
│  │  Discovery  │    │         Runner               │   │
│  │  (Swagger/  │───▶│  Orchestrates all checks     │   │
│  │   Config)   │    │  Aggregates findings         │   │
│  └─────────────┘    └──────────────┬───────────────┘   │
│                                    │                    │
│  ┌─────────────────────────────────▼───────────────┐   │
│  │              Security Checks                    │   │
│  │  unauth │ auth │ ratelimit │ params │ bola      │   │
│  │  mass_assignment │ jwt_none │ ssrf │ data_exp   │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  ┌──────────────┐   ┌──────────────┐                   │
│  │   History    │   │   Reporter   │                   │
│  │  (JSON file) │   │  PDF / JSON  │                   │
│  └──────────────┘   └──────────────┘                   │
└─────────────────────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│              Target API (crAPI / any REST API)          │
│                   localhost:8888                        │
└─────────────────────────────────────────────────────────┘
```

### Flow

```
User enters URL → Discovery (Swagger spec?) → Yes: auto-discover endpoints
                                            → No:  load from config.yaml
                         ↓
              Run 9 security checks in parallel
                         ↓
              Aggregate findings with severity
                         ↓
         Compare with last scan → Remediation status
                         ↓
         Save to scan_history.json + Emit via SocketIO
                         ↓
         Dashboard updates live → Export PDF/JSON
```

---

## Project Structure

```
API_AGENT/
├── agent/
│   ├── __init__.py
│   ├── crawler.py          # Loads config, builds endpoint list, fires HTTP requests
│   ├── discovery.py        # Auto-discovers endpoints from OpenAPI/Swagger specs
│   ├── history.py          # Saves scan results, tracks remediation across scans
│   ├── reporter.py         # Exports findings as PDF and JSON
│   ├── runner.py           # Orchestrates all checks, aggregates findings
│   └── checks/
│       ├── __init__.py
│       ├── unauth.py       # Insecure endpoint detection
│       ├── auth.py         # Broken authentication (invalid token acceptance)
│       ├── ratelimit.py    # Rate limit bypass detection
│       ├── params.py       # Parameter tampering
│       ├── bola.py         # BOLA/IDOR (two-user cross-access testing)
│       ├── mass_assignment.py  # Mass assignment via signup extra fields
│       ├── jwt_none.py     # JWT none algorithm attack
│       ├── ssrf.py         # Server-Side Request Forgery
│       └── data_exposure.py    # Excessive data exposure in responses
├── dashboard/
│   ├── app.py              # Flask + SocketIO server, all API routes
│   └── templates/
│       └── index.html      # Live dashboard UI
├── reports/                # Auto-generated PDF and JSON exports
├── config.yaml             # Target URL, credentials, endpoint list
├── requirements.txt
├── scan_history.json       # Auto-generated scan history
└── README.md
```

---

## Prerequisites

- Python 3.10+
- Docker + Docker Compose (for crAPI demo target)
- Git

---

## Setup & Run — Step by Step

### Step 1 — Clone this repository

```bash
git clone https://github.com/YOUR_USERNAME/API_AGENT.git
cd API_AGENT
```

### Step 2 — Install Python dependencies

```bash
pip install -r requirements.txt
```

`requirements.txt` contains:
```
requests
flask
flask-socketio
pyyaml
reportlab
```

### Step 3 — Set up crAPI (demo vulnerable target)

crAPI is an intentionally vulnerable API by OWASP used as the demo target.

```bash
# In a separate folder outside API_AGENT
git clone https://github.com/OWASP/crAPI.git
cd crAPI
docker compose -f deploy/docker/docker-compose.yml pull
docker compose -f deploy/docker/docker-compose.yml up -d
```

Wait ~60 seconds for all 14 containers to reach Healthy status:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
```

Verify crAPI is running at: `http://localhost:8888`

### Step 4 — Create test accounts in crAPI

The agent needs two accounts to test BOLA/IDOR vulnerabilities.

1. Go to `http://localhost:8888` → Sign Up
   - **Victim account**: `test2@example.com` / `Testpass@123`
   - **Attacker account**: `attacker@example.com` / `Testpass@123`

2. Verify each account via MailHog at `http://localhost:8025`

3. Login as each account → Add a Vehicle (required for SSRF and BOLA vehicle checks)

4. Login as each account → Go to Shop → Buy any product (required for order IDOR checks)

### Step 5 — Configure the agent

Edit `config.yaml` — update credentials if you used different emails:

```yaml
target:
  base_url: "http://localhost:8888"
  name: "crAPI"

auth:
  login_url: "/identity/api/auth/login"
  test_credentials:
    email: "test2@example.com"
    password: "Testpass@123"
  attacker_credentials:
    email: "attacker@example.com"
    password: "Testpass@123"

scan:
  interval_seconds: 60
```

### Step 6 — Initialize scan history

```bash
echo [] > scan_history.json
```

### Step 7 — Run the agent

```bash
cd API_AGENT
python dashboard/app.py
```

Open `http://localhost:5000` in your browser.

### Step 8 — Run your first scan

Click **⚡ Scan Now** on the dashboard. The scan takes 30–60 seconds. Results appear live via WebSocket.

Expected results against crAPI:
- **6 CRITICAL** — BOLA/IDOR (3) + JWT None Algorithm (3)
- **3 HIGH** — Rate Limit Bypass (1) + SSRF (2)
- **3 MEDIUM** — Parameter Tampering + Excessive Data Exposure + Info Leak
- **48 PASS**

---

## Using the Dashboard

### Scan any API
Enter any REST API base URL in the input box and click Scan Now. If the API exposes an OpenAPI/Swagger spec, endpoints are auto-discovered. Otherwise, endpoints from `config.yaml` are used.

**Example — Swagger Petstore:**
```
https://petstore3.swagger.io
```
The agent will auto-discover 19 endpoints and run safe checks on them.

### Filter findings
Use the **All / Critical / High / Medium / Passed** filter buttons to focus on specific severity levels.

### Remediation Tracker
Run two or more scans to see the Remediation Tracker populate:
- 🆕 **NEW** — vulnerability appeared in this scan but not the last
- ⚠️ **PERSISTS** — vulnerability present in both scans (unfixed)
- ✅ **RESOLVED** — vulnerability was present last scan but gone now

### Export reports
- **⬇ JSON** — saves a structured JSON file to `reports/` folder
- **⬇ PDF** — downloads a formatted PDF report

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError: No module named 'agent'` | Make sure you run `python dashboard/app.py` from the `API_AGENT` root directory, not from inside `dashboard/` |
| Scan hangs indefinitely | Run `python -m agent.runner` directly to check for errors. Usually means crAPI containers are not fully healthy yet |
| `scan_history.json` parse error | Run `echo [] > scan_history.json` to reset it |
| Dashboard shows 0 results after scan | SocketIO issue on Windows — ensure `debug=False` and `allow_unsafe_werkzeug=True` in `app.py` last line |
| `Number already registered` on mass assignment check | Fixed automatically — the check now generates a random phone number each run |
| crAPI vehicle not found | Make sure you added a vehicle to the victim account and verified it via MailHog |
| BOLA shows no orders | Place at least one shop order in crAPI as the victim account before scanning |

---

## Ethical & Legal Notice

This tool is intended for use only against:
- APIs you own
- APIs you have explicit written permission to test
- Intentionally vulnerable applications (crAPI, DVWA, etc.) in a local environment

**Do not use this tool against production systems or third-party APIs without authorization.** Unauthorized security testing is illegal under the Computer Fraud and Abuse Act (CFAA) and equivalent laws worldwide.

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Agent Core | Python 3.13 |
| Web Framework | Flask + Flask-SocketIO |
| HTTP Engine | Requests |
| Config Parsing | PyYAML |
| PDF Reports | ReportLab |
| Target App | crAPI (OWASP) via Docker |
| Dashboard UI | HTML + CSS + JavaScript + Socket.IO |

---

## References

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [crAPI — Completely Ridiculous API](https://github.com/OWASP/crAPI)
- [OWASP Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/)
- [JWT RFC 7519](https://tools.ietf.org/html/rfc7519)

---

## Guide

**Dr. Vishalakshi Prabhu H**
Associate Professor, Dept. of CSE (Cyber Security)
Ramaiah Institute of Technology, Bengaluru - 560054

---

*Mini Project — VAPT Lab (23CYL65) | CSE (Cyber Security) | RIT | May 2026*