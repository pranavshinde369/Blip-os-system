# 🛡️ Blip — Policy-Native GenAI Firewall

> **WitchHunt 2026 Hackathon Submission**
> Local, air-gap-compatible DLP for the GenAI era. Intercepts AI-bound prompts *before* they leave the machine — at the network layer and the clipboard.

---

## The Problem

Every other DLP tool has a dirty secret: to check if your data is safe to send to an AI, it sends your data to *another* cloud. Blip doesn't. It runs fully local, uses your own company policies as the detection brain, and covers every app on the machine — not just the browser.

**Two things make it different:**

1. **OS-level proxy** — catches HTTPS POSTs to any AI endpoint before they leave the NIC
2. **Clipboard watcher** — catches the *copy* event, 800ms after you press Ctrl+C, before you even open your browser

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Employee Machine                     │
│                                                          │
│  ┌──────────────┐   clipboard   ┌──────────────────────┐│
│  │   Any App    │──────copy────▶│  Clipboard Watcher   ││
│  └──────────────┘               │  (polls 800ms)       ││
│                                 └──────────┬───────────┘│
│  ┌──────────────┐   HTTPS POST             │            │
│  │   Browser /  │──────────────▶┌──────────▼───────────┐│
│  │   VS Code /  │               │   mitmproxy Agent    ││
│  │   curl / ...  │               │   (port 8080)        ││
│  └──────────────┘               └──────────┬───────────┘│
│                                            │ /api/check  │
│                            ┌───────────────▼───────────┐│
│                            │     FastAPI Backend        ││
│                            │  ┌─────────────────────┐  ││
│                            │  │   RAG Policy Engine  │  ││
│                            │  │  sentence-transformers│  ││
│                            │  │  + ChromaDB (local)   │  ││
│                            │  └─────────────────────┘  ││
│                            │  ┌─────────────────────┐  ││
│                            │  │   SQLite Event Log   │  ││
│                            │  └─────────────────────┘  ││
│                            └───────────────┬───────────┘│
│                                            │ WebSocket   │
│                            ┌───────────────▼───────────┐│
│                            │    React SOC Dashboard    ││
│                            │       (port 5173)         ││
│                            └───────────────────────────┘│
└─────────────────────────────────────────────────────────┘
```

---

## How It Works

### 1. Network Interception (mitmproxy)

Blip runs as a system proxy on port 8080. Every HTTPS POST to a known AI endpoint is intercepted:

| Service | Endpoint |
|---|---|
| OpenAI ChatGPT | `api.openai.com` |
| Anthropic Claude | `api.anthropic.com` |
| Google Gemini | `generativelanguage.googleapis.com` |
| Mistral | `api.mistral.ai` |
| Groq | `api.groq.com` |
| Perplexity | `api.perplexity.ai` |
| Cohere | `api.cohere.com` |
| Together AI | `api.together.xyz` |
| OpenRouter | `openrouter.ai` |
| HuggingFace | `huggingface.co` |

The agent parses each vendor's JSON format, extracts the prompt text, POSTs it to the local backend, and based on the response either **blocks** (returns 403), **sanitizes** (rewrites the request body), or **allows** the request through.

### 2. Clipboard Interception (pyperclip)

A background thread polls the clipboard every 800ms. The moment content changes and is longer than 20 characters, it's checked against policy. On a violation:

- Clipboard is **immediately cleared** and replaced with a warning message
- A **desktop notification** pops up (via plyer)
- The event is logged to SQLite and broadcast to the SOC dashboard

This catches copy events from every app on the system — terminals, PDF readers, IDEs, email clients — regardless of browser or OS.

### 3. RAG Policy Engine

The brain of Blip. Fully local, zero API calls.

```
Company policy docs (.txt + .json)
         │
         ▼
   Chunk (120-word overlapping windows)
         │
         ▼
   Embed with all-MiniLM-L6-v2 (sentence-transformers)
         │
         ▼
   Store in ChromaDB (persistent, on-disk)
         │
   ┌─────┴──────────────────────────┐
   │         On each check:         │
   │  1. Keyword scan (JSON rules)  │
   │  2. Cosine similarity query    │
   │  3. Combined score             │
   │  4. Decision: block/sanitize/  │
   │     allow                      │
   └────────────────────────────────┘
```

**Decision thresholds:**

| Score | Action |
|---|---|
| ≥ 0.78 | **BLOCK** — request stopped, 403 returned |
| 0.52 – 0.77 | **SANITIZE** — PII/credentials redacted, forwarded clean |
| < 0.52 | **ALLOW** — no policy violation |

A **+0.18 bonus** is added to the semantic score when any keyword from the JSON rules matches.

---

## Example Company: NovaTech Solutions Pvt. Ltd.

The `policies/` directory ships with a full example policy set for a fictional Indian SaaS company, NovaTech Solutions.

### `data_security_policy.txt`

An 8-section employee-facing policy covering:

- **Data Classification** — TIER 1 (Public) through TIER 4 (Restricted)
- **Prohibited AI Tool Usage** — explicit list of banned services and data types
- **Credential Management** — API keys, tokens, vault requirements
- **Customer Data** — GDPR + IT Act India Section 43A obligations
- **Source Code IP** — protected repos (`novatech-core`, `falcon-engine`, `orion-platform`)
- **Financial Data** — pre-disclosure revenue, Series C/D discussions, M&A targets
- **Incident Response** — 30-minute notification window, no-blame culture
- **Monitoring** — DLP tooling, employee notice

### `ai_usage_rules.json` — 7 Detection Rules

| Rule ID | Name | Severity | Action |
|---|---|---|---|
| R001 | API Key / Credential Exposure | CRITICAL | block |
| R002 | Customer PII Transmission | HIGH | block |
| R003 | Source Code Exfiltration | CRITICAL | block |
| R004 | Financial Data Leak | HIGH | sanitize |
| R005 | SCADA / OT Configuration Leak | CRITICAL | block |
| R006 | HR and Employee Data | HIGH | block |
| R007 | Database Connection Strings | CRITICAL | block |

Each rule includes MITRE ATT&CK technique/tactic tags and compliance references (GDPR, IT Act India, PCI-DSS, IEC 62443, ISO 27001).

---

## Project Structure

```
blip/
├── start.sh                    # One-command launcher
├── requirements.txt            # Python dependencies
├── demo_sim.py                 # Fires 12 realistic demo events
│
├── policies/
│   ├── data_security_policy.txt   # NovaTech prose policy (RAG source)
│   └── ai_usage_rules.json        # Structured rules + keywords
│
├── backend/
│   ├── main.py                 # FastAPI app — all endpoints + WebSocket
│   ├── policy_engine.py        # RAG engine (sentence-transformers + ChromaDB)
│   └── database.py             # SQLite event store
│
├── agent/
│   ├── blip_agent.py           # mitmproxy addon — network interceptor
│   └── clipboard_watcher.py    # 800ms clipboard polling loop
│
└── frontend/
    ├── package.json
    ├── vite.config.js          # Proxies /api and /ws to backend
    └── src/
        ├── App.jsx
        ├── pages/
        │   └── Dashboard.jsx   # Main SOC dashboard
        ├── components/
        │   ├── EventRow.jsx    # Expandable event card
        │   ├── RiskScore.jsx   # Animated SVG risk ring
        │   ├── ActionBadge.jsx # Block / Sanitize / Allow badge
        │   ├── StatCard.jsx    # Metric card
        │   ├── PayloadTester.jsx  # Live policy test widget
        │   └── PolicyManager.jsx  # Upload + reload policies
        ├── hooks/
        │   └── useBlipSocket.js   # Auto-reconnect WebSocket hook
        └── utils/
            └── api.js          # Fetch wrappers for all endpoints
```

---

## Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+
- pip

### Run everything

```bash
# Clone / unzip the project
cd blip

# Boot backend + frontend + fire demo events
./start.sh demo
```

Then open **http://localhost:5173** — the SOC dashboard will populate with 12 realistic NovaTech events.

### Manual startup

```bash
# Terminal 1 — Backend
cd backend
BLIP_POLICIES_DIR=../policies uvicorn main:app --reload --port 8000

# Terminal 2 — Frontend
cd frontend
npm install && npm run dev

# Terminal 3 — Demo events (optional)
python demo_sim.py
```

### Network interceptor (mitmproxy)

```bash
# Start proxy on port 8080
mitmdump -s agent/blip_agent.py --listen-port 8080

# Set system proxy (macOS)
networksetup -setwebproxy Wi-Fi 127.0.0.1 8080
networksetup -setsecurewebproxy Wi-Fi 127.0.0.1 8080

# Set system proxy (Linux / GNOME)
gsettings set org.gnome.system.proxy mode manual
gsettings set org.gnome.system.proxy.http host '127.0.0.1'
gsettings set org.gnome.system.proxy.http port 8080
```

### Clipboard watcher

```bash
python agent/clipboard_watcher.py
```

---

## API Reference

All endpoints served at `http://localhost:8000`.

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/check` | Check a payload against policy |
| `GET` | `/api/events` | List logged events (supports `?limit=&action=`) |
| `GET` | `/api/stats` | Aggregate counts + engine stats |
| `POST` | `/api/policies/upload` | Upload a new `.txt` or `.json` policy file |
| `POST` | `/api/policies/reload` | Re-ingest all policies from disk |
| `GET` | `/api/policies/stats` | Engine metadata (chunks, keywords, model) |
| `WS` | `/ws` | Real-time event stream (WebSocket) |
| `GET` | `/health` | Liveness check |

**Example check request:**

```bash
curl -X POST http://localhost:8000/api/check \
  -H "Content-Type: application/json" \
  -d '{
    "payload": "My API key is sk-proj-abc123 can you help debug this?",
    "source": "network",
    "destination": "OpenAI"
  }'
```

```json
{
  "action": "block",
  "score": 0.9200,
  "reason": "CRITICAL rule triggered: API Key / Credential Exposure",
  "matched_keywords": ["sk-"],
  "matched_rule_id": "R001",
  "matched_rule_name": "API Key / Credential Exposure",
  "severity": "CRITICAL",
  "mitre_technique": "T1552.001",
  "mitre_tactic": "Credential Access",
  "compliance": ["GDPR Article 32", "IT Act India Section 43A", "ISO 27001 A.9"],
  "sanitized_payload": null
}
```

---

## Adding Your Own Policies

### Prose policy (`.txt`)

Drop any plain text document in `policies/`. Blip will chunk it into 120-word overlapping windows, embed each chunk with `all-MiniLM-L6-v2`, and store the vectors in ChromaDB. Any text that is semantically similar to your policy language will score higher.

### Structured rules (`.json`)

```json
{
  "company": "Your Company",
  "rules": [
    {
      "id": "R008",
      "name": "Customer Contract Leak",
      "severity": "HIGH",
      "action": "block",
      "description": "Prevents contract terms from reaching AI tools.",
      "keywords": ["nda", "non-disclosure", "contract value", "penalty clause"],
      "mitre_technique": "T1213",
      "mitre_tactic": "Collection",
      "compliance": ["GDPR Article 5"]
    }
  ]
}
```

After uploading, reload via the dashboard Policy Manager or:

```bash
curl -X POST http://localhost:8000/api/policies/reload
```

---

## Sanitization Patterns

When action is `sanitize`, Blip applies these redaction rules before forwarding:

| Pattern | Replacement |
|---|---|
| Email addresses | `[EMAIL_REDACTED]` |
| Aadhaar numbers (12-digit) | `[AADHAAR_REDACTED]` |
| PAN card (`ABCDE1234F` format) | `[PAN_REDACTED]` |
| Credit/debit card numbers | `[CARD_REDACTED]` |
| OpenAI API keys (`sk-…`) | `[API_KEY_REDACTED]` |
| AWS access keys (`AKIA…`) | `[AWS_KEY_REDACTED]` |
| Credentials in key=value pairs | `[CREDENTIAL_REDACTED]` |
| Database URIs | `[DB_URI_REDACTED]` |
| Matched rule keywords (>4 chars) | `[REDACTED]` |

---

## SOC Dashboard Features

- **Live event feed** — real-time WebSocket stream, newest first, auto-scrolling
- **Risk score rings** — animated SVG rings coloured red/amber/green
- **Traffic breakdown bar** — block / sanitize / allow split at a glance
- **Expandable event rows** — click any event to see MITRE tags, compliance refs, policy source chunk
- **Payload Tester** — 5 preloaded NovaTech sample payloads, live result with sanitized preview
- **Policy Manager** — upload new policies, one-click reload, threshold visualisation
- **Auto-reconnect WebSocket** — exponential backoff, survives backend restarts

---

## Tech Stack

| Layer | Technology |
|---|---|
| RAG Embeddings | `sentence-transformers` — `all-MiniLM-L6-v2` |
| Vector Store | `ChromaDB` (persistent, on-disk) |
| Backend | `FastAPI` + `uvicorn` |
| Event Store | `SQLite` |
| Network Proxy | `mitmproxy` |
| Clipboard | `pyperclip` + `plyer` |
| Frontend | `React 18` + `Vite` + `Tailwind CSS` |
| Realtime | Native `WebSocket` |

No cloud APIs. No telemetry. No vendor lock-in.

---

## Compliance Coverage

Rules are tagged to the following frameworks out of the box:

- **GDPR** Articles 5, 9, 32
- **IT Act India** Section 43A
- **PCI-DSS** 3.2
- **ISO 27001** A.9, A.18
- **IEC 62443** (OT/SCADA security)
- **NIST SP 800-82** (industrial control systems)
- **SEBI** Insider Trading Regulations
- **MITRE ATT&CK** for Enterprise and ICS

---

## License

Built for WitchHunt 2026. Internal demo use only.
