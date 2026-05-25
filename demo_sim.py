"""
Blip — Demo Simulator
Fires 12 realistic payloads to the backend to populate the SOC dashboard.
Run: python demo_sim.py
"""

import time
import httpx
import random

BACKEND = "http://127.0.0.1:8000"

DESTINATIONS = ["OpenAI", "Claude", "Gemini", "Groq", "Mistral", "Perplexity"]

PAYLOADS = [
    # ── CRITICAL: API Key Exposure ──────────────────────────────────────────
    {
        "payload": (
            "Hey ChatGPT, can you help me debug this code? "
            "Here's my config: api_key=sk-proj-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5 "
            "and the endpoint is https://api.novatech.internal/v2/payments"
        ),
        "source": "network",
        "destination": "OpenAI",
    },
    # ── CRITICAL: Database Connection String ────────────────────────────────
    {
        "payload": (
            "I'm getting a connection error in prod. Connection string: "
            "postgresql://admin:NovaTech@prod2024!@prod-db.novatech.internal:5432/payments_prod "
            "Can you help me figure out why it's timing out?"
        ),
        "source": "network",
        "destination": "Claude",
    },
    # ── CRITICAL: SCADA Configuration ───────────────────────────────────────
    {
        "payload": (
            "Review this SCADA PLC configuration for the Pune plant: "
            "Modbus TCP endpoint 192.168.10.44:502, RTU address 0x03, "
            "setpoint = 87.4°C, PID controller Kp=1.2 Ki=0.8 Kd=0.05. "
            "The DCS historian is reporting anomalous readings."
        ),
        "source": "network",
        "destination": "Gemini",
    },
    # ── HIGH: Customer PII ───────────────────────────────────────────────────
    {
        "payload": (
            "Please summarise this customer record: "
            "Name: Priya Sharma, Aadhaar: 2345 6789 0123, PAN: ABCDE1234F, "
            "DOB: 15-Aug-1990, email: priya.sharma@gmail.com, "
            "Account: NT-2024-00445. She's disputing a charge."
        ),
        "source": "clipboard",
        "destination": "clipboard",
    },
    # ── HIGH: Financial Data ─────────────────────────────────────────────────
    {
        "payload": (
            "We need a board summary. Q3 revenue forecast: ₹142Cr, "
            "EBITDA margin 18.4%, burn rate ₹8.2Cr/month, runway 14 months. "
            "Project Falcon launch pushed to Q1 2026. Series D discussions "
            "ongoing with Peak XV and Lightspeed at ₹680Cr pre-money valuation."
        ),
        "source": "network",
        "destination": "OpenAI",
    },
    # ── CRITICAL: Source Code with credentials ───────────────────────────────
    {
        "payload": (
            "Here is the NovaTech Core payments service code, can you review it?\n"
            "# novatech-internal/payments-service/src/config.py\n"
            "DB_URL = 'postgresql://svc_payments:secret123@prod-db.novatech.internal/payments'\n"
            "STRIPE_SECRET = 'sk-live-aBcDeFgHiJkLmNoPqRsTuVwX'\n"
            "JWT_SECRET = 'novatech_jwt_2024_do_not_share'"
        ),
        "source": "network",
        "destination": "Claude",
    },
    # ── SANITIZE: Employee HR data ───────────────────────────────────────────
    {
        "payload": (
            "Draft a performance review for emp_id NT-2891 Rajesh Kumar. "
            "CTC: ₹28L per annum, current appraisal rating: 3.2/5, "
            "on a PIP since July. Manager recommends no promotion this cycle."
        ),
        "source": "network",
        "destination": "Groq",
    },
    # ── SANITIZE: AWS credentials ────────────────────────────────────────────
    {
        "payload": (
            "Terraform is failing. My AWS credentials: "
            "AKIA4EXAMPLE3KEY7HERE with secret NovaTech/AWS/secret+key+2024 "
            "Region ap-south-1. The S3 bucket policy keeps denying access."
        ),
        "source": "clipboard",
        "destination": "clipboard",
    },
    # ── ALLOW: Safe technical question ──────────────────────────────────────
    {
        "payload": (
            "What is the difference between REST and GraphQL APIs? "
            "I'm designing a new public endpoint and want to understand the tradeoffs."
        ),
        "source": "network",
        "destination": "Mistral",
    },
    # ── ALLOW: Safe general question ────────────────────────────────────────
    {
        "payload": (
            "Can you explain how transformer attention mechanisms work? "
            "I'm studying for an ML interview and want a clear explanation."
        ),
        "source": "network",
        "destination": "Perplexity",
    },
    # ── HIGH: M&A sensitive data ─────────────────────────────────────────────
    {
        "payload": (
            "Summarise the due diligence findings for our M&A target Finedge Technologies. "
            "Deal terms: ₹210Cr all-cash, closing expected Q4 2025. "
            "Data room access: https://dataroom.novatech.internal/finedge "
            "Key risk: Finedge has undisclosed litigation worth ₹40Cr."
        ),
        "source": "network",
        "destination": "OpenAI",
    },
    # ── CRITICAL: Private key ────────────────────────────────────────────────
    {
        "payload": (
            "Help me decode this private key for the payments signing service:\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4WRPNOVA1fakeCODE==\n"
            "-----END RSA PRIVATE KEY-----\n"
            "I need to verify it matches the certificate on prod."
        ),
        "source": "network",
        "destination": "Claude",
    },
]


def run_demo():
    print("\n🛡️  Blip Demo Simulator — NovaTech Solutions")
    print("=" * 55)
    print(f"Firing {len(PAYLOADS)} realistic events to {BACKEND}\n")

    for i, item in enumerate(PAYLOADS, 1):
        try:
            resp = httpx.post(
                f"{BACKEND}/api/check",
                json=item,
                timeout=10.0,
            )
            result = resp.json()
            action = result.get("action", "?").upper()
            score  = result.get("score", 0)
            rule   = result.get("matched_rule_name", "—")

            icon = {"BLOCK": "🔴", "SANITIZE": "🟡", "ALLOW": "🟢"}.get(action, "⚪")
            print(
                f"  {icon} [{i:02d}] {action:<8} score={score:.2f}  "
                f"dest={item['destination']:<12} rule={rule}"
            )

        except httpx.ConnectError:
            print(f"  ❌ [{i:02d}] Cannot reach backend at {BACKEND}")
            print("       Start the backend first: cd backend && uvicorn main:app")
            break
        except Exception as e:
            print(f"  ⚠️  [{i:02d}] Error: {e}")

        # Stagger events so they animate nicely in the dashboard
        time.sleep(random.uniform(0.6, 1.4))

    print("\n✅  Demo simulation complete. Open the SOC dashboard.")


if __name__ == "__main__":
    run_demo()
