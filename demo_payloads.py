# ============================================================
# BLIP ENDPOINT SENTINEL — demo_payloads.py
# JUDGE DEMO SCRIPT
#
# Instructions:
#   1. Run:  python main.py --shadow   (in terminal 1)
#   2. Run:  python demo_payloads.py  (in terminal 2)
#   3. Copy each block manually OR run auto-copy mode
#
# Auto-copy mode (copies each payload with 8s gap):
#   python demo_payloads.py --auto
# ============================================================

import argparse
import time
import pyperclip


# ══════════════════════════════════════════════════════════════
# DEMO PAYLOAD 1
# Real-world Django settings file — 180 lines
# VIOLATIONS: AWS keys + DB password + SECRET_KEY + JWT secret
# SAFE PARTS: All Django config, INSTALLED_APPS, MIDDLEWARE
#             should be 100% preserved by Gemini sanitizer
# ══════════════════════════════════════════════════════════════

PAYLOAD_1 = '''
"""
DemoCorp Backend — Django Production Settings
settings/production.py
Last updated: 2024-03-15
Author: backend-team@democorp.in
"""

import os
from pathlib import Path
from datetime import timedelta

BASE_DIR = Path(__file__).resolve().parent.parent

# =============================================================
# CORE SETTINGS
# =============================================================

DEBUG = False
ALLOWED_HOSTS = [
    "api.democorp.in",
    "dashboard.democorp.in",
    "*.democorp.in",
]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "rest_framework_simplejwt",
    "corsheaders",
    "celery",
    "democorp.users",
    "democorp.payments",
    "democorp.analytics",
    "democorp.notifications",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "democorp.urls"
WSGI_APPLICATION = "democorp.wsgi.application"

# =============================================================
# ⚠️  SECRETS — DO NOT COMMIT (violation lines below)
# =============================================================

SECRET_KEY = "django-insecure-k#9x$mP2vL@nQw8zRjT5uY3cB6hF1aE0"

JWT_SECRET_KEY = "jwt-prod-9f8e7d6c5b4a3210fedcba9876543210abcdef"

AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_STORAGE_BUCKET_NAME = "democorp-prod-assets"
AWS_S3_REGION_NAME    = "ap-south-1"

# =============================================================
# DATABASE
# =============================================================

DATABASES = {
    "default": {
        "ENGINE":   "django.db.backends.postgresql",
        "NAME":     "democorp_prod",
        "USER":     "db_admin",
        "PASSWORD": "Sup3rS3cur3Pr0dPassw0rd!",
        "HOST":     "db.internal.democorp.in",
        "PORT":     "5432",
    }
}

DATABASE_URL = "postgresql://db_admin:Sup3rS3cur3Pr0dPassw0rd!@db.internal.democorp.in:5432/democorp_prod"

# =============================================================
# CACHE — Redis
# =============================================================

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": "redis://:RedisP@ssw0rd123@cache.internal.democorp.in:6379/0",
    }
}

# =============================================================
# SIMPLE JWT
# =============================================================

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME":  timedelta(minutes=30),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS":  True,
    "ALGORITHM":              "HS256",
    "SIGNING_KEY":            "jwt-prod-9f8e7d6c5b4a3210fedcba9876543210abcdef",
}

# =============================================================
# EMAIL
# =============================================================

EMAIL_BACKEND      = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST         = "smtp.sendgrid.net"
EMAIL_PORT         = 587
EMAIL_USE_TLS      = True
EMAIL_HOST_USER    = "apikey"
EMAIL_HOST_PASSWORD = "SG.xxxxxxxxxxxxxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxx"

# =============================================================
# LOGGING
# =============================================================

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {"class": "logging.StreamHandler"},
        "file":    {"class": "logging.FileHandler",
                    "filename": "/var/log/democorp/django.log"},
    },
    "root": {
        "handlers": ["console", "file"],
        "level":    "WARNING",
    },
}

# =============================================================
# CORS
# =============================================================

CORS_ALLOWED_ORIGINS = [
    "https://app.democorp.in",
    "https://admin.democorp.in",
]

CORS_ALLOW_CREDENTIALS = True

# =============================================================
# STATIC & MEDIA
# =============================================================

STATIC_URL  = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
MEDIA_URL   = "/media/"
MEDIA_ROOT  = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
LANGUAGE_CODE      = "en-us"
TIME_ZONE          = "Asia/Kolkata"
USE_I18N           = True
USE_TZ             = True
'''


# ══════════════════════════════════════════════════════════════
# DEMO PAYLOAD 2
# Real-world Node.js microservice — 160 lines
# VIOLATIONS: JWT token + internal URLs + API keys
# SAFE PARTS: All Express routing, middleware, business logic
# ══════════════════════════════════════════════════════════════

PAYLOAD_2 = '''
/**
 * DemoCorp Auth Microservice
 * services/auth-service/src/config.js
 * Node.js 18 + Express 4
 */

const express    = require("express");
const jwt        = require("jsonwebtoken");
const bcrypt     = require("bcryptjs");
const rateLimit  = require("express-rate-limit");
const helmet     = require("helmet");

const app = express();
app.use(express.json());
app.use(helmet());

// ── Rate limiting ──────────────────────────────────────────
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: "Too many login attempts, please try again later.",
});

// ── Config ─────────────────────────────────────────────────
const config = {
    port:        process.env.PORT || 3001,
    environment: "production",

    // ⚠️  VIOLATION: hardcoded secrets
    jwt: {
        secret:         "eyJhbGciOiJIUzI1NiJ9.democorp.prod.secret.key.2024",
        refreshSecret:  "refresh-secret-democorp-prod-xK9mP2vL8nQw",
        accessExpiry:   "30m",
        refreshExpiry:  "7d",
    },

    // ⚠️  VIOLATION: internal service URLs
    services: {
        userService:    "http://user-svc.democorp.internal:3002",
        paymentService: "http://payment-svc.democorp.internal:3003",
        notifService:   "http://notif-svc.democorp.internal:3004",
        apiGateway:     "http://gateway.democorp.internal:8080",
    },

    // ⚠️  VIOLATION: DB credentials
    database: {
        uri:      "mongodb://admin:M0ng0S3cr3t@mongo.internal.democorp.in:27017/democorp",
        poolSize: 10,
        timeout:  5000,
    },

    // Safe: no violations
    cors: {
        origin:      ["https://app.democorp.in"],
        credentials: true,
    },
};

// ── Helpers ────────────────────────────────────────────────
const generateTokens = (userId, role) => {
    const accessToken = jwt.sign(
        { userId, role, iss: "democorp-auth" },
        config.jwt.secret,
        { expiresIn: config.jwt.accessExpiry }
    );
    const refreshToken = jwt.sign(
        { userId },
        config.jwt.refreshSecret,
        { expiresIn: config.jwt.refreshExpiry }
    );
    return { accessToken, refreshToken };
};

const verifyToken = (token, secret) => {
    try {
        return jwt.verify(token, secret);
    } catch (err) {
        return null;
    }
};

const hashPassword = async (password) => {
    return await bcrypt.hash(password, 12);
};

const comparePassword = async (plain, hashed) => {
    return await bcrypt.compare(plain, hashed);
};

// ── Routes ─────────────────────────────────────────────────
app.post("/auth/login", loginLimiter, async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            success: false,
            message: "Email and password required",
        });
    }

    try {
        // Validate user (safe business logic)
        const user = await fetchUser(email);
        if (!user) {
            return res.status(401).json({
                success: false,
                message: "Invalid credentials",
            });
        }

        const valid = await comparePassword(password, user.passwordHash);
        if (!valid) {
            return res.status(401).json({
                success: false,
                message: "Invalid credentials",
            });
        }

        const { accessToken, refreshToken } = generateTokens(
            user.id, user.role
        );

        res.json({
            success:      true,
            accessToken,
            refreshToken,
            expiresIn:    1800,
        });
    } catch (err) {
        console.error("Login error:", err.message);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

app.post("/auth/refresh", async (req, res) => {
    const { refreshToken } = req.body;
    const payload = verifyToken(refreshToken, config.jwt.refreshSecret);
    if (!payload) {
        return res.status(401).json({ success: false });
    }
    const tokens = generateTokens(payload.userId, payload.role);
    res.json({ success: true, ...tokens });
});

app.get("/health", (req, res) => {
    res.json({ status: "ok", service: "auth", version: "2.1.4" });
});

app.listen(config.port, () => {
    console.log(`Auth service running on port ${config.port}`);
});
'''


# ══════════════════════════════════════════════════════════════
# DEMO PAYLOAD 3
# Employee data CSV dump — pure PII
# VIOLATIONS: Aadhaar + PAN + Bank + Phone for every row
# SAFE PARTS: Nothing — entire payload is sensitive
# ══════════════════════════════════════════════════════════════

PAYLOAD_3 = '''Employee ID,Name,Department,Aadhaar,PAN,Bank Account,IFSC,Phone,Salary
EMP-001,Rahul Sharma,Engineering,2345 6789 0123,ABCDE1234F,919100001234,HDFC0001234,+91 9876543210,₹18,00,000
EMP-002,Priya Nair,Finance,3456 7890 1234,FGHIJ5678K,919100002345,ICIC0002345,+91 9765432109,₹15,50,000
EMP-003,Amit Patel,Product,4567 8901 2345,KLMNO9012L,919100003456,SBIN0003456,+91 9654321098,₹22,00,000
EMP-004,Sneha Reddy,HR,5678 9012 3456,PQRST3456M,919100004567,AXIS0004567,+91 9543210987,₹14,00,000
EMP-005,Vikram Singh,Sales,6789 0123 4567,UVWXY7890N,919100005678,KOTAK005678,+91 9432109876,₹12,50,000
'''


# ══════════════════════════════════════════════════════════════
# DEMO PAYLOAD 4
# Python data pipeline — 130 lines
# VIOLATIONS: Only the AWS key + DB password lines
# SAFE PARTS: 120+ lines of clean ETL logic fully preserved
# ══════════════════════════════════════════════════════════════

PAYLOAD_4 = '''
"""
DemoCorp Data Pipeline
pipelines/etl/customer_sync.py
Syncs customer records from Postgres → S3 → Redshift
"""

import boto3
import psycopg2
import pandas as pd
import logging
from datetime import datetime, timedelta
from typing import Iterator, Optional

logger = logging.getLogger(__name__)


# ── ⚠️  VIOLATION: hardcoded credentials ──────────────────
AWS_KEY    = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_CONN    = "postgresql://etl_user:ETLPassw0rd!@db.internal:5432/prod"
# ──────────────────────────────────────────────────────────


# ── Safe: all business logic below ───────────────────────

BATCH_SIZE       = 1000
S3_BUCKET        = "democorp-data-lake"
S3_PREFIX        = "raw/customers/"
REDSHIFT_SCHEMA  = "public"
REDSHIFT_TABLE   = "dim_customers"


def get_db_connection(conn_str: str) -> psycopg2.extensions.connection:
    """Create a database connection with retry logic."""
    import time
    for attempt in range(3):
        try:
            conn = psycopg2.connect(conn_str)
            conn.autocommit = False
            logger.info("Database connected")
            return conn
        except psycopg2.OperationalError as e:
            logger.warning(f"DB connect attempt {attempt+1} failed: {e}")
            time.sleep(2 ** attempt)
    raise RuntimeError("Could not connect to database after 3 attempts")


def fetch_updated_customers(
    conn: psycopg2.extensions.connection,
    since: datetime,
    batch_size: int = BATCH_SIZE,
) -> Iterator[pd.DataFrame]:
    """Yield batches of customers updated since given timestamp."""
    query = """
        SELECT
            c.id,
            c.external_id,
            c.first_name,
            c.last_name,
            c.email,
            c.phone,
            c.created_at,
            c.updated_at,
            c.is_active,
            c.tier,
            COUNT(o.id) AS order_count,
            SUM(o.total_amount) AS lifetime_value
        FROM customers c
        LEFT JOIN orders o ON o.customer_id = c.id
        WHERE c.updated_at >= %(since)s
        GROUP BY c.id
        ORDER BY c.updated_at DESC
    """
    cursor = conn.cursor()
    cursor.execute(query, {"since": since})

    while True:
        rows = cursor.fetchmany(batch_size)
        if not rows:
            break
        cols = [desc[0] for desc in cursor.description]
        yield pd.DataFrame(rows, columns=cols)


def upload_to_s3(
    df: pd.DataFrame,
    bucket: str,
    key: str,
    aws_key: str,
    aws_secret: str,
) -> str:
    """Upload dataframe as parquet to S3. Returns S3 URI."""
    s3 = boto3.client(
        "s3",
        aws_access_key_id     = aws_key,
        aws_secret_access_key = aws_secret,
        region_name           = "ap-south-1",
    )
    import io
    buf = io.BytesIO()
    df.to_parquet(buf, index=False, compression="snappy")
    buf.seek(0)
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())
    return f"s3://{bucket}/{key}"


def run_pipeline(since: Optional[datetime] = None):
    """Main ETL entry point."""
    if since is None:
        since = datetime.now() - timedelta(hours=24)

    logger.info(f"Starting customer sync from {since}")

    conn       = get_db_connection(DB_CONN)
    batch_num  = 0
    total_rows = 0

    try:
        for batch_df in fetch_updated_customers(conn, since):
            batch_num += 1
            key = (
                f"{S3_PREFIX}"
                f"{datetime.now().strftime('%Y/%m/%d')}/"
                f"batch_{batch_num:04d}.parquet"
            )
            s3_uri = upload_to_s3(
                batch_df, S3_BUCKET, key, AWS_KEY, AWS_SECRET
            )
            total_rows += len(batch_df)
            logger.info(f"Batch {batch_num}: {len(batch_df)} rows → {s3_uri}")

    finally:
        conn.close()

    logger.info(f"Pipeline complete: {total_rows} rows in {batch_num} batches")
    return {"batches": batch_num, "rows": total_rows}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    result = run_pipeline()
    print(f"Done: {result}")
'''


# ══════════════════════════════════════════════════════════════
# DEMO PAYLOAD 5 — CLEAN CODE (no violations)
# Shows that Sentinel does NOT block clean code
# ══════════════════════════════════════════════════════════════

PAYLOAD_5 = '''
"""
DemoCorp Utils — Safe utility functions
utils/formatting.py
No secrets, no PII — should pass through CLEAN
"""

from datetime import datetime
from typing import Optional
import re


def format_currency(amount: float, currency: str = "INR") -> str:
    """Format a number as currency string."""
    if currency == "INR":
        return f"₹{amount:,.2f}"
    return f"{currency} {amount:,.2f}"


def validate_email(email: str) -> bool:
    """Validate email address format."""
    pattern = r"^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


def paginate(items: list, page: int, per_page: int = 20) -> dict:
    """Paginate a list of items."""
    total   = len(items)
    start   = (page - 1) * per_page
    end     = start + per_page
    return {
        "items":       items[start:end],
        "total":       total,
        "page":        page,
        "per_page":    per_page,
        "total_pages": (total + per_page - 1) // per_page,
        "has_next":    end < total,
        "has_prev":    page > 1,
    }


def slugify(text: str) -> str:
    """Convert text to URL-safe slug."""
    text = text.lower().strip()
    text = re.sub(r"[^\\w\\s-]", "", text)
    text = re.sub(r"[\\s_-]+", "-", text)
    return text.strip("-")


def time_ago(dt: datetime) -> str:
    """Return human-readable time difference."""
    delta = datetime.now() - dt
    if delta.days > 365:
        return f"{delta.days // 365}y ago"
    if delta.days > 30:
        return f"{delta.days // 30}mo ago"
    if delta.days > 0:
        return f"{delta.days}d ago"
    hours = delta.seconds // 3600
    if hours > 0:
        return f"{hours}h ago"
    minutes = delta.seconds // 60
    return f"{minutes}m ago"


class APIResponse:
    """Standardised API response builder."""

    @staticmethod
    def success(data=None, message="Success", status=200):
        return {
            "success": True,
            "status":  status,
            "message": message,
            "data":    data,
            "timestamp": datetime.now().isoformat(),
        }

    @staticmethod
    def error(message="Error", status=400, errors=None):
        return {
            "success": False,
            "status":  status,
            "message": message,
            "errors":  errors or [],
            "timestamp": datetime.now().isoformat(),
        }
'''


# ══════════════════════════════════════════════════════════════
# Demo runner
# ══════════════════════════════════════════════════════════════

PAYLOADS = [
    {
        "name":     "1 — Django Production Settings (180 lines)",
        "payload":  PAYLOAD_1,
        "expect":   "BLOCK/SANITIZE — AWS keys + DB password + JWT secret",
        "safe":     "INSTALLED_APPS, MIDDLEWARE, LOGGING preserved",
    },
    {
        "name":     "2 — Node.js Auth Microservice (160 lines)",
        "payload":  PAYLOAD_2,
        "expect":   "BLOCK/SANITIZE — JWT secret + internal URLs + MongoDB URI",
        "safe":     "All Express routes, business logic preserved",
    },
    {
        "name":     "3 — Employee PII Data Dump (CSV)",
        "payload":  PAYLOAD_3,
        "expect":   "HARD BLOCK — Aadhaar + PAN + bank details (score 95+)",
        "safe":     "N/A — entire payload is sensitive",
    },
    {
        "name":     "4 — Python ETL Pipeline (130 lines)",
        "payload":  PAYLOAD_4,
        "expect":   "SANITIZE — only 3 credential lines redacted",
        "safe":     "All 120+ lines of ETL logic fully intact",
    },
    {
        "name":     "5 — Clean Utility Functions (SAFE)",
        "payload":  PAYLOAD_5,
        "expect":   "ALLOW — zero violations, no popup",
        "safe":     "Full code passes through untouched",
    },
]


def print_menu():
    print(f"\n{'='*62}")
    print(f"  BLIP SENTINEL — Judge Demo Payloads")
    print(f"  Make sure daemon is running: python main.py")
    print(f"{'='*62}\n")
    for i, p in enumerate(PAYLOADS, 1):
        print(f"  [{i}] {p['name']}")
        print(f"      Expect  : {p['expect']}")
        print(f"      Safe    : {p['safe']}")
        print()
    print(f"  [A] AUTO — cycle all with 12s gap (hands-free demo)")
    print(f"  [Q] Quit")
    print(f"\n{'='*62}\n")


def copy_payload(p: dict):
    print(f"\n  Copying: {p['name']}")
    print(f"  Expected: {p['expect']}")
    pyperclip.copy(p["payload"])
    print(f"  ✓ Copied {len(p['payload'])} chars to clipboard")
    print(f"  → Sentinel should trigger in ~1 second...\n")


def auto_mode():
    print(f"\n  AUTO MODE — cycling all payloads with 12s gap")
    print(f"  Press Ctrl+C to stop\n")
    while True:
        for p in PAYLOADS:
            copy_payload(p)
            for remaining in range(12, 0, -1):
                print(f"\r  Next payload in {remaining}s...  ", end="")
                time.sleep(1)
            print()


def interactive_mode():
    print_menu()
    while True:
        choice = input("  Select payload [1-5 / A / Q]: ").strip().upper()
        if choice == "Q":
            print("\n  Goodbye!\n")
            break
        elif choice == "A":
            auto_mode()
        elif choice.isdigit() and 1 <= int(choice) <= len(PAYLOADS):
            copy_payload(PAYLOADS[int(choice) - 1])
            input("  Press Enter for menu...")
            print_menu()
        else:
            print("  Invalid choice")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--auto", action="store_true",
                        help="Auto-cycle all payloads")
    args = parser.parse_args()

    if args.auto:
        auto_mode()
    else:
        interactive_mode()