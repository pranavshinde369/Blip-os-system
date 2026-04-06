# ============================================================
# BLIP ENDPOINT SENTINEL — core/scanner.py
# Sovereign Regex Engine — 100% offline, <5ms scan time
# Detects: Aadhaar, PAN, GSTIN, AWS keys, RSA blocks,
#          Credit cards, IFSC, Hindi/Devanagari PII
# ============================================================

import re
import time
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ── Enums ────────────────────────────────────────────────────

class ThreatType(Enum):
    AADHAAR          = "Aadhaar Number"
    PAN              = "PAN Card"
    GSTIN            = "GSTIN"
    IFSC             = "IFSC Code"
    CREDIT_CARD      = "Credit Card Number"
    BANK_ACCOUNT     = "Bank Account Number"
    AWS_ACCESS_KEY   = "AWS Access Key"
    AWS_SECRET_KEY   = "AWS Secret Key"
    RSA_PRIVATE_KEY  = "RSA Private Key"
    SSH_PRIVATE_KEY  = "SSH Private Key"
    GENERIC_API_KEY  = "Generic API Key"
    DB_CONN_STRING   = "Database Connection String"
    JWT_TOKEN        = "JWT Token"
    PHONE_NUMBER     = "Phone Number (IN)"
    EMAIL_ADDRESS    = "Email Address"
    IP_ADDRESS       = "Internal IP Address"
    HINDI_PII        = "Hindi/Devanagari PII"
    PASSPORT         = "Passport Number (IN)"


class Severity(Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


# ── Result dataclass ─────────────────────────────────────────

@dataclass
class ScanMatch:
    threat_type:  ThreatType
    severity:     Severity
    matched_text: str          # raw matched string (truncated for logs)
    redacted:     str          # safe display version
    start:        int          # char offset in original text
    end:          int
    rule_id:      str


@dataclass
class ScanResult:
    is_threat:    bool
    matches:      list[ScanMatch] = field(default_factory=list)
    scan_time_ms: float = 0.0
    content_hash: str  = ""    # SHA-256 of scanned text (zero-knowledge)
    highest_severity: Optional[Severity] = None

    def add(self, match: ScanMatch):
        self.matches.append(match)
        self.is_threat = True
        # Track highest severity
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        if self.highest_severity is None or \
           order.index(match.severity) > order.index(self.highest_severity):
            self.highest_severity = match.severity


# ── Pattern definitions ───────────────────────────────────────

# Each entry: (rule_id, ThreatType, Severity, compiled_regex)
_PATTERNS: list[tuple[str, ThreatType, Severity, re.Pattern]] = [

    # ── India PII ─────────────────────────────────────────────
    (
        "IN-001",
        ThreatType.AADHAAR,
        Severity.CRITICAL,
        # 12-digit number, optionally space/hyphen separated in groups of 4
        re.compile(
            r'\b[2-9]{1}[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b',
            re.IGNORECASE
        )
    ),
    (
        "IN-002",
        ThreatType.PAN,
        Severity.CRITICAL,
        # Format: AAAAA9999A (5 alpha, 4 digit, 1 alpha)
        re.compile(
            r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b'
        )
    ),
    (
        "IN-003",
        ThreatType.GSTIN,
        Severity.HIGH,
        # Format: 2-digit state code + PAN + 1 digit + Z + 1 alphanumeric
        re.compile(
            r'\b[0-3][0-9][A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b'
        )
    ),
    (
        "IN-004",
        ThreatType.IFSC,
        Severity.MEDIUM,
        # Format: 4 alpha (bank) + 0 + 6 alphanumeric (branch)
        re.compile(
            r'\b[A-Z]{4}0[A-Z0-9]{6}\b'
        )
    ),
    (
        "IN-005",
        ThreatType.PASSPORT,
        Severity.HIGH,
        # Indian passport: 1 letter + 7 digits
        re.compile(
            r'\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b'
        )
    ),
    (
        "IN-006",
        ThreatType.PHONE_NUMBER,
        Severity.MEDIUM,
        # Indian mobile: +91 or 0 prefix, 10 digits starting with 6-9
        re.compile(
            r'(?:\+91|0091|0)[\s\-]?[6-9][0-9]{9}\b'
        )
    ),
    (
        "IN-007",
        ThreatType.BANK_ACCOUNT,
        Severity.HIGH,
        # Indian bank accounts: 9–18 digits (context-dependent)
        re.compile(
            r'(?i)(?:account[\s\-]?(?:no|number|num)[\s:]*)[0-9]{9,18}\b'
        )
    ),

    # ── Financial ─────────────────────────────────────────────
    (
        "FIN-001",
        ThreatType.CREDIT_CARD,
        Severity.CRITICAL,
        # Visa, Mastercard, Amex, Discover — with optional spaces/hyphens
        re.compile(
            r'\b(?:4[0-9]{12}(?:[0-9]{3})?'       # Visa
            r'|5[1-5][0-9]{14}'                     # Mastercard
            r'|3[47][0-9]{13}'                      # Amex
            r'|6(?:011|5[0-9]{2})[0-9]{12})'        # Discover
            r'(?:[\s\-]?[0-9]{4}){0,1}\b'
        )
    ),

    # ── Cloud Secrets ─────────────────────────────────────────
    (
        "SEC-001",
        ThreatType.AWS_ACCESS_KEY,
        Severity.CRITICAL,
        # AWS Access Key IDs always start with AKIA, ABIA, ACCA, or ASIA
        re.compile(
            r'\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b'
        )
    ),
    (
        "SEC-002",
        ThreatType.AWS_SECRET_KEY,
        Severity.CRITICAL,
        # 40-char base64-ish string often preceded by "aws_secret" keywords
        re.compile(
            r'(?i)(?:aws_secret(?:_access)?_key|aws_secret)\s*[=:]\s*'
            r'[A-Za-z0-9/+]{40}\b'
        )
    ),
    (
        "SEC-003",
        ThreatType.RSA_PRIVATE_KEY,
        Severity.CRITICAL,
        re.compile(
            r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
            re.IGNORECASE
        )
    ),
    (
        "SEC-004",
        ThreatType.SSH_PRIVATE_KEY,
        Severity.CRITICAL,
        re.compile(
            r'-----BEGIN OPENSSH PRIVATE KEY-----',
            re.IGNORECASE
        )
    ),
    (
        "SEC-005",
        ThreatType.GENERIC_API_KEY,
        Severity.HIGH,
        # Generic patterns: key=<long alphanum>, token=<long alphanum>
        re.compile(
            r'(?i)(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token|'
            r'auth[_\-]?token|bearer)\s*[=:]\s*[A-Za-z0-9_\-]{20,}'
        )
    ),
    (
        "SEC-006",
        ThreatType.JWT_TOKEN,
        Severity.HIGH,
        # JWT: three base64url segments separated by dots
        re.compile(
            r'\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b'
        )
    ),

    # ── Database Connection Strings ───────────────────────────
    (
        "DB-001",
        ThreatType.DB_CONN_STRING,
        Severity.CRITICAL,
        re.compile(
            r'(?i)(?:mongodb|postgresql|mysql|redis|mssql|oracle|sqlite)'
            r'(?:\+[a-z]+)?://[^\s]{10,}'
        )
    ),

    # ── Network ───────────────────────────────────────────────
    (
        "NET-001",
        ThreatType.IP_ADDRESS,
        Severity.MEDIUM,
        # Private/internal IP ranges only
        re.compile(
            r'\b(?:10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
            r'|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}'
            r'|192\.168\.[0-9]{1,3}\.[0-9]{1,3})\b'
        )
    ),

    # ── Contact Info ──────────────────────────────────────────
    (
        "PII-001",
        ThreatType.EMAIL_ADDRESS,
        Severity.LOW,
        re.compile(
            r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
        )
    ),

    # ── Hindi / Devanagari PII ────────────────────────────────
    (
        "HIN-001",
        ThreatType.HINDI_PII,
        Severity.MEDIUM,
        # Detects Devanagari text blocks (names, addresses in Hindi)
        # Unicode range U+0900–U+097F covers full Devanagari script
        re.compile(
            r'[\u0900-\u097F]{3,}(?:\s+[\u0900-\u097F]{2,}){1,}',
            re.UNICODE
        )
    ),
]


# ── Redaction helper ─────────────────────────────────────────

def _redact(text: str, threat_type: ThreatType) -> str:
    """Produce a safe display string — never exposes full sensitive value."""
    if threat_type == ThreatType.AADHAAR:
        # Show only last 4 digits: XXXX-XXXX-1234
        digits = re.sub(r'[\s\-]', '', text)
        return f"XXXX-XXXX-{digits[-4:]}"
    if threat_type == ThreatType.PAN:
        return f"{text[:3]}XXXXXXX"
    if threat_type == ThreatType.CREDIT_CARD:
        digits = re.sub(r'[\s\-]', '', text)
        return f"XXXX-XXXX-XXXX-{digits[-4:]}"
    if threat_type in (ThreatType.RSA_PRIVATE_KEY, ThreatType.SSH_PRIVATE_KEY):
        return "-----BEGIN PRIVATE KEY----- [REDACTED] -----END PRIVATE KEY-----"
    if threat_type == ThreatType.AWS_ACCESS_KEY:
        return f"{text[:4]}{'X' * 12}{text[-4:]}"
    if threat_type == ThreatType.JWT_TOKEN:
        return f"{text[:12]}...[JWT REDACTED]"
    # Default: show first 4 chars + mask the rest
    if len(text) > 8:
        return f"{text[:4]}{'*' * (len(text) - 4)}"
    return '*' * len(text)


# ── Scanner class ─────────────────────────────────────────────

class SovereignScanner:
    """
    100% offline regex-based scanner.
    Thread-safe, stateless — safe to call from background daemon.
    Target: <5ms for typical clipboard payloads (<10KB).
    """

    def __init__(self):
        # Pre-compile all patterns at init (already compiled above,
        # this just validates and stores a reference)
        self._patterns = _PATTERNS

    def scan(self, text: str) -> ScanResult:
        """
        Scan text for all known threat patterns.
        Returns a ScanResult with all matches found.
        """
        t_start = time.perf_counter()

        result = ScanResult(
            is_threat=False,
            content_hash=hashlib.sha256(text.encode("utf-8", errors="replace"))
                                  .hexdigest()
        )

        if not text or not text.strip():
            result.scan_time_ms = 0.0
            return result

        # Truncate excessively large payloads to protect CPU
        payload = text[:50_000]

        for rule_id, threat_type, severity, pattern in self._patterns:
            for match in pattern.finditer(payload):
                raw = match.group(0)
                result.add(ScanMatch(
                    threat_type  = threat_type,
                    severity     = severity,
                    matched_text = raw[:64],          # cap stored raw text
                    redacted     = _redact(raw, threat_type),
                    start        = match.start(),
                    end          = match.end(),
                    rule_id      = rule_id,
                ))

        result.scan_time_ms = (time.perf_counter() - t_start) * 1000
        return result

    def scan_quick(self, text: str) -> bool:
        """
        Ultra-fast boolean check — returns True on first match found.
        Use this for the hot-path cache miss check before full scan.
        """
        if not text:
            return False
        payload = text[:50_000]
        for _, _, _, pattern in self._patterns:
            if pattern.search(payload):
                return True
        return False

    @property
    def rule_count(self) -> int:
        return len(self._patterns)


# ── Module-level singleton ────────────────────────────────────

_scanner_instance: Optional[SovereignScanner] = None

def get_scanner() -> SovereignScanner:
    """Return the module-level singleton scanner (lazy init)."""
    global _scanner_instance
    if _scanner_instance is None:
        _scanner_instance = SovereignScanner()
    return _scanner_instance


# ── Quick self-test (run this file directly to verify) ───────

if __name__ == "__main__":
    scanner = SovereignScanner()

    test_cases = [
        ("Aadhaar",     "My aadhaar is 2345 6789 0123"),
        ("PAN",         "PAN: ABCDE1234F"),
        ("GSTIN",       "GST: 27ABCDE1234F1Z5"),
        ("AWS Key",     "AKIAIOSFODNN7EXAMPLE"),
        ("RSA Key",     "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."),
        ("JWT",         "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123def456ghi"),
        ("DB Conn",     "postgresql://admin:password123@db.internal:5432/prod"),
        ("Credit Card", "Card: 4111 1111 1111 1111"),
        ("Internal IP", "Server at 192.168.1.100"),
        ("Hindi PII",   "नाम: राहुल शर्मा पता: मुंबई"),
        ("Clean text",  "Hello world, this is safe text."),
    ]

    print(f"\n{'='*60}")
    print(f"  Blip Sentinel — SovereignScanner Self-Test")
    print(f"  {scanner.rule_count} rules loaded")
    print(f"{'='*60}\n")

    all_passed = True
    for label, text in test_cases:
        result = scanner.scan(text)
        status = "THREAT" if result.is_threat else "CLEAN "
        time_ms = f"{result.scan_time_ms:.2f}ms"

        if result.is_threat:
            match = result.matches[0]
            print(f"  [{status}] {label:<14} | {time_ms:>8} | "
                  f"{match.threat_type.value} [{match.severity.value}] "
                  f"→ {match.redacted}")
        else:
            print(f"  [{status}] {label:<14} | {time_ms:>8} |"
                  f" no threats detected")

    print(f"\n{'='*60}\n")