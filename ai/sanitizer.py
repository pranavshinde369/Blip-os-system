# ============================================================
# BLIP ENDPOINT SENTINEL — ai/sanitizer.py
# Surgical AI Sanitizer — Gemini 1.5 Flash
# Triggered when user clicks "✨ SANITIZE & PASTE"
# Sends text + violated policy context to Gemini.
# Redacts ONLY the violating portion — leaves safe
# code/text 100% intact.
# Fallback: offline regex redaction if Gemini unavailable.
# ============================================================

import re
import time
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Optional

import google.generativeai as genai

from core.scanner    import ScanResult
from core.rag_engine import RAGResult


# ── Sanitization result ───────────────────────────────────────

class SanitizeMethod(Enum):
    GEMINI_AI   = "GEMINI_AI"       # cloud AI surgical redaction
    REGEX_LOCAL = "REGEX_LOCAL"     # offline fallback
    PASSTHROUGH = "PASSTHROUGH"     # nothing to redact


@dataclass
class SanitizeResult:
    original_text:   str
    sanitized_text:  str
    method:          SanitizeMethod
    redactions_made: int            # count of replacements
    latency_ms:      float
    success:         bool
    error:           Optional[str] = None

    @property
    def was_modified(self) -> bool:
        return self.original_text != self.sanitized_text

    @property
    def summary(self) -> str:
        return (
            f"{self.method.value} | "
            f"{self.redactions_made} redaction(s) | "
            f"{self.latency_ms:.0f}ms"
        )


# ── Prompt templates ──────────────────────────────────────────

_BASE_SYSTEM_PROMPT = """You are a surgical data sanitizer for an enterprise 
Data Loss Prevention system. Your job is EXTREMELY precise.

STRICT RULES:
1. Redact ONLY the specific text that violates the policy described below.
2. Replace each violation with [REDACTED: <Policy Name>].
3. Leave ALL other text — including surrounding code, comments, and 
   sentences — completely intact and unchanged.
4. Do NOT summarize, explain, or add any commentary.
5. Do NOT wrap your response in markdown code blocks.
6. Return ONLY the sanitized text, nothing else.
7. If nothing needs redacting, return the original text unchanged.
8. Preserve all whitespace, indentation, and line breaks exactly."""

_POLICY_CONTEXT_TEMPLATE = """
VIOLATED POLICIES:
{policies}

THREAT TYPES DETECTED:
{threats}

TEXT TO SANITIZE:
{text}"""

_REGEX_ONLY_PROMPT = """
THREAT TYPES DETECTED:
{threats}

TEXT TO SANITIZE:
{text}"""


# ── Circuit breaker ───────────────────────────────────────────

class _CircuitBreaker:
    """
    Prevents hammering Gemini API when it's unavailable.
    Opens after 3 consecutive failures, resets after 60s.
    """
    FAILURE_THRESHOLD = 3
    RESET_TIMEOUT_SEC = 60

    def __init__(self):
        self._failures   = 0
        self._open       = False
        self._opened_at  = 0.0
        self._lock       = threading.Lock()

    def is_open(self) -> bool:
        with self._lock:
            if self._open:
                if time.time() - self._opened_at > self.RESET_TIMEOUT_SEC:
                    self._open    = False
                    self._failures = 0
                    print("[Sanitizer] Circuit breaker reset — retrying Gemini")
                    return False
            return self._open

    def record_success(self):
        with self._lock:
            self._failures = 0
            self._open     = False

    def record_failure(self):
        with self._lock:
            self._failures += 1
            if self._failures >= self.FAILURE_THRESHOLD:
                self._open      = True
                self._opened_at = time.time()
                print(f"[Sanitizer] Circuit breaker OPEN — "
                      f"falling back to offline redaction for "
                      f"{self.RESET_TIMEOUT_SEC}s")


# ── Surgical Sanitizer ────────────────────────────────────────

class SurgicalSanitizer:
    """
    Two-layer sanitizer:
      Layer 1 (preferred): Gemini 1.5 Flash — understands context,
                           preserves surrounding safe code precisely.
      Layer 2 (fallback):  Offline regex redaction — fast, no API needed.

    Usage:
        sanitizer = SurgicalSanitizer(api_key="YOUR_KEY")
        result    = sanitizer.sanitize(
                        text        = original_text,
                        scan_result = scan_result,
                        rag_result  = rag_result,
                    )
        pyperclip.copy(result.sanitized_text)
    """

    def __init__(
        self,
        api_key:         Optional[str] = None,
        model_name:      str = "gemini-1.5-flash",
        timeout_sec:     int = 10,
        offline_fallback: bool = True,
    ):
        self._api_key         = api_key
        self._model_name      = model_name
        self._timeout_sec     = timeout_sec
        self._offline_fallback = offline_fallback
        self._model:          Optional[genai.GenerativeModel] = None
        self._circuit_breaker = _CircuitBreaker()
        self._ready           = False

        # Stats
        self._stats = {
            "total":      0,
            "ai_success": 0,
            "fallbacks":  0,
            "errors":     0,
        }

    # ── Init ──────────────────────────────────────────────────

    def initialize(self) -> bool:
        """Configure Gemini client. Returns True if AI is available."""
        if not self._api_key:
            print("[Sanitizer] No API key — offline mode only")
            return False
        try:
            genai.configure(api_key=self._api_key)
            self._model = genai.GenerativeModel(
                model_name    = self._model_name,
                system_instruction = _BASE_SYSTEM_PROMPT,
            )
            self._ready = True
            print(f"[Sanitizer] Gemini ready ({self._model_name})")
            return True
        except Exception as e:
            print(f"[Sanitizer] Gemini init failed: {e}")
            return False

    # ── Main sanitize entry point ─────────────────────────────

    def sanitize(
        self,
        text:        str,
        scan_result: Optional[ScanResult]  = None,
        rag_result:  Optional[RAGResult]   = None,
        policy_context: Optional[str]      = None,
    ) -> SanitizeResult:
        """
        Sanitize text using AI (preferred) or regex (fallback).

        Args:
            text:           original clipboard text
            scan_result:    from scanner.py (regex hits)
            rag_result:     from rag_engine.py (policy matches)
            policy_context: optional override policy description

        Returns:
            SanitizeResult with sanitized_text ready to paste
        """
        self._stats["total"] += 1

        if not text or not text.strip():
            return SanitizeResult(
                original_text  = text,
                sanitized_text = text,
                method         = SanitizeMethod.PASSTHROUGH,
                redactions_made = 0,
                latency_ms     = 0.0,
                success        = True,
            )

        # ── Try Gemini AI first ───────────────────────────────
        if (self._ready
                and not self._circuit_breaker.is_open()
                and self._model is not None):
            result = self._sanitize_with_gemini(
                text, scan_result, rag_result, policy_context
            )
            if result.success:
                self._stats["ai_success"] += 1
                self._circuit_breaker.record_success()
                return result
            else:
                self._circuit_breaker.record_failure()
                self._stats["errors"] += 1

        # ── Fallback: offline regex redaction ─────────────────
        if self._offline_fallback:
            self._stats["fallbacks"] += 1
            return self._sanitize_with_regex(text, scan_result)

        # ── No options available ──────────────────────────────
        return SanitizeResult(
            original_text   = text,
            sanitized_text  = text,
            method          = SanitizeMethod.PASSTHROUGH,
            redactions_made = 0,
            latency_ms      = 0.0,
            success         = False,
            error           = "No sanitization method available",
        )

    # ── Gemini AI sanitization ────────────────────────────────

    def _sanitize_with_gemini(
        self,
        text:           str,
        scan_result:    Optional[ScanResult],
        rag_result:     Optional[RAGResult],
        policy_context: Optional[str],
    ) -> SanitizeResult:
        """Call Gemini with strict surgical redaction prompt."""
        t_start = time.perf_counter()

        try:
            # Build policy context string
            policies_str = self._build_policy_context(
                scan_result, rag_result, policy_context
            )
            threats_str  = self._build_threats_string(scan_result)

            # Build prompt
            prompt = _POLICY_CONTEXT_TEMPLATE.format(
                policies = policies_str,
                threats  = threats_str,
                text     = text[:8000],    # Gemini Flash context cap
            )

            # Call Gemini with timeout
            response = self._call_with_timeout(prompt)

            if response is None:
                return SanitizeResult(
                    original_text   = text,
                    sanitized_text  = text,
                    method          = SanitizeMethod.GEMINI_AI,
                    redactions_made = 0,
                    latency_ms      = (time.perf_counter() - t_start) * 1000,
                    success         = False,
                    error           = "Gemini timeout",
                )

            sanitized = response.text.strip()

            # Safety check — Gemini should never return empty
            if not sanitized:
                sanitized = text

            # Count redactions made
            redactions = sanitized.count("[REDACTED:")

            return SanitizeResult(
                original_text   = text,
                sanitized_text  = sanitized,
                method          = SanitizeMethod.GEMINI_AI,
                redactions_made = redactions,
                latency_ms      = (time.perf_counter() - t_start) * 1000,
                success         = True,
            )

        except Exception as e:
            return SanitizeResult(
                original_text   = text,
                sanitized_text  = text,
                method          = SanitizeMethod.GEMINI_AI,
                redactions_made = 0,
                latency_ms      = (time.perf_counter() - t_start) * 1000,
                success         = False,
                error           = str(e),
            )

    def _call_with_timeout(
        self,
        prompt: str,
    ) -> Optional[object]:
        """
        Call Gemini API with a timeout using a thread.
        Returns response object or None on timeout.
        """
        result_holder = [None]
        error_holder  = [None]

        def _call():
            try:
                result_holder[0] = self._model.generate_content(prompt)
            except Exception as e:
                error_holder[0] = e

        t = threading.Thread(target=_call, daemon=True)
        t.start()
        t.join(timeout=self._timeout_sec)

        if t.is_alive():
            print(f"[Sanitizer] Gemini timeout after {self._timeout_sec}s")
            return None

        if error_holder[0]:
            raise error_holder[0]

        return result_holder[0]

    # ── Context builders ──────────────────────────────────────

    def _build_policy_context(
        self,
        scan_result:    Optional[ScanResult],
        rag_result:     Optional[RAGResult],
        override:       Optional[str],
    ) -> str:
        """Build a readable policy context string for the prompt."""
        if override:
            return override

        parts = []

        if rag_result and rag_result.matches:
            for match in rag_result.matches[:3]:
                parts.append(
                    f"- [{match.policy_id} / {match.rule_id}] "
                    f"{match.description}"
                )

        if scan_result and scan_result.matches:
            seen = set()
            for m in scan_result.matches:
                if m.threat_type not in seen:
                    parts.append(
                        f"- [Regex Rule {m.rule_id}] "
                        f"Detected {m.threat_type.value} "
                        f"(severity: {m.severity.value})"
                    )
                    seen.add(m.threat_type)

        return "\n".join(parts) if parts else "General data security policy"

    def _build_threats_string(
        self,
        scan_result: Optional[ScanResult],
    ) -> str:
        if not scan_result or not scan_result.matches:
            return "Unknown threat type"
        types = list({m.threat_type.value for m in scan_result.matches})
        return ", ".join(types)

    # ── Offline regex fallback ────────────────────────────────

    def _sanitize_with_regex(
        self,
        text:        str,
        scan_result: Optional[ScanResult],
    ) -> SanitizeResult:
        """
        Offline fallback: replace regex match regions with
        [REDACTED: ThreatType] tags.
        Processes matches in reverse order to preserve offsets.
        """
        t_start = time.perf_counter()

        if not scan_result or not scan_result.matches:
            # No specific matches — apply generic PII patterns
            return self._apply_generic_redaction(text, t_start)

        result      = text
        redactions  = 0

        # Sort descending by position to preserve string offsets
        sorted_matches = sorted(
            scan_result.matches,
            key=lambda m: m.start,
            reverse=True,
        )

        for match in sorted_matches:
            tag    = f"[REDACTED: {match.threat_type.value}]"
            result = result[:match.start] + tag + result[match.end:]
            redactions += 1

        return SanitizeResult(
            original_text   = text,
            sanitized_text  = result,
            method          = SanitizeMethod.REGEX_LOCAL,
            redactions_made = redactions,
            latency_ms      = (time.perf_counter() - t_start) * 1000,
            success         = True,
        )

    def _apply_generic_redaction(
        self,
        text:    str,
        t_start: float,
    ) -> SanitizeResult:
        """
        Apply a broad set of generic redaction patterns
        when no specific scan matches are available.
        """
        patterns = [
            # Aadhaar
            (r'\b[2-9]{1}[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b',
             "Aadhaar Number"),
            # PAN
            (r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b',
             "PAN Card"),
            # AWS key
            (r'\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b',
             "AWS Access Key"),
            # Generic API key
            (r'(?i)(?:api[_-]?key|secret|token)\s*[=:]\s*\S{20,}',
             "API Key/Secret"),
            # Private key block
            (r'-----BEGIN[^-]+PRIVATE KEY-----[\s\S]*?-----END[^-]+PRIVATE KEY-----',
             "Private Key"),
            # DB connection string
            (r'(?i)(?:mongodb|postgresql|mysql|redis)://[^\s]+',
             "DB Connection String"),
            # Credit card
            (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
             "Credit Card"),
        ]

        result     = text
        redactions = 0

        for pattern, label in patterns:
            def replacer(m, lbl=label):
                return f"[REDACTED: {lbl}]"
            new_result = re.sub(pattern, replacer, result)
            if new_result != result:
                redactions += new_result.count(f"[REDACTED: {label}]")
                result = new_result

        return SanitizeResult(
            original_text   = text,
            sanitized_text  = result,
            method          = SanitizeMethod.REGEX_LOCAL,
            redactions_made = redactions,
            latency_ms      = (time.perf_counter() - t_start) * 1000,
            success         = True,
        )

    # ── Stats ─────────────────────────────────────────────────

    def get_stats(self) -> dict:
        return {**self._stats, "ready": self._ready}


# ── Module-level singleton ────────────────────────────────────

_sanitizer_instance: Optional[SurgicalSanitizer] = None

def get_sanitizer(config: Optional[dict] = None) -> SurgicalSanitizer:
    global _sanitizer_instance
    if _sanitizer_instance is None:
        cfg     = config or {}
        ai_cfg  = cfg.get("ai", {})
        _sanitizer_instance = SurgicalSanitizer(
            api_key          = ai_cfg.get("gemini_api_key"),
            model_name       = ai_cfg.get("gemini_text_model",
                                          "gemini-1.5-flash"),
            timeout_sec      = ai_cfg.get("gemini_timeout_seconds", 10),
            offline_fallback = ai_cfg.get("offline_fallback", True),
        )
    return _sanitizer_instance


# ── Self-test ─────────────────────────────────────────────────

if __name__ == "__main__":
    import json
    from core.scanner import get_scanner

    print(f"\n{'='*65}")
    print(f"  Blip Sentinel — SurgicalSanitizer Self-Test")
    print(f"{'='*65}\n")

    # Load config for API key
    api_key = None
    try:
        with open("./config/settings.json") as f:
            cfg     = json.load(f)
            api_key = cfg.get("ai", {}).get("gemini_api_key")
            if api_key == "YOUR_GEMINI_API_KEY_HERE":
                api_key = None
    except Exception:
        pass

    sanitizer = SurgicalSanitizer(
        api_key          = api_key,
        offline_fallback = True,
    )
    sanitizer.initialize()

    scanner = get_scanner()

    test_cases = [
        {
            "label": "Python config with AWS key",
            "text": """
# Database configuration
DB_HOST = "localhost"
DB_PORT = 5432
DB_NAME = "production"

# AWS credentials (DO NOT COMMIT)
AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# App settings
DEBUG = False
LOG_LEVEL = "INFO"
""",
        },
        {
            "label": "HR record with Aadhaar + PAN",
            "text": (
                "Employee: Rahul Sharma\n"
                "Department: Engineering\n"
                "Aadhaar: 2345 6789 0123\n"
                "PAN: ABCDE1234F\n"
                "Email: rahul@company.com\n"
                "Joining Date: 01/04/2023"
            ),
        },
        {
            "label": "DB connection in code",
            "text": (
                "def get_db():\n"
                "    # Production database\n"
                "    conn = psycopg2.connect(\n"
                '        "postgresql://admin:SuperSecret123'
                '@db.internal:5432/prod"\n'
                "    )\n"
                "    return conn"
            ),
        },
        {
            "label": "Clean code (no redaction needed)",
            "text": (
                "def calculate_total(items: list) -> float:\n"
                "    return sum(item.price for item in items)\n"
            ),
        },
    ]

    for tc in test_cases:
        text        = tc["text"]
        scan_result = scanner.scan(text)
        result      = sanitizer.sanitize(
            text        = text,
            scan_result = scan_result,
        )

        print(f"  ── {tc['label']} ──")
        print(f"  Method     : {result.method.value}")
        print(f"  Redactions : {result.redactions_made}")
        print(f"  Latency    : {result.latency_ms:.1f}ms")
        print(f"  Modified   : {result.was_modified}")
        if result.was_modified:
            print(f"  Output:")
            for line in result.sanitized_text.strip().splitlines():
                print(f"    {line}")
        print()

    print(f"  Stats: {sanitizer.get_stats()}")
    print(f"\n{'='*65}\n")