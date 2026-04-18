# ============================================================
# BLIP ENDPOINT SENTINEL — security/audit_logger.py
# AES-256 Fernet Encrypted Audit Logger
# DPDP Act compliant — zero-knowledge storage
# Every clipboard event logged: Allowed / Blocked / Sanitized
# Tamper-proof: encrypted at rest, hash-chained entries
# ============================================================

import hashlib
import json
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken


# ── Action / Threat enums ─────────────────────────────────────

class AuditAction(Enum):
    ALLOWED   = "ALLOWED"
    WARNED    = "WARNED"
    SANITIZED = "SANITIZED"
    BLOCKED   = "BLOCKED"
    SHADOW    = "SHADOW"       # dry-run mode — would have blocked


class AuditThreatSource(Enum):
    REGEX     = "REGEX"
    RAG       = "RAG"
    VISION    = "VISION"
    COMBINED  = "COMBINED"
    NONE      = "NONE"


# ── Audit entry ───────────────────────────────────────────────

@dataclass
class AuditEntry:
    # Identity
    entry_id:       str           # UUID-like sequential ID
    timestamp:      str           # ISO-8601
    user_id:        str           # from settings
    hostname:       str

    # Event
    action:         str           # AuditAction.value
    threat_source:  str           # AuditThreatSource.value
    threat_types:   list[str]     # e.g. ["Aadhaar Number", "PAN Card"]
    content_type:   str           # classifier output
    risk_score:     int           # 0–100
    top_severity:   str           # LOW / MEDIUM / HIGH / CRITICAL / NONE

    # Policy
    violated_policies: list[str]  # policy IDs
    violated_rules:    list[str]  # rule IDs

    # Zero-knowledge fields
    content_hash:   str           # SHA-256 of original text — NEVER raw text
    content_length: int           # character count only
    redacted_preview: str         # e.g. "XXXX-XXXX-1234" safe display

    # Context
    active_process: str           # which app was active
    window_title:   str           # window title (sanitized)

    # Chain integrity
    prev_hash:      str           # hash of previous entry (chain)
    entry_hash:     str = ""      # hash of this entry (set after creation)

    def compute_hash(self) -> str:
        """SHA-256 of entry content for tamper detection."""
        data = (
            f"{self.entry_id}{self.timestamp}{self.user_id}"
            f"{self.action}{self.content_hash}{self.risk_score}"
            f"{self.prev_hash}"
        )
        return hashlib.sha256(data.encode()).hexdigest()

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


# ── Key manager ───────────────────────────────────────────────

class KeyManager:
    """
    Manages the Fernet AES-256 encryption key.
    Generates a new key if none exists.
    Key stored at config/sentinel.key (gitignored).
    """

    def __init__(self, key_path: str = "./config/sentinel.key"):
        self._key_path = Path(key_path)
        self._fernet:  Optional[Fernet] = None

    def load_or_create(self) -> bool:
        """Load existing key or generate a new one."""
        try:
            if self._key_path.exists():
                with open(self._key_path, "rb") as f:
                    key = f.read().strip()
                self._fernet = Fernet(key)
                print(f"[KeyMgr] Key loaded from {self._key_path}")
            else:
                key = Fernet.generate_key()
                self._key_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self._key_path, "wb") as f:
                    f.write(key)
                self._fernet = Fernet(key)
                print(f"[KeyMgr] New key generated → {self._key_path}")
            return True
        except Exception as e:
            print(f"[KeyMgr] Key error: {e}")
            return False

    def encrypt(self, data: bytes) -> bytes:
        if not self._fernet:
            raise RuntimeError("KeyManager not initialized")
        return self._fernet.encrypt(data)

    def decrypt(self, token: bytes) -> bytes:
        if not self._fernet:
            raise RuntimeError("KeyManager not initialized")
        return self._fernet.decrypt(token)

    @property
    def is_ready(self) -> bool:
        return self._fernet is not None


# ── Audit Logger ──────────────────────────────────────────────

class AuditLogger:
    """
    Thread-safe, AES-256 encrypted audit logger.

    Storage format:
      - Log file is a Fernet-encrypted JSON array
      - Each entry is hash-chained to the previous
      - Raw content NEVER stored — only SHA-256 hashes
      - Admin decrypts on-the-fly in dashboard

    Usage:
        logger = AuditLogger()
        logger.initialize()
        logger.log_event(...)
        entries = logger.read_all()   # for admin dashboard
    """

    def __init__(
        self,
        log_path:  str = "./data/logs/threats.json.enc",
        key_path:  str = "./config/sentinel.key",
        user_id:   str = "user@company.com",
        hostname:  str = "WORKSTATION-01",
        max_entries: int = 10_000,
        rotate_days: int = 30,
    ):
        self._log_path    = Path(log_path)
        self._key_manager = KeyManager(key_path)
        self._user_id     = user_id
        self._hostname    = hostname
        self._max_entries = max_entries
        self._rotate_days = rotate_days

        self._lock        = threading.Lock()
        self._entry_count = 0
        self._last_hash   = "GENESIS"   # chain anchor
        self._ready       = False

    # ── Init ──────────────────────────────────────────────────

    def initialize(self) -> bool:
        """Load key, create log file if needed, read chain state."""
        try:
            if not self._key_manager.load_or_create():
                return False

            # Ensure log directory exists
            self._log_path.parent.mkdir(parents=True, exist_ok=True)

            # Load existing entries to restore chain state
            if self._log_path.exists():
                entries = self._load_raw()
                self._entry_count = len(entries)
                if entries:
                    self._last_hash = entries[-1].get("entry_hash", "GENESIS")
                print(f"[Audit] Loaded {self._entry_count} existing entries")
            else:
                # Create empty encrypted log
                self._save_raw([])
                print("[Audit] New log file created")

            self._ready = True
            return True

        except Exception as e:
            print(f"[Audit] Initialization failed: {e}")
            return False

    # ── Log event ─────────────────────────────────────────────

    def log_event(
        self,
        action:            AuditAction,
        risk_score:        int,
        content_hash:      str,
        content_length:    int,
        threat_types:      list[str]  = None,
        threat_source:     AuditThreatSource = AuditThreatSource.NONE,
        content_type:      str  = "UNKNOWN",
        top_severity:      str  = "NONE",
        violated_policies: list[str] = None,
        violated_rules:    list[str] = None,
        redacted_preview:  str  = "",
        active_process:    str  = "",
        window_title:      str  = "",
    ) -> Optional[AuditEntry]:
        """
        Log a clipboard event. Thread-safe.
        Returns the created AuditEntry or None on failure.
        """
        if not self._ready:
            print("[Audit] Logger not initialized")
            return None

        with self._lock:
            try:
                self._entry_count += 1
                entry_id = f"EVT-{self._entry_count:06d}"

                entry = AuditEntry(
                    entry_id          = entry_id,
                    timestamp         = datetime.now().isoformat(),
                    user_id           = self._user_id,
                    hostname          = self._hostname,
                    action            = action.value,
                    threat_source     = threat_source.value,
                    threat_types      = threat_types or [],
                    content_type      = content_type,
                    risk_score        = risk_score,
                    top_severity      = top_severity,
                    violated_policies = violated_policies or [],
                    violated_rules    = violated_rules or [],
                    content_hash      = content_hash,
                    content_length    = content_length,
                    redacted_preview  = redacted_preview,
                    active_process    = active_process,
                    window_title      = _sanitize_window_title(window_title),
                    prev_hash         = self._last_hash,
                )

                # Compute and seal entry hash
                entry.entry_hash = entry.compute_hash()
                self._last_hash  = entry.entry_hash

                # Append to encrypted log
                self._append_entry(entry)

                return entry

            except Exception as e:
                print(f"[Audit] log_event failed: {e}")
                return None

    # ── Read all (admin dashboard) ────────────────────────────

    def read_all(self) -> list[dict]:
        """
        Decrypt and return all audit entries.
        Called by admin dashboard — requires valid Fernet key.
        Returns list of dicts sorted newest-first.
        """
        if not self._ready:
            return []
        try:
            entries = self._load_raw()
            return list(reversed(entries))   # newest first
        except Exception as e:
            print(f"[Audit] read_all failed: {e}")
            return []

    def read_recent(self, n: int = 100) -> list[dict]:
        """Return the N most recent entries."""
        return self.read_all()[:n]

    # ── Integrity verification ────────────────────────────────

    def verify_chain(self) -> tuple[bool, str]:
        """
        Walk the hash chain and verify no entries were tampered with.
        Returns (is_valid, message).
        """
        if not self._ready:
            return False, "Logger not initialized"

        entries = self._load_raw()
        if not entries:
            return True, "Empty log — chain valid"

        prev = "GENESIS"
        for i, e in enumerate(entries):
            # Reconstruct expected hash
            data = (
                f"{e['entry_id']}{e['timestamp']}{e['user_id']}"
                f"{e['action']}{e['content_hash']}{e['risk_score']}"
                f"{prev}"
            )
            expected = hashlib.sha256(data.encode()).hexdigest()
            stored   = e.get("entry_hash", "")

            if expected != stored:
                msg = (f"TAMPER DETECTED at entry {i+1} "
                       f"({e.get('entry_id', '?')})")
                print(f"[Audit] {msg}")
                return False, msg

            prev = stored

        return True, f"Chain valid — {len(entries)} entries verified"

    # ── Statistics (for dashboard) ────────────────────────────

    def get_stats(self) -> dict:
        """Return aggregated metrics for admin dashboard."""
        entries = self.read_all()
        if not entries:
            return {
                "total": 0, "blocked": 0, "sanitized": 0,
                "warned": 0, "allowed": 0,
                "top_threats": [], "top_processes": [],
            }

        from collections import Counter

        actions  = Counter(e["action"] for e in entries)
        threats  = Counter(
            t for e in entries for t in e.get("threat_types", [])
        )
        procs    = Counter(
            e.get("active_process", "unknown") for e in entries
            if e.get("action") != AuditAction.ALLOWED.value
        )

        # Score trend (last 50 entries)
        recent_scores = [
            e["risk_score"] for e in entries[:50]
        ]

        return {
            "total":         len(entries),
            "blocked":       actions.get("BLOCKED", 0),
            "sanitized":     actions.get("SANITIZED", 0),
            "warned":        actions.get("WARNED", 0),
            "allowed":       actions.get("ALLOWED", 0),
            "top_threats":   threats.most_common(5),
            "top_processes": procs.most_common(5),
            "recent_scores": recent_scores,
            "chain_valid":   self.verify_chain()[0],
        }

    # ── Rotation ──────────────────────────────────────────────

    def rotate_if_needed(self):
        """
        Archive old entries beyond retention period.
        Called periodically by the daemon.
        """
        if not self._ready:
            return

        entries = self._load_raw()
        cutoff  = datetime.now() - timedelta(days=self._rotate_days)
        fresh   = []
        archived = 0

        for e in entries:
            try:
                ts = datetime.fromisoformat(e["timestamp"])
                if ts >= cutoff:
                    fresh.append(e)
                else:
                    archived += 1
            except Exception:
                fresh.append(e)   # keep unparseable entries

        if archived > 0:
            self._save_raw(fresh)
            print(f"[Audit] Rotated {archived} old entries")

    # ── Internal I/O ──────────────────────────────────────────

    def _append_entry(self, entry: AuditEntry):
        """Read → append → encrypt → write."""
        entries = self._load_raw()

        # Cap at max_entries (drop oldest)
        if len(entries) >= self._max_entries:
            entries = entries[-(self._max_entries - 1):]

        entries.append(entry.to_dict())
        self._save_raw(entries)

    def _load_raw(self) -> list[dict]:
        """Decrypt and parse the log file."""
        if not self._log_path.exists():
            return []
        try:
            with open(self._log_path, "rb") as f:
                encrypted = f.read()
            if not encrypted:
                return []
            decrypted = self._key_manager.decrypt(encrypted)
            return json.loads(decrypted.decode("utf-8"))
        except InvalidToken:
            print("[Audit] Decryption failed — wrong key or tampered file")
            return []
        except Exception as e:
            print(f"[Audit] Load failed: {e}")
            return []

    def _save_raw(self, entries: list[dict]):
        """Serialize, encrypt, and write the log file."""
        raw       = json.dumps(entries, indent=2).encode("utf-8")
        encrypted = self._key_manager.encrypt(raw)
        with open(self._log_path, "wb") as f:
            f.write(encrypted)

    # ── Status ────────────────────────────────────────────────

    @property
    def is_ready(self) -> bool:
        return self._ready

    @property
    def entry_count(self) -> int:
        return self._entry_count

    def status(self) -> dict:
        return {
            "ready":       self._ready,
            "log_path":    str(self._log_path),
            "entry_count": self._entry_count,
            "last_hash":   self._last_hash[:16] + "...",
        }


# ── Helpers ───────────────────────────────────────────────────

def _sanitize_window_title(title: str) -> str:
    """Remove potentially sensitive info from window titles."""
    if not title:
        return ""
    # Truncate and strip common sensitive patterns
    safe = title[:100]
    for pattern in ["password", "secret", "token", "key", "credential"]:
        safe = safe.lower().replace(pattern, "[redacted]")
    return safe


# ── Module-level singleton ────────────────────────────────────

_logger_instance: Optional[AuditLogger] = None

def get_audit_logger(config: Optional[dict] = None) -> AuditLogger:
    global _logger_instance
    if _logger_instance is None:
        cfg = config or {}
        _logger_instance = AuditLogger(
            log_path  = cfg.get("log_path",  "./data/logs/threats.json.enc"),
            key_path  = cfg.get("key_path",  "./config/sentinel.key"),
            user_id   = cfg.get("user_id",   "user@company.com"),
            hostname  = cfg.get("hostname",  "WORKSTATION-01"),
        )
    return _logger_instance


# ── Self-test ─────────────────────────────────────────────────

if __name__ == "__main__":
    import shutil

    # Use a temp dir for testing
    TEST_LOG = "./data/logs/test_threats.json.enc"
    TEST_KEY = "./config/test_sentinel.key"

    print(f"\n{'='*60}")
    print(f"  Blip Sentinel — AuditLogger Self-Test")
    print(f"{'='*60}\n")

    logger = AuditLogger(
        log_path = TEST_LOG,
        key_path = TEST_KEY,
        user_id  = "test@company.com",
        hostname = "TEST-MACHINE",
    )

    ok = logger.initialize()
    print(f"  Init: {'OK' if ok else 'FAILED'}")
    print(f"  Status: {logger.status()}\n")

    # Log several test events
    test_events = [
        dict(
            action         = AuditAction.ALLOWED,
            risk_score     = 5,
            content_hash   = hashlib.sha256(b"hello world").hexdigest(),
            content_length = 11,
            threat_types   = [],
            threat_source  = AuditThreatSource.NONE,
            content_type   = "NATURAL_LANGUAGE",
            top_severity   = "NONE",
            active_process = "notepad.exe",
            window_title   = "Untitled - Notepad",
        ),
        dict(
            action         = AuditAction.WARNED,
            risk_score     = 45,
            content_hash   = hashlib.sha256(b"my email test@corp.com").hexdigest(),
            content_length = 22,
            threat_types   = ["Email Address"],
            threat_source  = AuditThreatSource.REGEX,
            content_type   = "PII_BLOCK",
            top_severity   = "LOW",
            violated_policies = ["GRP-FIN-001"],
            violated_rules    = ["FIN-001"],
            redacted_preview  = "te**@corp.com",
            active_process = "chrome.exe",
            window_title   = "Gmail - Chrome",
        ),
        dict(
            action         = AuditAction.BLOCKED,
            risk_score     = 97,
            content_hash   = hashlib.sha256(b"AKIAIOSFODNN7EXAMPLE").hexdigest(),
            content_length = 20,
            threat_types   = ["AWS Access Key", "AWS Secret Key"],
            threat_source  = AuditThreatSource.COMBINED,
            content_type   = "CREDENTIALS",
            top_severity   = "CRITICAL",
            violated_policies = ["GRP-ENG-001"],
            violated_rules    = ["ENG-001"],
            redacted_preview  = "AKIA************MPLE",
            active_process = "code.exe",
            window_title   = "config.py - VS Code",
        ),
        dict(
            action         = AuditAction.SANITIZED,
            risk_score     = 72,
            content_hash   = hashlib.sha256(b"aadhaar 2345 6789 0123").hexdigest(),
            content_length = 22,
            threat_types   = ["Aadhaar Number"],
            threat_source  = AuditThreatSource.REGEX,
            content_type   = "PII_BLOCK",
            top_severity   = "CRITICAL",
            violated_policies = ["GRP-FIN-001"],
            violated_rules    = ["FIN-001"],
            redacted_preview  = "XXXX-XXXX-0123",
            active_process = "excel.exe",
            window_title   = "Employee_Data.xlsx",
        ),
    ]

    print("  Logging test events...")
    for ev in test_events:
        entry = logger.log_event(**ev)
        print(f"  [{entry.action:<10}] {entry.entry_id} | "
              f"score:{entry.risk_score:>3} | "
              f"{entry.redacted_preview or 'clean'}")

    print(f"\n  Total entries: {logger.entry_count}")

    # Verify chain integrity
    valid, msg = logger.verify_chain()
    print(f"\n  Chain integrity: {'✓ ' + msg if valid else '✗ ' + msg}")

    # Read back
    print(f"\n  Reading back (newest first):")
    for e in logger.read_recent(3):
        print(f"    {e['entry_id']} | {e['action']} | "
              f"score:{e['risk_score']} | {e['timestamp'][:19]}")

    # Stats
    stats = logger.get_stats()
    print(f"\n  Stats:")
    print(f"    Total:     {stats['total']}")
    print(f"    Blocked:   {stats['blocked']}")
    print(f"    Sanitized: {stats['sanitized']}")
    print(f"    Warned:    {stats['warned']}")
    print(f"    Allowed:   {stats['allowed']}")
    print(f"    Top threats: {stats['top_threats']}")

    # Tamper test
    print(f"\n  Tamper test — manually corrupting one entry...")
    entries = logger._load_raw()
    entries[1]["risk_score"] = 999   # corrupt
    logger._save_raw(entries)
    valid2, msg2 = logger.verify_chain()
    print(f"  Chain after tamper: {'✓' if valid2 else '✗'} {msg2}")

    # Cleanup test files
    Path(TEST_LOG).unlink(missing_ok=True)
    Path(TEST_KEY).unlink(missing_ok=True)

    print(f"\n{'='*60}\n")