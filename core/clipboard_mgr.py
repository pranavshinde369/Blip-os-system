# ============================================================
# BLIP ENDPOINT SENTINEL — core/clipboard_mgr.py
# Clipboard Interception Engine
# Continuously polls OS clipboard for text + image changes.
# On threat detected: substitutes clipboard content,
# fires UI popup, waits for user decision (Block/Sanitize).
# Ties together: Scanner → Classifier → RAG → RiskScorer
#                → AuditLogger → Notifier → UI
# ============================================================

import hashlib
import threading
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Callable, Optional

import pyperclip
from PIL import ImageGrab

from core.scanner     import get_scanner,    ScanResult
from core.classifier  import get_classifier, ClassificationResult
from core.risk_scorer import get_scorer,     RiskScore, Decision
from core.rag_engine  import get_rag_engine, RAGResult
from security.audit_logger import (
    get_audit_logger, AuditAction, AuditThreatSource
)


# ── Clipboard content types ───────────────────────────────────

class ClipboardContentType(Enum):
    TEXT  = "TEXT"
    IMAGE = "IMAGE"
    EMPTY = "EMPTY"


# ── Clipboard snapshot ────────────────────────────────────────

@dataclass
class ClipboardSnapshot:
    content_type: ClipboardContentType
    text:         Optional[str]   = None
    image:        Optional[object] = None   # PIL Image
    content_hash: str             = ""
    captured_at:  datetime        = field(default_factory=datetime.now)

    def compute_hash(self) -> str:
        if self.text:
            return hashlib.sha256(
                self.text.encode("utf-8", errors="replace")
            ).hexdigest()
        if self.image:
            import io
            buf = io.BytesIO()
            self.image.save(buf, format="PNG")
            return hashlib.sha256(buf.getvalue()).hexdigest()
        return ""


# ── Threat event (passed to UI) ───────────────────────────────

@dataclass
class ThreatEvent:
    snapshot:       ClipboardSnapshot
    scan_result:    ScanResult
    rag_result:     RAGResult
    risk_score:     RiskScore
    classification: ClassificationResult
    active_process: str = ""
    window_title:   str = ""

    @property
    def threat_summary(self) -> str:
        types = [m.threat_type.value for m in self.scan_result.matches]
        if self.rag_result.is_violation and self.rag_result.best_match:
            types.append(f"Policy: {self.rag_result.best_match.rule_id}")
        return ", ".join(types) if types else "Vision AI Flag"

    @property
    def top_policy(self) -> str:
        if self.rag_result.best_match:
            return (f"{self.rag_result.best_match.policy_id} — "
                    f"{self.rag_result.best_match.description[:60]}")
        return "Regex Pattern Match"

    @property
    def redacted_preview(self) -> str:
        if self.scan_result.matches:
            return self.scan_result.matches[0].redacted
        return ""


# ── User decision ─────────────────────────────────────────────

class UserDecision(Enum):
    BLOCK    = "BLOCK"
    SANITIZE = "SANITIZE"
    ALLOW    = "ALLOW"      # override (admin only)
    TIMEOUT  = "TIMEOUT"    # popup timed out → auto-block


# ── LRU Threat Cache ──────────────────────────────────────────

class ThreatCache:
    """
    Caches recent clipboard hashes + their scan decisions.
    Prevents re-scanning identical content on every poll cycle.
    Target: eliminates ~90% of redundant AI calls.
    """

    def __init__(self, max_size: int = 256):
        self._cache: dict[str, tuple[bool, RiskScore]] = {}
        self._order: list[str] = []
        self._max   = max_size
        self._lock  = threading.Lock()

    def get(self, content_hash: str) -> Optional[tuple[bool, RiskScore]]:
        with self._lock:
            return self._cache.get(content_hash)

    def put(self, content_hash: str, is_threat: bool, score: RiskScore):
        with self._lock:
            if content_hash in self._cache:
                self._order.remove(content_hash)
            elif len(self._order) >= self._max:
                oldest = self._order.pop(0)
                del self._cache[oldest]
            self._cache[content_hash] = (is_threat, score)
            self._order.append(content_hash)

    def clear(self):
        with self._lock:
            self._cache.clear()
            self._order.clear()

    @property
    def size(self) -> int:
        return len(self._cache)


# ── Clipboard Manager ─────────────────────────────────────────

class ClipboardManager:
    """
    Core daemon engine. Polls clipboard every N ms,
    runs the full detection pipeline, and handles
    threat responses via the Clipboard Substitution Pattern.

    Callbacks:
        on_threat(ThreatEvent) → called when threat detected
        on_allow(snapshot)     → called when content is clean
        on_error(exception)    → called on unexpected errors
    """

    BLOCKED_PLACEHOLDER = (
        "⚠️ [CONTENT BLOCKED BY BLIP SENTINEL]\n"
        "This content was flagged as a potential data leak.\n"
        "Contact your administrator if this is a mistake."
    )

    def __init__(
        self,
        poll_interval_ms:   int   = 500,
        shadow_mode:        bool  = False,
        demo_mode:          bool  = False,
        popup_timeout_sec:  int   = 30,
        max_clipboard_kb:   int   = 512,
        rag_enabled:        bool  = True,
        vision_enabled:     bool  = False,   # requires Gemini
        config:             dict  = None,
    ):
        self._poll_ms        = poll_interval_ms
        self._shadow         = shadow_mode
        self._demo           = demo_mode
        self._timeout_sec    = popup_timeout_sec
        self._max_kb         = max_clipboard_kb
        self._rag_enabled    = rag_enabled
        self._vision_enabled = vision_enabled
        self._config         = config or {}

        # Core modules
        self._scanner     = get_scanner()
        self._classifier  = get_classifier()
        self._scorer      = get_scorer()
        self._rag         = get_rag_engine() if rag_enabled else None
        self._logger      = get_audit_logger()
        self._cache       = ThreatCache(
            max_size=self._config.get("threat_cache_size", 256)
        )

        # State
        self._last_hash:    str  = ""
        self._running:      bool = False
        self._paused:       bool = False
        self._poll_thread:  Optional[threading.Thread] = None

        # Decision gate — UI sets this event + result
        self._decision_event:  threading.Event = threading.Event()
        self._pending_decision: Optional[UserDecision] = None
        self._sanitized_text:   Optional[str] = None

        # Callbacks (set by main.py / ui layer)
        self.on_threat:  Optional[Callable[[ThreatEvent], None]] = None
        self.on_allow:   Optional[Callable[[ClipboardSnapshot], None]] = None
        self.on_error:   Optional[Callable[[Exception], None]]   = None

        # Stats
        self._stats = {
            "total_scans":    0,
            "threats_found":  0,
            "cache_hits":     0,
            "blocks":         0,
            "sanitizations":  0,
            "allows":         0,
        }

        # Demo mode test payloads
        self._demo_index   = 0
        self._demo_payloads = [
            "My Aadhaar is 2345 6789 0123 — please update records",
            "aws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG",
            "postgresql://admin:secret123@db.internal:5432/prod_db",
            "PAN: ABCDE1234F  GSTIN: 27ABCDE1234F1Z5  IFSC: HDFC0001234",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
            "Hello team, please find the attached report. Best regards.",
        ]

    # ── Lifecycle ─────────────────────────────────────────────

    def start(self):
        """Start the background polling thread."""
        if self._running:
            return
        self._running = True
        self._poll_thread = threading.Thread(
            target=self._poll_loop,
            name="BlipSentinel-ClipboardPoll",
            daemon=True,
        )
        self._poll_thread.start()
        print("[ClipMgr] Polling started "
              f"(interval={self._poll_ms}ms, "
              f"shadow={self._shadow}, demo={self._demo})")

    def stop(self):
        """Gracefully stop the polling thread."""
        self._running = False
        if self._poll_thread:
            self._poll_thread.join(timeout=3.0)
        print("[ClipMgr] Polling stopped")

    def pause(self):
        """Temporarily pause scanning (e.g. while popup is open)."""
        self._paused = True

    def resume(self):
        """Resume scanning after popup resolution."""
        self._paused = False

    # ── Main poll loop ────────────────────────────────────────

    def _poll_loop(self):
        """
        Background thread: polls clipboard every N ms.
        Designed for <1% CPU usage at 500ms interval.
        """
        while self._running:
            try:
                if not self._paused:
                    if self._demo:
                        self._inject_demo_payload()
                    else:
                        self._check_clipboard()
            except Exception as e:
                if self.on_error:
                    self.on_error(e)
                else:
                    print(f"[ClipMgr] Poll error: {e}")
                    traceback.print_exc()

            time.sleep(self._poll_ms / 1000.0)

    # ── Clipboard capture ─────────────────────────────────────

    def _check_clipboard(self):
        """Capture current clipboard and run pipeline if changed."""
        snapshot = self._capture_clipboard()
        if snapshot.content_type == ClipboardContentType.EMPTY:
            return

        # Skip if content unchanged
        if snapshot.content_hash == self._last_hash:
            return

        self._last_hash = snapshot.content_hash
        self._process_snapshot(snapshot)

    def _capture_clipboard(self) -> ClipboardSnapshot:
        """Read current clipboard — text first, then image."""
        # ── Try text ──────────────────────────────────────────
        try:
            text = pyperclip.paste()
            if text and text.strip():
                # Size guard
                if len(text) > self._max_kb * 1024:
                    text = text[:self._max_kb * 1024]

                snap = ClipboardSnapshot(
                    content_type=ClipboardContentType.TEXT,
                    text=text,
                )
                snap.content_hash = snap.compute_hash()
                return snap
        except Exception:
            pass

        # ── Try image ─────────────────────────────────────────
        if self._vision_enabled:
            try:
                img = ImageGrab.grabclipboard()
                if img is not None:
                    snap = ClipboardSnapshot(
                        content_type=ClipboardContentType.IMAGE,
                        image=img,
                    )
                    snap.content_hash = snap.compute_hash()
                    return snap
            except Exception:
                pass

        return ClipboardSnapshot(
            content_type=ClipboardContentType.EMPTY
        )

    # ── Full detection pipeline ───────────────────────────────

    def _process_snapshot(self, snapshot: ClipboardSnapshot):
        """Run the full detection pipeline on a clipboard snapshot."""
        self._stats["total_scans"] += 1

        # ── Get context ───────────────────────────────────────
        active_process, window_title = self._get_window_context()

        # ── Image path ────────────────────────────────────────
        if snapshot.content_type == ClipboardContentType.IMAGE:
            self._handle_image(snapshot, active_process, window_title)
            return

        text = snapshot.text or ""

        # ── Cache check ───────────────────────────────────────
        cached = self._cache.get(snapshot.content_hash)
        if cached is not None:
            self._stats["cache_hits"] += 1
            is_threat, risk_score = cached
            if not is_threat:
                self._log_and_notify_clean(snapshot, risk_score)
            # If cached threat, do nothing (already handled)
            return

        # ── Layer 1: Fast regex scan ──────────────────────────
        scan_result = self._scanner.scan(text)

        # ── Layer 2: Content classification ───────────────────
        classification = self._classifier.classify(text)

        # ── Layer 3: RAG semantic check ───────────────────────
        rag_result = RAGResult(is_violation=False)
        rag_distance = None

        if self._rag_enabled and self._rag and self._rag.is_ready:
            try:
                rag_result   = self._rag.query(
                    text,
                    policy_groups=classification.policy_groups
                )
                if rag_result.matches:
                    rag_distance = rag_result.best_distance
            except Exception as e:
                print(f"[ClipMgr] RAG query failed: {e}")

        # ── Layer 4: Risk scoring ─────────────────────────────
        risk_score = self._scorer.score(
            scan_result    = scan_result,
            classification = classification,
            active_process = active_process,
            rag_distance   = rag_distance,
        )

        # ── Cache result ──────────────────────────────────────
        is_threat = (
            scan_result.is_threat
            or rag_result.is_violation
            or risk_score.decision != Decision.ALLOW
        )
        self._cache.put(snapshot.content_hash, is_threat, risk_score)

        # ── Route decision ────────────────────────────────────
        if not is_threat:
            self._handle_clean(
                snapshot, scan_result, rag_result,
                risk_score, classification,
                active_process, window_title
            )
        else:
            self._stats["threats_found"] += 1
            self._handle_threat(
                snapshot, scan_result, rag_result,
                risk_score, classification,
                active_process, window_title
            )

    # ── Threat handler ────────────────────────────────────────

    def _handle_threat(
        self,
        snapshot:       ClipboardSnapshot,
        scan_result:    ScanResult,
        rag_result:     RAGResult,
        risk_score:     RiskScore,
        classification: ClassificationResult,
        active_process: str,
        window_title:   str,
    ):
        """
        Threat detected flow:
        1. Substitute clipboard immediately (Substitution Pattern)
        2. Fire UI popup callback
        3. Wait for user decision (Block/Sanitize/Timeout)
        4. Apply decision + log
        """

        # ── Step 1: Substitute clipboard immediately ──────────
        # This prevents the user from pasting sensitive content
        # while the popup is shown.
        if not self._shadow:
            try:
                pyperclip.copy(self.BLOCKED_PLACEHOLDER)
            except Exception as e:
                print(f"[ClipMgr] Clipboard substitution failed: {e}")

        # ── Step 2: Build threat event ────────────────────────
        event = ThreatEvent(
            snapshot       = snapshot,
            scan_result    = scan_result,
            rag_result     = rag_result,
            risk_score     = risk_score,
            classification = classification,
            active_process = active_process,
            window_title   = window_title,
        )

        # ── Step 3: Auto-block CRITICAL (no popup) ────────────
        if risk_score.decision == Decision.BLOCK:
            self._apply_decision(
                UserDecision.BLOCK, event,
                auto=True
            )
            return

        # ── Step 4: Show popup and wait for user decision ─────
        self._decision_event.clear()
        self._pending_decision = None
        self._sanitized_text   = None

        self.pause()   # stop polling while popup is active

        if self.on_threat:
            try:
                self.on_threat(event)
            except Exception as e:
                print(f"[ClipMgr] on_threat callback error: {e}")

        # Wait for UI to call resolve_decision()
        resolved = self._decision_event.wait(
            timeout=self._timeout_sec
        )

        if not resolved:
            self._pending_decision = UserDecision.TIMEOUT

        decision = self._pending_decision or UserDecision.BLOCK
        self._apply_decision(decision, event, auto=not resolved)
        self.resume()

    # ── Decision application ──────────────────────────────────

    def _apply_decision(
        self,
        decision: UserDecision,
        event:    ThreatEvent,
        auto:     bool = False,
    ):
        """Apply user/system decision and log the event."""

        text   = event.snapshot.text or ""
        action = AuditAction.BLOCKED

        if decision == UserDecision.BLOCK or decision == UserDecision.TIMEOUT:
            # Clipboard already substituted — nothing more to do
            action = AuditAction.BLOCKED
            self._stats["blocks"] += 1
            if not self._shadow:
                try:
                    pyperclip.copy(self.BLOCKED_PLACEHOLDER)
                except Exception:
                    pass

        elif decision == UserDecision.SANITIZE:
            action = AuditAction.SANITIZED
            self._stats["sanitizations"] += 1
            sanitized = self._sanitized_text or self._fallback_sanitize(
                text, event.scan_result
            )
            if not self._shadow:
                try:
                    pyperclip.copy(sanitized)
                except Exception:
                    pass

        elif decision == UserDecision.ALLOW:
            action = AuditAction.ALLOWED
            self._stats["allows"] += 1
            if not self._shadow:
                try:
                    pyperclip.copy(text)   # restore original
                except Exception:
                    pass

        # ── Shadow mode override ──────────────────────────────
        if self._shadow:
            action = AuditAction.SHADOW

        # ── Determine threat source ───────────────────────────
        threat_source = AuditThreatSource.NONE
        if event.scan_result.is_threat and event.rag_result.is_violation:
            threat_source = AuditThreatSource.COMBINED
        elif event.scan_result.is_threat:
            threat_source = AuditThreatSource.REGEX
        elif event.rag_result.is_violation:
            threat_source = AuditThreatSource.RAG

        # ── Log event ─────────────────────────────────────────
        self._logger.log_event(
            action             = action,
            risk_score         = event.risk_score.score,
            content_hash       = event.snapshot.content_hash,
            content_length     = len(text),
            threat_types       = event.risk_score.threat_types,
            threat_source      = threat_source,
            content_type       = event.classification.content_type.value,
            top_severity       = (event.risk_score.top_severity.value
                                  if event.risk_score.top_severity else "NONE"),
            violated_policies  = event.rag_result.violated_policies,
            violated_rules     = ([m.rule_id for m in event.rag_result.matches]
                                  if event.rag_result.matches else []),
            redacted_preview   = event.redacted_preview,
            active_process     = event.active_process,
            window_title       = event.window_title,
        )

        mode = "[SHADOW]" if self._shadow else ""
        print(f"[ClipMgr]{mode} {action.value} | "
              f"score:{event.risk_score.score} | "
              f"{event.threat_summary[:50]} | "
              f"proc:{event.active_process}")

    # ── Clean handler ─────────────────────────────────────────

    def _handle_clean(
        self,
        snapshot:       ClipboardSnapshot,
        scan_result:    ScanResult,
        rag_result:     RAGResult,
        risk_score:     RiskScore,
        classification: ClassificationResult,
        active_process: str,
        window_title:   str,
    ):
        """Log clean events (WARN gets logged, ALLOW silently passes)."""

        if risk_score.decision == Decision.WARN:
            self._logger.log_event(
                action         = AuditAction.WARNED,
                risk_score     = risk_score.score,
                content_hash   = snapshot.content_hash,
                content_length = len(snapshot.text or ""),
                threat_types   = risk_score.threat_types,
                threat_source  = AuditThreatSource.REGEX
                                 if scan_result.is_threat
                                 else AuditThreatSource.NONE,
                content_type   = classification.content_type.value,
                top_severity   = (risk_score.top_severity.value
                                  if risk_score.top_severity else "NONE"),
                active_process = active_process,
                window_title   = window_title,
            )

        if self.on_allow:
            self.on_allow(snapshot)

    def _log_and_notify_clean(
        self,
        snapshot:   ClipboardSnapshot,
        risk_score: RiskScore,
    ):
        if self.on_allow:
            self.on_allow(snapshot)

    # ── Image handler ─────────────────────────────────────────

    def _handle_image(
        self,
        snapshot:       ClipboardSnapshot,
        active_process: str,
        window_title:   str,
    ):
        """
        Route clipboard image to Vision AI.
        vision.py will call resolve_decision() with result.
        """
        print(f"[ClipMgr] Image detected — routing to Vision AI")
        # Vision handler is wired externally in main.py
        # This is a hook point for ai/vision.py

    # ── UI resolution API ─────────────────────────────────────

    def resolve_decision(
        self,
        decision:       UserDecision,
        sanitized_text: Optional[str] = None,
    ):
        """
        Called by the UI popup when user clicks Block or Sanitize.
        Unblocks the _decision_event.wait() in _handle_threat().
        """
        self._pending_decision = decision
        self._sanitized_text   = sanitized_text
        self._decision_event.set()

    # ── Fallback sanitizer (no AI) ────────────────────────────

    def _fallback_sanitize(
        self,
        text:        str,
        scan_result: ScanResult,
    ) -> str:
        """
        Offline fallback: regex-replace matched regions with
        [REDACTED: ThreatType] when Gemini is unavailable.
        """
        result = text
        # Process in reverse order to preserve offsets
        for match in sorted(
            scan_result.matches,
            key=lambda m: m.start,
            reverse=True
        ):
            tag = f"[REDACTED: {match.threat_type.value}]"
            result = result[:match.start] + tag + result[match.end:]
        return result

    # ── Context capture ───────────────────────────────────────

    def _get_window_context(self) -> tuple[str, str]:
        """Get active window process name + title."""
        try:
            from core.context_capture import get_context_capture
            ctx = get_context_capture()
            info = ctx.capture()
            return info.process_name, info.window_title
        except Exception:
            return "", ""

    # ── Demo mode ─────────────────────────────────────────────

    def _inject_demo_payload(self):
        """Inject test payloads cyclically for live demos."""
        payload = self._demo_payloads[
            self._demo_index % len(self._demo_payloads)
        ]
        self._demo_index += 1

        content_hash = hashlib.sha256(
            payload.encode()
        ).hexdigest()

        if content_hash == self._last_hash:
            return

        self._last_hash = content_hash
        snap = ClipboardSnapshot(
            content_type  = ClipboardContentType.TEXT,
            text          = payload,
            content_hash  = content_hash,
        )
        self._process_snapshot(snap)
        time.sleep(5)   # 5 second gap between demo events

    # ── Stats + status ────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        return self._running

    def get_stats(self) -> dict:
        return {**self._stats, "cache_size": self._cache.size}

    def status(self) -> dict:
        return {
            "running":        self._running,
            "paused":         self._paused,
            "shadow_mode":    self._shadow,
            "demo_mode":      self._demo,
            "poll_interval":  self._poll_ms,
            "rag_enabled":    self._rag_enabled,
            "vision_enabled": self._vision_enabled,
            "stats":          self.get_stats(),
        }


# ── Module-level singleton ────────────────────────────────────

_clip_mgr_instance: Optional[ClipboardManager] = None

def get_clipboard_manager(config: dict = None) -> ClipboardManager:
    global _clip_mgr_instance
    if _clip_mgr_instance is None:
        cfg = config or {}
        sentinel = cfg.get("sentinel", {})
        _clip_mgr_instance = ClipboardManager(
            poll_interval_ms  = sentinel.get("poll_interval_ms", 500),
            shadow_mode       = sentinel.get("shadow_mode",      False),
            demo_mode         = sentinel.get("demo_mode",        False),
            popup_timeout_sec = cfg.get("ui", {}).get(
                                    "popup_timeout_seconds", 30),
            max_clipboard_kb  = cfg.get("thresholds", {}).get(
                                    "max_clipboard_size_kb", 512),
            config            = cfg,
        )
    return _clip_mgr_instance


# ── Self-test ─────────────────────────────────────────────────

if __name__ == "__main__":
    import json

    print(f"\n{'='*60}")
    print(f"  Blip Sentinel — ClipboardManager Self-Test")
    print(f"{'='*60}\n")

    # Load config
    try:
        with open("./config/settings.json") as f:
            config = json.load(f)
    except Exception:
        config = {}

    # Initialize audit logger first
    logger = get_audit_logger()
    logger.initialize()

    # Initialize RAG
    rag = get_rag_engine()
    rag.initialize()

    # Track events for test
    threats_seen = []
    clean_seen   = []

    def on_threat(event: ThreatEvent):
        threats_seen.append(event)
        print(f"\n  [THREAT DETECTED]")
        print(f"    Summary  : {event.threat_summary}")
        print(f"    Score    : {event.risk_score.score}/100 "
              f"({event.risk_score.decision.value})")
        print(f"    Type     : {event.classification.label}")
        print(f"    Preview  : {event.redacted_preview}")
        print(f"    Policy   : {event.top_policy}")

        # Auto-resolve with BLOCK for test
        mgr.resolve_decision(UserDecision.BLOCK)

    def on_allow(snapshot: ClipboardSnapshot):
        clean_seen.append(snapshot)

    # Create manager
    mgr = ClipboardManager(
        poll_interval_ms = 500,
        shadow_mode      = True,    # dry-run for test
        rag_enabled      = True,
    )
    mgr.on_threat = on_threat
    mgr.on_allow  = on_allow

    print("  Running pipeline on test payloads...\n")

    # Manually process test snapshots
    test_payloads = [
        "Hello world — clean text, no threats here.",
        "aws_access_key_id=AKIAIOSFODNN7EXAMPLE",
        "My Aadhaar: 2345 6789 0123",
        "postgresql://admin:secret@db.internal/prod",
        "SELECT * FROM users WHERE id = 1",
    ]

    for payload in test_payloads:
        snap = ClipboardSnapshot(
            content_type=ClipboardContentType.TEXT,
            text=payload,
        )
        snap.content_hash = snap.compute_hash()
        print(f"  Testing: {payload[:50]}...")
        mgr._process_snapshot(snap)
        time.sleep(0.1)

    print(f"\n  Results:")
    print(f"    Total scanned : {mgr._stats['total_scans']}")
    print(f"    Threats found : {mgr._stats['threats_found']}")
    print(f"    Cache hits    : {mgr._stats['cache_hits']}")
    print(f"    Blocks        : {mgr._stats['blocks']}")

    print(f"\n  Audit log entries: {logger.entry_count}")
    valid, msg = logger.verify_chain()
    print(f"  Chain integrity : {msg}")

    print(f"\n{'='*60}\n")