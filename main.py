# ============================================================
# BLIP ENDPOINT SENTINEL — main.py
# Daemon Entry Point + Watchdog + CLI
#
# Usage:
#   python main.py                  # normal mode
#   python main.py --shadow         # dry-run (log only, no blocks)
#   python main.py --demo           # inject test payloads every 5s
#   python main.py --dashboard      # open admin dashboard only
#   python main.py --verify-chain   # check audit log integrity
#   python main.py --reindex        # rebuild RAG policy index
# ============================================================

import argparse
import json
import os
import signal
import sys
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Splash ────────────────────────────────────────────────────

BANNER = r"""
  ██████╗ ██╗     ██╗██████╗
  ██╔══██╗██║     ██║██╔══██╗
  ██████╔╝██║     ██║██████╔╝
  ██╔══██╗██║     ██║██╔═══╝
  ██████╔╝███████╗██║██║
  ╚═════╝ ╚══════╝╚═╝╚═╝   ENDPOINT SENTINEL v1.0.0

  Enterprise DLP — DPDP Act Compliant
  Built for SAMVED 2026 Hackathon
"""


# ── Config loader ─────────────────────────────────────────────

def load_config(path: str = "./config/settings.json") -> dict:
    """Load and validate master config."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        print(f"[Main] Config loaded from {path}")
        return cfg
    except FileNotFoundError:
        print(f"[Main] Config not found at {path} — using defaults")
        return {}
    except json.JSONDecodeError as e:
        print(f"[Main] Config parse error: {e} — using defaults")
        return {}


# ── Startup checks ────────────────────────────────────────────

def run_startup_checks() -> bool:
    """
    Verify all required directories and dependencies exist.
    Returns True if all checks pass.
    """
    print("[Main] Running startup checks...")

    checks = [
        ("Config dir",        Path("./config")),
        ("Policies dir",      Path("./config/policies")),
        ("Data dir",          Path("./data")),
        ("Logs dir",          Path("./data/logs")),
        ("ChromaDB dir",      Path("./data/chroma_db")),
    ]

    all_ok = True
    for label, path in checks:
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
            print(f"  [+] Created {label}: {path}")
        else:
            print(f"  [✓] {label}: {path}")

    # Check Python version
    if sys.version_info < (3, 10):
        print("  [✗] Python 3.10+ required")
        all_ok = False
    else:
        print(f"  [✓] Python {sys.version_info.major}."
              f"{sys.version_info.minor}")

    # Check critical imports
    critical_imports = [
        ("pyperclip",               "pyperclip"),
        ("customtkinter",           "customtkinter"),
        ("chromadb",                "chromadb"),
        ("sentence_transformers",   "sentence-transformers"),
        ("cryptography",            "cryptography"),
        ("google.generativeai",     "google-generativeai"),
    ]

    for module, pkg in critical_imports:
        try:
            __import__(module)
            print(f"  [✓] {pkg}")
        except ImportError:
            print(f"  [✗] {pkg} not installed — run: "
                  f"pip install {pkg}")
            all_ok = False

    return all_ok


# ── Module initializer ────────────────────────────────────────

class SentinelCore:
    """
    Orchestrates initialization and lifecycle of all modules.
    Single source of truth for the running daemon.
    """

    def __init__(self, config: dict, args: argparse.Namespace):
        self._config  = config
        self._args    = args
        self._running = False

        # Module handles
        self._logger   = None
        self._rag      = None
        self._sanitizer = None
        self._clip_mgr  = None
        self._popup     = None
        self._dashboard = None

        # Watchdog
        self._watchdog_thread: Optional[threading.Thread] = None
        self._heartbeat_time  = time.time()

    # ── Init all modules ──────────────────────────────────────

    def initialize(self) -> bool:
        """Initialize all modules in dependency order."""
        print("\n[Main] Initializing modules...\n")

        # ── 1. Audit Logger ───────────────────────────────────
        print("[Main] [1/5] Audit Logger...")
        from security.audit_logger import get_audit_logger
        self._logger = get_audit_logger(
            config={
                "log_path": self._config.get("audit", {}).get(
                    "log_path", "./data/logs/threats.json.enc"),
                "key_path": self._config.get("audit", {}).get(
                    "key_path", "./config/sentinel.key"),
                "user_id":  self._config.get("user", {}).get(
                    "user_id", "user@company.com"),
                "hostname": self._config.get("user", {}).get(
                    "hostname", "WORKSTATION-01"),
            }
        )
        if not self._logger.initialize():
            print("[Main] Audit logger failed — cannot continue")
            return False
        print(f"[Main]   ✓ Audit logger ready "
              f"({self._logger.entry_count} existing entries)")

        # ── 2. RAG Engine ─────────────────────────────────────
        print("[Main] [2/5] RAG Engine...")
        from core.rag_engine import get_rag_engine
        rag_cfg = self._config.get("rag", {})
        self._rag = get_rag_engine()
        # Re-init with config values
        from core.rag_engine import RAGEngine
        self._rag = RAGEngine(
            policies_dir        = "./config/policies",
            chroma_dir          = rag_cfg.get(
                "chroma_persist_dir", "./data/chroma_db"),
            collection_name     = rag_cfg.get(
                "collection_name", "company_policies"),
            model_name          = rag_cfg.get(
                "model_name", "all-MiniLM-L6-v2"),
            distance_threshold  = self._config.get(
                "thresholds", {}).get("rag_distance_flag", 0.45),
            top_k               = rag_cfg.get("top_k_results", 3),
        )
        rag_ok = self._rag.initialize()
        if rag_ok:
            print(f"[Main]   ✓ RAG engine ready "
                  f"({self._rag.chunk_count} chunks)")
        else:
            print("[Main]   ⚠ RAG engine failed — "
                  "continuing without semantic matching")

        # ── 3. AI Sanitizer ───────────────────────────────────
        print("[Main] [3/5] AI Sanitizer...")
        from ai.sanitizer import get_sanitizer, SurgicalSanitizer
        ai_cfg = self._config.get("ai", {})
        api_key = ai_cfg.get("gemini_api_key", "")
        if api_key == "YOUR_GEMINI_API_KEY_HERE":
            api_key = None
        self._sanitizer = SurgicalSanitizer(
            api_key          = api_key,
            model_name       = ai_cfg.get(
                "gemini_text_model", "gemini-1.5-flash"),
            timeout_sec      = ai_cfg.get(
                "gemini_timeout_seconds", 10),
            offline_fallback = ai_cfg.get(
                "offline_fallback", True),
        )
        san_ok = self._sanitizer.initialize()
        if san_ok:
            print("[Main]   ✓ Gemini AI sanitizer ready")
        else:
            print("[Main]   ⚠ Gemini unavailable — "
                  "offline regex fallback active")

        # ── 4. Clipboard Manager ──────────────────────────────
        print("[Main] [4/5] Clipboard Manager...")
        from core.clipboard_mgr import (
            ClipboardManager, get_clipboard_manager
        )
        sentinel_cfg = self._config.get("sentinel", {})
        self._clip_mgr = ClipboardManager(
            poll_interval_ms  = sentinel_cfg.get(
                "poll_interval_ms", 500),
            shadow_mode       = (self._args.shadow or
                sentinel_cfg.get("shadow_mode", False)),
            demo_mode         = (self._args.demo or
                sentinel_cfg.get("demo_mode", False)),
            popup_timeout_sec = self._config.get(
                "ui", {}).get("popup_timeout_seconds", 30),
            max_clipboard_kb  = self._config.get(
                "thresholds", {}).get(
                    "max_clipboard_size_kb", 512),
            rag_enabled       = rag_ok,
            config            = self._config,
        )
        # Inject our RAG instance
        self._clip_mgr._rag    = self._rag
        self._clip_mgr._logger = self._logger
        print("[Main]   ✓ Clipboard manager ready")

        # ── 5. UI Layer ───────────────────────────────────────
        print("[Main] [5/5] UI Layer...")
        from ui.intervention_popup import get_popup
        self._popup = get_popup()

        # Wire popup callback to clipboard manager
        self._clip_mgr.on_threat = self._on_threat
        self._clip_mgr.on_allow  = self._on_allow
        self._clip_mgr.on_error  = self._on_error
        print("[Main]   ✓ UI layer ready")

        print("\n[Main] All modules initialized ✓\n")
        return True

    # ── Threat callback ───────────────────────────────────────

    def _on_threat(self, event):
        """
        Called by ClipboardManager when threat detected.
        Shows intervention popup and routes decision back.
        """
        from core.clipboard_mgr import UserDecision

        self._heartbeat_time = time.time()

        # Log to console
        score  = event.risk_score.score
        dec    = event.risk_score.decision.value
        label  = event.threat_summary[:50]
        print(f"\n[THREAT] score:{score} | {dec} | {label}")
        print(f"         type:{event.classification.label} | "
              f"proc:{event.active_process}")

        # Show popup — popup calls resolve_decision on the
        # clipboard manager when user clicks Block/Sanitize
        def _on_decision(decision: UserDecision,
                         sanitized_text: str = None):
            self._clip_mgr.resolve_decision(decision, sanitized_text)
            self._send_alert_if_critical(event)

        self._popup.show(
            event       = event,
            on_decision = _on_decision,
            timeout_sec = self._config.get("ui", {}).get(
                "popup_timeout_seconds", 30),
        )

    def _on_allow(self, snapshot):
        """Called on clean clipboard content."""
        self._heartbeat_time = time.time()

    def _on_error(self, error: Exception):
        """Called on unexpected daemon errors."""
        print(f"\n[ERROR] {type(error).__name__}: {error}")
        traceback.print_exc()

    # ── Admin alerting ────────────────────────────────────────

    def _send_alert_if_critical(self, event):
        """Fire admin notification for BLOCK-level events."""
        from core.risk_scorer import Decision
        if event.risk_score.decision != Decision.BLOCK:
            return
        try:
            from security.notifier import send_alert
            send_alert(
                subject = (f"[SENTINEL] CRITICAL: "
                           f"{event.threat_summary[:40]}"),
                body    = (
                    f"User:     {self._config.get('user',{}).get('user_id','?')}\n"
                    f"Score:    {event.risk_score.score}/100\n"
                    f"Threats:  {event.threat_summary}\n"
                    f"Process:  {event.active_process}\n"
                    f"Type:     {event.classification.label}\n"
                    f"Time:     {datetime.now().isoformat()}\n"
                ),
                config  = self._config,
            )
        except Exception as e:
            print(f"[Main] Alert failed: {e}")

    # ── Daemon start ──────────────────────────────────────────

    def start(self):
        """Start the clipboard polling daemon."""
        self._running = True
        self._clip_mgr.start()
        self._start_watchdog()

        mode = ""
        if self._args.shadow:
            mode = "  [SHADOW MODE — logging only, no blocks]"
        if self._args.demo:
            mode = "  [DEMO MODE — injecting test payloads]"

        print(f"[Main] Daemon running.{mode}")
        print(f"[Main] Press Ctrl+C to stop.\n")

    def stop(self):
        """Graceful shutdown."""
        print("\n[Main] Shutting down...")
        self._running = False
        if self._clip_mgr:
            self._clip_mgr.stop()
        print(f"[Main] Final stats: "
              f"{self._clip_mgr.get_stats() if self._clip_mgr else {}}")
        print("[Main] Goodbye.")

    # ── Watchdog ──────────────────────────────────────────────

    def _start_watchdog(self):
        """
        Background watchdog thread.
        Restarts clipboard polling if it dies unexpectedly.
        Also handles periodic log rotation.
        """
        def _watch():
            rotation_counter = 0
            while self._running:
                time.sleep(30)
                rotation_counter += 1

                # ── Heartbeat check ───────────────────────────
                stale_sec = time.time() - self._heartbeat_time
                if stale_sec > 120 and self._clip_mgr:
                    print("[Watchdog] Heartbeat stale "
                          f"({stale_sec:.0f}s) — restarting poller")
                    try:
                        self._clip_mgr.stop()
                        time.sleep(1)
                        self._clip_mgr.start()
                        self._heartbeat_time = time.time()
                    except Exception as e:
                        print(f"[Watchdog] Restart failed: {e}")

                # ── Log rotation (every ~6h) ──────────────────
                if rotation_counter % 720 == 0 and self._logger:
                    try:
                        self._logger.rotate_if_needed()
                    except Exception as e:
                        print(f"[Watchdog] Rotation error: {e}")

                # ── Policy hot-reload check ───────────────────
                if rotation_counter % 120 == 0 and self._rag:
                    try:
                        self._check_policy_reload()
                    except Exception as e:
                        print(f"[Watchdog] Policy check error: {e}")

        self._watchdog_thread = threading.Thread(
            target=_watch,
            name="BlipSentinel-Watchdog",
            daemon=True,
        )
        self._policy_mtime = self._get_policy_mtime()
        self._watchdog_thread.start()
        print("[Main] Watchdog started")

    def _get_policy_mtime(self) -> float:
        """Get latest mtime across all policy files."""
        try:
            mtimes = [
                p.stat().st_mtime
                for p in Path("./config/policies").glob("*.json")
            ]
            return max(mtimes) if mtimes else 0.0
        except Exception:
            return 0.0

    def _check_policy_reload(self):
        """Reload RAG index if policy files changed."""
        current_mtime = self._get_policy_mtime()
        if current_mtime > self._policy_mtime:
            print("[Main] Policy files changed — reindexing RAG...")
            self._rag.reindex()
            self._policy_mtime = current_mtime
            print("[Main] Policy reindex complete")

    # ── Status report ─────────────────────────────────────────

    def print_status(self):
        """Print current daemon status to console."""
        stats = self._clip_mgr.get_stats() if self._clip_mgr else {}
        print(f"\n{'='*55}")
        print(f"  BLIP SENTINEL STATUS")
        print(f"{'='*55}")
        print(f"  Running:      {self._running}")
        print(f"  Shadow mode:  {self._args.shadow}")
        print(f"  Demo mode:    {self._args.demo}")
        print(f"  RAG chunks:   "
              f"{self._rag.chunk_count if self._rag else 0}")
        print(f"  Log entries:  "
              f"{self._logger.entry_count if self._logger else 0}")
        print(f"  Scans total:  {stats.get('total_scans', 0)}")
        print(f"  Threats:      {stats.get('threats_found', 0)}")
        print(f"  Cache hits:   {stats.get('cache_hits', 0)}")
        print(f"  Blocks:       {stats.get('blocks', 0)}")
        print(f"  Sanitized:    {stats.get('sanitizations', 0)}")
        print(f"{'='*55}\n")


# ── CLI commands ──────────────────────────────────────────────

def cmd_verify_chain(config: dict):
    """Verify audit log hash chain integrity."""
    from security.audit_logger import AuditLogger
    audit_cfg = config.get("audit", {})
    logger    = AuditLogger(
        log_path = audit_cfg.get(
            "log_path", "./data/logs/threats.json.enc"),
        key_path = audit_cfg.get(
            "key_path", "./config/sentinel.key"),
    )
    logger.initialize()
    valid, msg = logger.verify_chain()
    stats      = logger.get_stats()

    print(f"\n{'='*55}")
    print(f"  Audit Log Chain Verification")
    print(f"{'='*55}")
    print(f"  Result:    {'✓ VALID' if valid else '✗ TAMPERED'}")
    print(f"  Message:   {msg}")
    print(f"  Entries:   {stats['total']}")
    print(f"  Blocked:   {stats['blocked']}")
    print(f"  Sanitized: {stats['sanitized']}")
    print(f"  Top threats: {stats['top_threats']}")
    print(f"{'='*55}\n")
    sys.exit(0 if valid else 1)


def cmd_reindex(config: dict):
    """Rebuild RAG policy index from scratch."""
    from core.rag_engine import RAGEngine
    rag_cfg = config.get("rag", {})
    engine  = RAGEngine(
        policies_dir       = "./config/policies",
        chroma_dir         = rag_cfg.get(
            "chroma_persist_dir", "./data/chroma_db"),
        distance_threshold = config.get(
            "thresholds", {}).get("rag_distance_flag", 0.45),
    )
    engine.initialize()
    count = engine.reindex()
    print(f"\n[Reindex] Done — {count} chunks indexed\n")
    sys.exit(0)


def cmd_dashboard(config: dict):
    """Launch admin dashboard standalone."""
    from security.audit_logger import get_audit_logger
    logger = get_audit_logger(config.get("audit", {}))
    logger.initialize()

    from ui.admin_dashboard import AdminDashboard
    dash = AdminDashboard()
    print("[Main] Launching admin dashboard...")
    dash.launch_blocking()
    sys.exit(0)


def cmd_status(config: dict):
    """Print status of all modules."""
    print(f"\n{'='*55}")
    print(f"  BLIP SENTINEL — Module Status Check")
    print(f"{'='*55}")

    # Audit log
    from security.audit_logger import AuditLogger
    audit_cfg = config.get("audit", {})
    logger    = AuditLogger(
        log_path = audit_cfg.get(
            "log_path", "./data/logs/threats.json.enc"),
        key_path = audit_cfg.get(
            "key_path", "./config/sentinel.key"),
    )
    logger.initialize()
    stats = logger.get_stats()
    print(f"  Audit Logger: ✓  ({stats['total']} entries)")

    # RAG
    from core.rag_engine import RAGEngine
    rag_cfg = config.get("rag", {})
    rag     = RAGEngine(
        policies_dir = "./config/policies",
        chroma_dir   = rag_cfg.get(
            "chroma_persist_dir", "./data/chroma_db"),
    )
    rag.initialize()
    print(f"  RAG Engine:   ✓  ({rag.chunk_count} chunks)")

    # Scanner
    from core.scanner import get_scanner
    scanner = get_scanner()
    print(f"  Scanner:      ✓  ({scanner.rule_count} rules)")

    print(f"{'='*55}\n")
    sys.exit(0)


# ── Argument parser ───────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="blip_sentinel",
        description="Blip Endpoint Sentinel — Enterprise DLP Daemon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                   Start the daemon normally
  python main.py --shadow          Dry-run: log without blocking
  python main.py --demo            Demo mode: inject test payloads
  python main.py --dashboard       Open admin dashboard only
  python main.py --verify-chain    Verify audit log integrity
  python main.py --reindex         Rebuild RAG policy index
  python main.py --status          Show module status
        """
    )
    p.add_argument("--shadow",       action="store_true",
                   help="Shadow/dry-run mode — log only, no blocks")
    p.add_argument("--demo",         action="store_true",
                   help="Demo mode — inject test threat payloads")
    p.add_argument("--dashboard",    action="store_true",
                   help="Launch admin dashboard only")
    p.add_argument("--verify-chain", action="store_true",
                   help="Verify audit log hash chain")
    p.add_argument("--reindex",      action="store_true",
                   help="Rebuild RAG vector index from policies")
    p.add_argument("--status",       action="store_true",
                   help="Print module status and exit")
    p.add_argument("--config",       type=str,
                   default="./config/settings.json",
                   help="Path to settings.json")
    return p


# ── Entry point ───────────────────────────────────────────────

def main():
    print(BANNER)

    # ── Parse args ────────────────────────────────────────────
    parser = build_parser()
    args   = parser.parse_args()

    # ── Load config ───────────────────────────────────────────
    config = load_config(args.config)

    # ── CLI-only commands ─────────────────────────────────────
    if args.verify_chain:
        cmd_verify_chain(config)

    if args.reindex:
        cmd_reindex(config)

    if args.dashboard:
        cmd_dashboard(config)

    if args.status:
        cmd_status(config)

    # ── Startup checks ────────────────────────────────────────
    if not run_startup_checks():
        print("\n[Main] Startup checks failed — fix errors above")
        sys.exit(1)

    # ── Build core ────────────────────────────────────────────
    sentinel = SentinelCore(config, args)

    if not sentinel.initialize():
        print("[Main] Initialization failed — exiting")
        sys.exit(1)

    # ── Signal handlers ───────────────────────────────────────
    def _handle_signal(sig, frame):
        print(f"\n[Main] Signal {sig} received")
        sentinel.print_status()
        sentinel.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    # ── Start daemon ──────────────────────────────────────────
    sentinel.start()

    # ── Keep main thread alive ────────────────────────────────
    # Print status every 60 seconds
    tick = 0
    while True:
        time.sleep(1)
        tick += 1
        if tick % 60 == 0:
            sentinel.print_status()


# ── Run ───────────────────────────────────────────────────────

if __name__ == "__main__":
    main()