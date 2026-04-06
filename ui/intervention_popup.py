# ============================================================
# BLIP ENDPOINT SENTINEL — ui/intervention_popup.py
# CustomTkinter Threat Intervention Popup
# Shows on every threat detection — sleek dark overlay
# Displays: Threat Type, Risk Score, Policy Violated
# Buttons: BLOCK | ✨ SANITIZE & PASTE
# ============================================================

import threading
import tkinter as tk
from typing import Callable, Optional

import customtkinter as ctk

from core.clipboard_mgr import ThreatEvent, UserDecision
from core.risk_scorer   import Decision


# ── Theme constants ───────────────────────────────────────────

COLORS = {
    "bg_primary":    "#1a1a2e",
    "bg_secondary":  "#16213e",
    "bg_card":       "#0f3460",
    "accent":        "#6C63FF",
    "accent_hover":  "#5a52e0",
    "danger":        "#e74c3c",
    "danger_hover":  "#c0392b",
    "warning":       "#f39c12",
    "success":       "#2ecc71",
    "sanitize":      "#e67e22",
    "sanitize_hover":"#d35400",
    "text_primary":  "#ffffff",
    "text_secondary":"#a0aec0",
    "text_muted":    "#718096",
    "border":        "#2d3748",
    "score_low":     "#2ecc71",
    "score_med":     "#f39c12",
    "score_high":    "#e67e22",
    "score_crit":    "#e74c3c",
}

DECISION_COLORS = {
    Decision.ALLOW:    COLORS["success"],
    Decision.WARN:     COLORS["warning"],
    Decision.SANITIZE: COLORS["sanitize"],
    Decision.BLOCK:    COLORS["danger"],
}


def _score_color(score: int) -> str:
    if score <= 30:  return COLORS["score_low"]
    if score <= 60:  return COLORS["score_med"]
    if score <= 85:  return COLORS["score_high"]
    return COLORS["score_crit"]


# ── Intervention Popup ────────────────────────────────────────

class InterventionPopup:
    """
    Sleek dark-mode popup shown on threat detection.
    Runs in its own thread — never blocks the daemon.

    Usage:
        popup = InterventionPopup()
        popup.show(event, on_decision_callback)
    """

    def __init__(self):
        self._window:   Optional[ctk.CTk] = None
        self._thread:   Optional[threading.Thread] = None
        self._callback: Optional[Callable] = None
        self._event:    Optional[ThreatEvent] = None

    # ── Public API ────────────────────────────────────────────

    def show(
        self,
        event:       ThreatEvent,
        on_decision: Callable[[UserDecision, Optional[str]], None],
        timeout_sec: int = 30,
    ):
        """
        Show the intervention popup for a threat event.
        on_decision(decision, sanitized_text) called on resolution.
        Thread-safe — can be called from background thread.
        """
        self._event    = event
        self._callback = on_decision

        self._thread = threading.Thread(
            target=self._run_popup,
            args=(event, on_decision, timeout_sec),
            daemon=True,
            name="BlipSentinel-Popup",
        )
        self._thread.start()

    def close(self):
        if self._window:
            try:
                self._window.quit()
                self._window.destroy()
            except Exception:
                pass

    # ── Popup window ──────────────────────────────────────────

    def _run_popup(
        self,
        event:       ThreatEvent,
        on_decision: Callable,
        timeout_sec: int,
    ):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        win = ctk.CTk()
        win.title("🛡️ Blip Sentinel — Threat Detected")
        win.geometry("520x600")
        win.resizable(False, False)
        win.configure(fg_color=COLORS["bg_primary"])
        win.attributes("-topmost", True)
        win.attributes("-alpha", 0.97)

        # Center on screen
        win.update_idletasks()
        sw = win.winfo_screenwidth()
        sh = win.winfo_screenheight()
        x  = (sw - 520) // 2
        y  = (sh - 600) // 2
        win.geometry(f"520x600+{x}+{y}")

        self._window = win

        # ── Decision state ────────────────────────────────────
        decision_made = [False]

        def _resolve(decision: UserDecision, sanitized: str = None):
            if decision_made[0]:
                return
            decision_made[0] = True
            try:
                on_decision(decision, sanitized)
            except Exception as e:
                print(f"[Popup] Callback error: {e}")
            finally:
                win.quit()

        # ── Auto-timeout ──────────────────────────────────────
        remaining = [timeout_sec]

        def _tick():
            if decision_made[0]:
                return
            remaining[0] -= 1
            if remaining[0] <= 0:
                timeout_label.configure(
                    text="⏱ Auto-blocking now..."
                )
                win.after(800, lambda: _resolve(UserDecision.TIMEOUT))
                return
            timeout_label.configure(
                text=f"⏱ Auto-block in {remaining[0]}s"
            )
            win.after(1000, _tick)

        # ── UI Layout ─────────────────────────────────────────
        score  = event.risk_score.score
        dec    = event.risk_score.decision
        color  = _score_color(score)
        d_color = DECISION_COLORS.get(dec, COLORS["danger"])

        # Header strip
        header = ctk.CTkFrame(
            win, fg_color=COLORS["bg_secondary"],
            height=56, corner_radius=0
        )
        header.pack(fill="x")
        header.pack_propagate(False)

        ctk.CTkLabel(
            header,
            text="🛡️  BLIP ENDPOINT SENTINEL",
            font=ctk.CTkFont("Segoe UI", 13, "bold"),
            text_color=COLORS["accent"],
        ).pack(side="left", padx=16, pady=14)

        ctk.CTkLabel(
            header,
            text="DATA LEAK PREVENTED",
            font=ctk.CTkFont("Segoe UI", 10),
            text_color=COLORS["text_muted"],
        ).pack(side="right", padx=16, pady=14)

        # Main card
        card = ctk.CTkFrame(
            win,
            fg_color=COLORS["bg_card"],
            corner_radius=12,
        )
        card.pack(fill="both", expand=True, padx=16, pady=12)

        # ── Risk score ring (simulated with label) ────────────
        score_frame = ctk.CTkFrame(
            card, fg_color="transparent"
        )
        score_frame.pack(pady=(20, 8))

        ctk.CTkLabel(
            score_frame,
            text=str(score),
            font=ctk.CTkFont("Segoe UI", 52, "bold"),
            text_color=color,
        ).pack()

        ctk.CTkLabel(
            score_frame,
            text="RISK SCORE / 100",
            font=ctk.CTkFont("Segoe UI", 10),
            text_color=COLORS["text_muted"],
        ).pack()

        # Decision badge
        ctk.CTkLabel(
            card,
            text=f"  {dec.value}  ",
            font=ctk.CTkFont("Segoe UI", 12, "bold"),
            fg_color=d_color,
            text_color=COLORS["text_primary"],
            corner_radius=6,
        ).pack(pady=(0, 14))

        # Divider
        ctk.CTkFrame(
            card, height=1,
            fg_color=COLORS["border"]
        ).pack(fill="x", padx=20, pady=4)

        # ── Threat details ────────────────────────────────────
        details_frame = ctk.CTkFrame(
            card, fg_color="transparent"
        )
        details_frame.pack(fill="x", padx=20, pady=8)

        def _row(label: str, value: str, val_color: str = None):
            row = ctk.CTkFrame(
                details_frame, fg_color="transparent"
            )
            row.pack(fill="x", pady=3)
            ctk.CTkLabel(
                row,
                text=label,
                font=ctk.CTkFont("Segoe UI", 11),
                text_color=COLORS["text_muted"],
                width=130,
                anchor="w",
            ).pack(side="left")
            ctk.CTkLabel(
                row,
                text=value[:52] if value else "—",
                font=ctk.CTkFont("Segoe UI", 11, "bold"),
                text_color=val_color or COLORS["text_primary"],
                anchor="w",
            ).pack(side="left", fill="x", expand=True)

        _row("Threat Type:",
             event.threat_summary,
             COLORS["danger"])
        _row("Content Type:",
             event.classification.label)
        _row("Severity:",
             event.risk_score.top_severity.value
             if event.risk_score.top_severity else "UNKNOWN",
             color)
        _row("Active Process:",
             event.active_process or "Unknown")
        _row("Policy Violated:",
             event.top_policy,
             COLORS["warning"])

        # Redacted preview
        if event.redacted_preview:
            ctk.CTkFrame(
                card, height=1,
                fg_color=COLORS["border"]
            ).pack(fill="x", padx=20, pady=8)

            ctk.CTkLabel(
                card,
                text="DETECTED CONTENT (redacted)",
                font=ctk.CTkFont("Segoe UI", 9),
                text_color=COLORS["text_muted"],
            ).pack(anchor="w", padx=20)

            preview_box = ctk.CTkTextbox(
                card,
                height=48,
                fg_color=COLORS["bg_secondary"],
                text_color=COLORS["warning"],
                font=ctk.CTkFont("Courier New", 11),
                corner_radius=6,
            )
            preview_box.pack(fill="x", padx=20, pady=4)
            preview_box.insert("1.0", event.redacted_preview)
            preview_box.configure(state="disabled")

        # Signals
        if event.risk_score.breakdown.contributing_signals:
            signals_text = "  •  ".join(
                event.risk_score.breakdown.contributing_signals[:4]
            )
            ctk.CTkLabel(
                card,
                text=signals_text,
                font=ctk.CTkFont("Segoe UI", 9),
                text_color=COLORS["text_muted"],
                wraplength=460,
            ).pack(padx=20, pady=(4, 0))

        # ── Action buttons ────────────────────────────────────
        ctk.CTkFrame(
            card, height=1,
            fg_color=COLORS["border"]
        ).pack(fill="x", padx=20, pady=10)

        btn_frame = ctk.CTkFrame(
            card, fg_color="transparent"
        )
        btn_frame.pack(fill="x", padx=20, pady=(0, 8))

        # BLOCK button
        ctk.CTkButton(
            btn_frame,
            text="🚫  BLOCK",
            font=ctk.CTkFont("Segoe UI", 13, "bold"),
            fg_color=COLORS["danger"],
            hover_color=COLORS["danger_hover"],
            height=44,
            corner_radius=8,
            command=lambda: _resolve(UserDecision.BLOCK),
        ).pack(side="left", expand=True, fill="x", padx=(0, 6))

        # SANITIZE button
        ctk.CTkButton(
            btn_frame,
            text="✨  SANITIZE & PASTE",
            font=ctk.CTkFont("Segoe UI", 13, "bold"),
            fg_color=COLORS["sanitize"],
            hover_color=COLORS["sanitize_hover"],
            height=44,
            corner_radius=8,
            command=lambda: _handle_sanitize(),
        ).pack(side="right", expand=True, fill="x", padx=(6, 0))

        def _handle_sanitize():
            """Trigger AI sanitization then resolve."""
            try:
                from ai.sanitizer import get_sanitizer
                sanitizer = get_sanitizer()
                result    = sanitizer.sanitize(
                    text        = event.snapshot.text or "",
                    scan_result = event.scan_result,
                    rag_result  = event.rag_result,
                )
                _resolve(UserDecision.SANITIZE, result.sanitized_text)
            except Exception as e:
                print(f"[Popup] Sanitize error: {e}")
                _resolve(UserDecision.SANITIZE, None)

        # Timeout label
        timeout_label = ctk.CTkLabel(
            card,
            text=f"⏱ Auto-block in {timeout_sec}s",
            font=ctk.CTkFont("Segoe UI", 10),
            text_color=COLORS["text_muted"],
        )
        timeout_label.pack(pady=(4, 12))

        # Start countdown
        win.after(1000, _tick)

        # Handle window close → treat as block
        win.protocol(
            "WM_DELETE_WINDOW",
            lambda: _resolve(UserDecision.BLOCK)
        )

        win.mainloop()


# ── Module-level singleton ────────────────────────────────────

_popup_instance: Optional[InterventionPopup] = None

def get_popup() -> InterventionPopup:
    global _popup_instance
    if _popup_instance is None:
        _popup_instance = InterventionPopup()
    return _popup_instance