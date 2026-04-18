# ============================================================
# sentinel_watch.py
# STANDALONE CLIPBOARD WATCHER — NO SETUP NEEDED
# Just run this, then copy anything sensitive.
# Popup fires within 0.5 seconds.
#
# Run: python sentinel_watch.py
# ============================================================

import hashlib
import re
import threading
import time
import tkinter as tk
from tkinter import ttk
import pyperclip

# ══════════════════════════════════════════════════════════════
# ALL DETECTION PATTERNS
# ══════════════════════════════════════════════════════════════

PATTERNS = [
    # India PII
    ("Aadhaar Number",      "CRITICAL",
     re.compile(r'\b[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b')),

    ("PAN Card",            "CRITICAL",
     re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b')),

    ("GSTIN",               "HIGH",
     re.compile(r'\b[0-3][0-9][A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b')),

    ("IFSC Code",           "MEDIUM",
     re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b')),

    ("Indian Phone",        "MEDIUM",
     re.compile(r'(?:\+91|0091|0)[\s\-]?[6-9]\d{9}\b')),

    ("Bank Account",        "HIGH",
     re.compile(r'(?i)(?:account[\s\-]?(?:no|number|num)[\s:]*)\d{9,18}\b')),

    ("Passport (IN)",       "HIGH",
     re.compile(r'\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b')),

    # Cloud secrets
    ("AWS Access Key",      "CRITICAL",
     re.compile(r'\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b')),

    ("AWS Secret Key",      "CRITICAL",
     re.compile(r'(?i)aws_secret[_\-]?(?:access[_\-]?)?key\s*[=:]\s*\S{20,}')),

    ("RSA Private Key",     "CRITICAL",
     re.compile(r'-----BEGIN\s(?:RSA\s)?PRIVATE KEY-----', re.I)),

    ("SSH Private Key",     "CRITICAL",
     re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----', re.I)),

    ("JWT Token",           "HIGH",
     re.compile(r'\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+')),

    ("Generic API Key",     "HIGH",
     re.compile(r'(?i)(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token'
                r'|auth[_\-]?token|bearer)\s*[=:]\s*[A-Za-z0-9_\-]{20,}')),

    # Database
    ("DB Connection String","CRITICAL",
     re.compile(r'(?i)(?:mongodb|postgresql|mysql|redis|mssql)'
                r'(?:\+\w+)?://[^\s]{10,}')),

    # Financial
    ("Credit Card",         "CRITICAL",
     re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?'
                r'|5[1-5][0-9]{14}'
                r'|3[47][0-9]{13})\b')),

    # Network
    ("Internal IP",         "MEDIUM",
     re.compile(r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
                r'|192\.168\.\d{1,3}\.\d{1,3})\b')),

    # Hindi PII
    ("Hindi/Devanagari PII","MEDIUM",
     re.compile(r'[\u0900-\u097F]{3,}(?:\s+[\u0900-\u097F]{2,}){1,}',
                re.UNICODE)),
]

SEVERITY_SCORE = {
    "CRITICAL": 45,
    "HIGH":     32,
    "MEDIUM":   20,
    "LOW":       8,
}

SEVERITY_COLOR = {
    "CRITICAL": "#e74c3c",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f39c12",
    "LOW":      "#2ecc71",
}

BLOCKED_TEXT = (
    "⚠️ [BLOCKED BY BLIP SENTINEL]\n"
    "Sensitive content was intercepted.\n"
    "Contact admin if this is a mistake."
)


# ══════════════════════════════════════════════════════════════
# SCANNER
# ══════════════════════════════════════════════════════════════

def scan(text: str) -> list[dict]:
    """Return list of all matches found."""
    matches = []
    seen    = set()
    for label, severity, pattern in PATTERNS:
        for m in pattern.finditer(text[:50_000]):
            if label not in seen:
                matches.append({
                    "label":    label,
                    "severity": severity,
                    "matched":  m.group(0)[:60],
                    "start":    m.start(),
                    "end":      m.end(),
                    "score":    SEVERITY_SCORE[severity],
                })
                seen.add(label)
    return matches


def risk_score(matches: list[dict]) -> int:
    base = sum(m["score"] for m in matches)
    if len(matches) > 1:
        base += 10   # multi-threat bonus
    return min(base, 100)


def redact(text: str, matches: list[dict]) -> str:
    """Replace each matched region with [REDACTED: label]."""
    result = text
    for m in sorted(matches, key=lambda x: x["start"], reverse=True):
        tag    = f"[REDACTED: {m['label']}]"
        result = result[:m["start"]] + tag + result[m["end"]:]
    return result


# ══════════════════════════════════════════════════════════════
# POPUP
# ══════════════════════════════════════════════════════════════

class ThreatPopup:
    """
    Instant dark-mode popup.
    Shows threat details + BLOCK / SANITIZE & PASTE buttons.
    """

    def __init__(
        self,
        original_text: str,
        matches:       list[dict],
        score:         int,
        on_block:      callable,
        on_sanitize:   callable,
    ):
        self._original  = original_text
        self._matches   = matches
        self._score     = score
        self._on_block  = on_block
        self._on_sanitize = on_sanitize
        self._decided   = False
        self._countdown = 20

    def show(self):
        """Build and run the popup window."""
        root = tk.Tk()
        root.title("🛡️ Blip Sentinel — Threat Intercepted")
        root.configure(bg="#1a1a2e")
        root.resizable(False, False)
        root.attributes("-topmost", True)
        root.attributes("-alpha",   0.97)

        # ── Window size + center ──────────────────────────────
        W, H = 500, 560 + max(0, len(self._matches) - 1) * 26
        root.geometry(f"{W}x{H}")
        root.update_idletasks()
        x = (root.winfo_screenwidth()  - W) // 2
        y = (root.winfo_screenheight() - H) // 2
        root.geometry(f"{W}x{H}+{x}+{y}")

        top_sev   = self._matches[0]["severity"] if self._matches else "HIGH"
        top_color = SEVERITY_COLOR.get(top_sev, "#e67e22")
        score_col = (
            "#2ecc71" if self._score <= 30 else
            "#f39c12" if self._score <= 60 else
            "#e67e22" if self._score <= 85 else
            "#e74c3c"
        )

        # ── Header ────────────────────────────────────────────
        hdr = tk.Frame(root, bg="#16213e", height=52)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(
            hdr,
            text="🛡️  BLIP ENDPOINT SENTINEL",
            bg="#16213e", fg="#6C63FF",
            font=("Segoe UI", 12, "bold"),
        ).pack(side="left", padx=16, pady=12)
        tk.Label(
            hdr,
            text="DATA LEAK INTERCEPTED",
            bg="#16213e", fg="#718096",
            font=("Segoe UI", 9),
        ).pack(side="right", padx=16)

        # ── Score ─────────────────────────────────────────────
        tk.Label(
            root,
            text=str(self._score),
            bg="#1a1a2e", fg=score_col,
            font=("Segoe UI", 56, "bold"),
        ).pack(pady=(18, 0))
        tk.Label(
            root,
            text="RISK SCORE / 100",
            bg="#1a1a2e", fg="#718096",
            font=("Segoe UI", 9),
        ).pack()

        dec_text = (
            "HARD BLOCK" if self._score > 85 else
            "SANITIZE"   if self._score > 60 else
            "WARN"
        )
        tk.Label(
            root,
            text=f"  {dec_text}  ",
            bg=score_col, fg="white",
            font=("Segoe UI", 11, "bold"),
            relief="flat",
        ).pack(pady=8)

        # ── Divider ───────────────────────────────────────────
        tk.Frame(root, bg="#2d3748", height=1).pack(fill="x", padx=20)

        # ── Threat rows ───────────────────────────────────────
        card = tk.Frame(root, bg="#0f3460")
        card.pack(fill="x", padx=18, pady=10)

        for m in self._matches:
            row = tk.Frame(card, bg="#0f3460")
            row.pack(fill="x", padx=12, pady=3)

            tk.Label(
                row,
                text=f"⚠  {m['label']}",
                bg="#0f3460",
                fg=SEVERITY_COLOR.get(m["severity"], "#e67e22"),
                font=("Segoe UI", 10, "bold"),
                width=24,
                anchor="w",
            ).pack(side="left")

            tk.Label(
                row,
                text=f"[{m['severity']}]",
                bg="#0f3460", fg="#718096",
                font=("Segoe UI", 9),
                width=10,
                anchor="w",
            ).pack(side="left")

            # Redacted preview
            raw     = m["matched"]
            preview = _make_preview(raw, m["label"])
            tk.Label(
                row,
                text=preview,
                bg="#0f3460", fg="#f39c12",
                font=("Courier New", 9),
                anchor="w",
            ).pack(side="left", fill="x", expand=True)

        # ── Clipboard preview box ─────────────────────────────
        tk.Frame(root, bg="#2d3748", height=1).pack(fill="x", padx=20, pady=6)
        tk.Label(
            root,
            text="CLIPBOARD CONTENT (first 120 chars)",
            bg="#1a1a2e", fg="#718096",
            font=("Segoe UI", 8),
        ).pack(anchor="w", padx=22)

        preview_text = self._original.strip()[:120].replace("\n", " ↵ ")
        tk.Label(
            root,
            text=preview_text,
            bg="#16213e", fg="#a0aec0",
            font=("Courier New", 9),
            wraplength=454,
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=22, pady=4)

        # ── Buttons ───────────────────────────────────────────
        tk.Frame(root, bg="#2d3748", height=1).pack(fill="x", padx=20, pady=8)

        btn_frame = tk.Frame(root, bg="#1a1a2e")
        btn_frame.pack(fill="x", padx=20)

        def _do_block():
            if self._decided:
                return
            self._decided = True
            self._on_block()
            root.destroy()

        def _do_sanitize():
            if self._decided:
                return
            self._decided = True
            sanitized = redact(self._original, self._matches)
            self._on_sanitize(sanitized)
            root.destroy()

        tk.Button(
            btn_frame,
            text="🚫  BLOCK",
            bg="#e74c3c", fg="white",
            activebackground="#c0392b",
            font=("Segoe UI", 12, "bold"),
            relief="flat", bd=0,
            height=2, cursor="hand2",
            command=_do_block,
        ).pack(side="left", expand=True, fill="x", padx=(0, 6))

        tk.Button(
            btn_frame,
            text="✨  SANITIZE & PASTE",
            bg="#e67e22", fg="white",
            activebackground="#d35400",
            font=("Segoe UI", 12, "bold"),
            relief="flat", bd=0,
            height=2, cursor="hand2",
            command=_do_sanitize,
        ).pack(side="right", expand=True, fill="x", padx=(6, 0))

        # ── Countdown ─────────────────────────────────────────
        countdown_var = tk.StringVar(value=f"⏱  Auto-block in {self._countdown}s")
        tk.Label(
            root,
            textvariable=countdown_var,
            bg="#1a1a2e", fg="#718096",
            font=("Segoe UI", 9),
        ).pack(pady=10)

        def _tick():
            if self._decided:
                return
            self._countdown -= 1
            if self._countdown <= 0:
                countdown_var.set("⏱  Blocking now...")
                root.after(600, _do_block)
                return
            countdown_var.set(f"⏱  Auto-block in {self._countdown}s")
            root.after(1000, _tick)

        root.after(1000, _tick)
        root.protocol("WM_DELETE_WINDOW", _do_block)
        root.mainloop()


def _make_preview(raw: str, label: str) -> str:
    """Safe display — never show full sensitive value."""
    if "Aadhaar" in label:
        digits = re.sub(r'[\s\-]', '', raw)
        return f"XXXX-XXXX-{digits[-4:]}"
    if "PAN" in label:
        return f"{raw[:3]}XXXXXXX"
    if "Credit" in label:
        digits = re.sub(r'[\s\-]', '', raw)
        return f"XXXX-XXXX-XXXX-{digits[-4:]}"
    if "AWS Access" in label:
        return f"{raw[:4]}{'*'*12}{raw[-4:]}"
    if "Private Key" in label:
        return "-----BEGIN KEY----- [REDACTED]"
    if "JWT" in label:
        return f"{raw[:14]}...[JWT]"
    if len(raw) > 10:
        return f"{raw[:4]}{'*' * min(len(raw)-4, 12)}"
    return "*" * len(raw)


# ══════════════════════════════════════════════════════════════
# CLIPBOARD WATCHER
# ══════════════════════════════════════════════════════════════

class ClipboardWatcher:
    """
    Polls clipboard every 400ms.
    On threat detected → substitutes clipboard → shows popup.
    """

    POLL_MS = 400

    def __init__(self):
        self._last_hash  = ""
        self._running    = False
        self._popup_open = False

    def start(self):
        self._running = True
        print(f"\n{'='*55}")
        print(f"  🛡️  BLIP SENTINEL — Watching Clipboard")
        print(f"  Copy anything sensitive to trigger the popup.")
        print(f"  Press Ctrl+C to stop.")
        print(f"{'='*55}\n")

        # Spin poll on background thread
        t = threading.Thread(target=self._poll, daemon=True)
        t.start()

        # Keep main thread alive
        try:
            while self._running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            self._running = False
            print("\n\n  Sentinel stopped. Goodbye.\n")

    def _poll(self):
        while self._running:
            try:
                if not self._popup_open:
                    self._check()
            except Exception as e:
                print(f"  [Poll error] {e}")
            time.sleep(self.POLL_MS / 1000)

    def _check(self):
        try:
            text = pyperclip.paste()
        except Exception:
            return

        if not text or not text.strip():
            return

        h = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
        if h == self._last_hash:
            return
        self._last_hash = h

        matches = scan(text)
        if not matches:
            print(f"  [CLEAN]  {text[:60].strip()!r}")
            return

        score = risk_score(matches)
        names = ", ".join(m["label"] for m in matches)
        print(f"\n  [THREAT] score:{score}  →  {names}")
        print(f"           {text[:60].strip()!r}")

        # Substitute clipboard immediately
        try:
            pyperclip.copy(BLOCKED_TEXT)
        except Exception:
            pass

        # Show popup on main thread via flag
        self._popup_open = True
        self._show_popup(text, matches, score)

    def _show_popup(
        self,
        original: str,
        matches:  list[dict],
        score:    int,
    ):
        def _on_block():
            print(f"  [BLOCK]     clipboard cleared")
            try:
                pyperclip.copy(BLOCKED_TEXT)
            except Exception:
                pass
            self._popup_open = False

        def _on_sanitize(sanitized: str):
            print(f"  [SANITIZE]  redacted + pasted")
            try:
                pyperclip.copy(sanitized)
            except Exception:
                pass
            self._popup_open = False

        popup = ThreatPopup(
            original_text = original,
            matches       = matches,
            score         = score,
            on_block      = _on_block,
            on_sanitize   = _on_sanitize,
        )
        popup.show()


# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    watcher = ClipboardWatcher()
    watcher.start()