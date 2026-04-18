# ============================================================
# BLIP ENDPOINT SENTINEL — core/context_capture.py
# Active Window + Process Name Capture
# ============================================================

from dataclasses import dataclass
from typing import Optional


@dataclass
class WindowContext:
    process_name: str = ""
    window_title: str = ""


class ContextCapture:
    """Captures active window context for audit enrichment."""

    def capture(self) -> WindowContext:
        ctx = WindowContext()
        try:
            import psutil
            import pygetwindow as gw
            wins = gw.getActiveWindow()
            if wins:
                ctx.window_title = wins.title[:100]

            # Get process from psutil
            import subprocess
            result = subprocess.run(
                ["powershell", "-command",
                 "Get-Process | Where-Object {$_.MainWindowTitle -ne ''} "
                 "| Select-Object -First 1 -ExpandProperty Name"],
                capture_output=True, text=True, timeout=2
            )
            if result.stdout.strip():
                ctx.process_name = (
                    result.stdout.strip().lower() + ".exe"
                )
        except Exception:
            pass
        return ctx


_ctx_instance: Optional[ContextCapture] = None

def get_context_capture() -> ContextCapture:
    global _ctx_instance
    if _ctx_instance is None:
        _ctx_instance = ContextCapture()
    return _ctx_instance