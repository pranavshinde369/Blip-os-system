import time
import pyperclip
import sys
import os

from PIL import ImageGrab

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.config import settings
from core.patterns import scan_text
from core.ai_engine import sanitize_text, analyze_image_for_sensitive_text, explain_threat
from core.rag_engine import get_rag_engine  # Enterprise RAG (optional)
from core.policy import apply_policy
from ui.popup import show_alert
from plyer import notification
from utils.logger import log_incident


def _notify(title: str, message: str, timeout: int = 2) -> None:
    """
    Wrapper around plyer notifications that respects config flags.
    """
    if settings.SHOW_TOASTS:
        try:
            notification.notify(title=title, message=message, timeout=timeout)
        except Exception:
            # Notifications are best-effort; don't crash the agent if they fail.
            pass


def start_monitoring():
    mode_label = "ENTERPRISE (AI + RAG)" if settings.is_enterprise else "STANDARD (Offline Regex)"
    print(f"🛡️  Blip Endpoint Sentinel Active in {mode_label} mode... (Press Ctrl+C to Stop)")

    # Initialize RAG Engine only in Enterprise mode (can take 2–3 seconds)
    rag = get_rag_engine() if settings.is_enterprise else None

    last_paste = ""
    last_image_signature = None  # (size, mode) to avoid re-scanning same screenshot

    try:
        while True:
            # ---------- TEXT CLIPBOARD PIPELINE ----------
            try:
                current_paste = pyperclip.paste()
            except Exception:
                current_paste = ""

            if current_paste != last_paste and current_paste.strip() != "":

                last_paste = current_paste

                # --- CHECK 1: Fast Regex (Identity/Keys) ---
                threat = scan_text(current_paste)

                # --- CHECK 2: Enterprise RAG (Code Leakage, Enterprise mode only) ---
                if not threat and settings.is_enterprise and rag is not None:
                    is_leak, reason = rag.check_for_leaks(current_paste)
                    if is_leak:
                        threat = {
                            "type": "🚫 PROPRIETARY CODE LEAK",
                            "description": reason,
                            "risk_level": "CRITICAL",
                            "source": "text",
                        }

                if threat:
                    # Enrich with policy decisions
                    threat = apply_policy(threat)

                    print(f"⚠️  THREAT DETECTED: {threat['type']}")

                    # LOG-only threats are recorded but do not interrupt the user.
                    if threat.get("policy_enforcement") == "LOG":
                        log_incident(
                            threat["type"],
                            threat["description"],
                            "LOGGED",
                            extra={
                                "risk_level": threat.get("risk_level"),
                                "source": threat.get("source", "text"),
                                "policy_enforcement": threat.get("policy_enforcement"),
                            },
                        )
                        continue

                    user_action = ["PENDING"]

                    def on_block():
                        print("❌ BLOCKED")
                        pyperclip.copy("")
                        user_action[0] = "BLOCKED"
                        log_incident(
                            threat["type"],
                            threat["description"],
                            "BLOCKED",
                            extra={
                                "risk_level": threat.get("risk_level"),
                                "source": threat.get("source", "text"),
                                "policy_enforcement": threat.get("policy_enforcement"),
                            },
                        )
                        _notify(title="Blip", message="Blocked by Security Policy.", timeout=2)

                    def on_allow():
                        print("✅ ALLOWED")
                        user_action[0] = "ALLOWED"
                        log_incident(
                            threat["type"],
                            threat["description"],
                            "ALLOWED",
                            extra={
                                "risk_level": threat.get("risk_level"),
                                "source": threat.get("source", "text"),
                                "policy_enforcement": threat.get("policy_enforcement"),
                            },
                        )

                    def on_sanitize():
                        # In STANDARD mode we promise sovereign/offline behavior,
                        # so we do not call Gemini at all.
                        if not settings.is_enterprise:
                            print("🚫 SANITIZE unavailable in STANDARD mode (offline-only).")
                            user_action[0] = "BLOCKED"
                            log_incident(
                                threat["type"],
                                threat["description"],
                                "SANITIZE_UNAVAILABLE_STANDARD",
                                extra={
                                    "risk_level": threat.get("risk_level"),
                                    "source": threat.get("source", "text"),
                                    "policy_enforcement": threat.get("policy_enforcement"),
                                },
                            )
                            _notify(
                                title="Blip",
                                message="Sanitize is only available in Enterprise mode.",
                                timeout=3,
                            )
                            return

                        # For image-based threats we currently treat SANITIZE
                        # as a safer BLOCK (clipboard wipe), since we cannot
                        # reliably rewrite images in-place.
                        if threat.get("source") == "image":
                            print("🚫 SANITIZE not supported for images. Blocking instead.")
                            pyperclip.copy("")
                            user_action[0] = "BLOCKED"
                            log_incident(
                                threat["type"],
                                threat["description"],
                                "BLOCKED_IMAGE_SANITIZE",
                                extra={
                                    "risk_level": threat.get("risk_level"),
                                    "source": threat.get("source", "image"),
                                    "policy_enforcement": threat.get("policy_enforcement"),
                                },
                            )
                            _notify(
                                title="Blip",
                                message="Image cleared from clipboard for safety.",
                                timeout=3,
                            )
                            return

                        print("✨ SANITIZING...")
                        _notify(title="Blip AI", message="Sanitizing text...", timeout=2)
                        clean_text = sanitize_text(current_paste)
                        pyperclip.copy(clean_text)
                        user_action[0] = "SANITIZED"
                        log_incident(
                            threat["type"],
                            threat["description"],
                            "SANITIZED",
                            extra={
                                "risk_level": threat.get("risk_level"),
                                "source": threat.get("source", "text"),
                                "policy_enforcement": threat.get("policy_enforcement"),
                            },
                        )
                        _notify(title="Blip AI", message="Text Sanitized!", timeout=3)

                    # --- SHOW POPUP ---
                    explanation = ""
                    if settings.is_enterprise and settings.ai_enabled:
                        explanation = explain_threat(
                            threat["type"],
                            threat["description"],
                            source=threat.get("source", "text"),
                        )

                    show_alert(
                        threat_type=threat["type"],
                        threat_desc=threat["description"],
                        on_allow=on_allow,
                        on_block=on_block,
                        on_sanitize=on_sanitize,
                        risk_level=threat.get("risk_level", "MEDIUM"),
                        explanation=explanation or None,
                        policy_enforcement=threat.get("policy_enforcement"),
                    )

                    # Memory Reset Logic
                    if user_action[0] == "BLOCKED":
                        last_paste = ""
                    elif user_action[0] == "SANITIZED":
                        last_paste = pyperclip.paste()

            # ---------- IMAGE CLIPBOARD PIPELINE (ENTERPRISE ONLY) ----------
            if settings.is_enterprise and settings.ai_enabled:
                try:
                    clip_obj = ImageGrab.grabclipboard()
                except Exception:
                    clip_obj = None

                # `grabclipboard` can return an Image, a list of file paths, or None
                image = clip_obj if hasattr(clip_obj, "size") and hasattr(clip_obj, "mode") else None

                if image is not None:
                    signature = (image.size, image.mode)
                    if signature != last_image_signature:
                        last_image_signature = signature

                        is_sensitive, reason = analyze_image_for_sensitive_text(image)
                        if is_sensitive:
                            threat = apply_policy(
                                {
                                "type": "🖼️ SENSITIVE IMAGE CONTENT",
                                "description": reason,
                                "risk_level": "HIGH",
                                "source": "image",
                                }
                            )

                            print(f"⚠️  THREAT DETECTED: {threat['type']}")

                            user_action = ["PENDING"]

                            def on_block_image():
                                print("❌ IMAGE BLOCKED")
                                pyperclip.copy("")
                                user_action[0] = "BLOCKED"
                                log_incident(
                                    threat["type"],
                                    threat["description"],
                                    "BLOCKED",
                                    extra={
                                        "risk_level": threat.get("risk_level"),
                                        "source": threat.get("source", "image"),
                                        "policy_enforcement": threat.get("policy_enforcement"),
                                    },
                                )
                                _notify(
                                    title="Blip",
                                    message="Sensitive image cleared from clipboard.",
                                    timeout=2,
                                )

                            def on_allow_image():
                                print("✅ IMAGE ALLOWED")
                                user_action[0] = "ALLOWED"
                                log_incident(
                                    threat["type"],
                                    threat["description"],
                                    "ALLOWED",
                                    extra={
                                        "risk_level": threat.get("risk_level"),
                                        "source": threat.get("source", "image"),
                                        "policy_enforcement": threat.get("policy_enforcement"),
                                    },
                                )

                            def on_sanitize_image():
                                # Handled as a BLOCK with a clear message.
                                print("🚫 SANITIZE not supported for images. Blocking instead.")
                                pyperclip.copy("")
                                user_action[0] = "BLOCKED"
                                log_incident(
                                    threat["type"],
                                    threat["description"],
                                    "BLOCKED_IMAGE_SANITIZE",
                                    extra={
                                        "risk_level": threat.get("risk_level"),
                                        "source": threat.get("source", "image"),
                                        "policy_enforcement": threat.get("policy_enforcement"),
                                    },
                                )
                                _notify(
                                    title="Blip",
                                    message="Image cleared from clipboard for safety.",
                                    timeout=3,
                                )

                            explanation_img = ""
                            if settings.is_enterprise and settings.ai_enabled:
                                explanation_img = explain_threat(
                                    threat["type"],
                                    threat["description"],
                                    source=threat.get("source", "image"),
                                )

                            show_alert(
                                threat_type=threat["type"],
                                threat_desc=threat["description"],
                                on_allow=on_allow_image,
                                on_block=on_block_image,
                                on_sanitize=on_sanitize_image,
                                risk_level=threat.get("risk_level", "HIGH"),
                                explanation=explanation_img or None,
                                policy_enforcement=threat.get("policy_enforcement"),
                            )

            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n🛑 Monitoring Stopped.")


if __name__ == "__main__":
    start_monitoring()