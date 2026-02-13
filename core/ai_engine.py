import json
from typing import Tuple

import google.generativeai as genai
from PIL.Image import Image as PILImage

from core.config import settings

# Lazy-initialized global model instance
_MODEL = None


if settings.GEMINI_API_KEY:
    # Configure Gemini only when a key is present
    genai.configure(api_key=settings.GEMINI_API_KEY)
else:
    # This warning will typically only matter in Enterprise mode;
    # STANDARD mode is designed to run fully offline.
    print("⚠️  WARNING: GEMINI_API_KEY not found in .env file.")


def _get_model():
    """
    Returns a singleton GenerativeModel instance to avoid re-creating it
    for every sanitization / analysis call.
    """
    global _MODEL
    if _MODEL is None:
        _MODEL = genai.GenerativeModel("gemini-2.5-flash")
    return _MODEL


def sanitize_text(text: str) -> str:
    """
    Uses Google Gemini to remove sensitive info while preserving context.
    Returns: The sanitized string, or a clear error message on failure.
    """
    # Extra guard so that even if the caller forgets, we never call AI
    # when Enterprise mode / API key are not correctly configured.
    if not settings.ai_enabled:
        return "[BLIP ERROR] AI Sanitization unavailable. Enterprise mode or API key not configured."

    try:
        model = _get_model()

        # Strict System Prompt for DLP
        prompt = f"""
        You are a Data Loss Prevention (DLP) security agent.

        TASK:
        Sanitize the following text by replacing ANY sensitive information with [REDACTED_TYPE].
        Sensitive info includes: API Keys, Passwords, Credit Card Numbers, Aadhaar IDs, PAN, Emails, Phone Numbers.

        RULES:
        1. PRESERVE the original structure and non-sensitive words exactly.
        2. DO NOT add conversational filler (e.g., "Here is the text").
        3. ONLY output the sanitized text.

        INPUT TEXT:
        \"\"\"{text}\"\"\"
        """

        response = model.generate_content(prompt)
        return (response.text or "").strip()

    except Exception as e:
        return f"[BLIP ERROR] Sanitization failed: {str(e)}"


def analyze_image_for_sensitive_text(image: PILImage) -> Tuple[bool, str]:
    """
    Uses Gemini Vision to inspect an image (e.g., screenshot of a document or code)
    and determine if it contains sensitive textual content.

    Returns:
        (is_sensitive, reason)
    """
    if not settings.ai_enabled:
        return False, "AI analysis disabled (STANDARD mode or missing API key)."

    try:
        model = _get_model()

        prompt = """
        You are a Data Loss Prevention (DLP) security agent.

        Look at this image and decide if it contains any sensitive textual information,
        such as Aadhaar / PAN numbers, bank or UPI details, passwords, API keys,
        confidential internal documents, or proprietary source code / algorithms.

        Respond with EXACTLY one line of JSON:
        {"sensitive": true/false, "reason": "<short reason>"}
        """

        response = model.generate_content([prompt, image])
        raw = (response.text or "").strip()

        # Strip optional markdown code fences if the model adds them
        if raw.startswith("```"):
            raw = raw.strip("`")
            if raw.lower().startswith("json"):
                raw = raw[4:].strip()

        try:
            parsed = json.loads(raw)
        except Exception:
            # Fallback: if JSON parsing fails, do a very simple heuristic
            lowered = raw.lower()
            if "true" in lowered and "sensitive" in lowered:
                return True, raw
            return False, raw

        is_sensitive = bool(parsed.get("sensitive", False))
        reason = str(parsed.get("reason", raw))
        return is_sensitive, reason

    except Exception as e:
        # Fail open (no block) but return reason for logging/debugging.
        return False, f"Image analysis failed: {e}"


def explain_threat(threat_type: str, description: str, source: str = "text") -> str:
    """
    Asks Gemini to generate a short, developer-friendly explanation and safe alternative
    for a given threat. Enterprise mode only.

    Returns a short markdown string, or an empty string if unavailable.
    """
    if not settings.ai_enabled:
        return ""

    try:
        model = _get_model()

        prompt = f"""
        You are a security assistant explaining Data Loss Prevention alerts
        to developers and knowledge workers.

        THREAT TYPE: {threat_type}
        SOURCE: {source}
        DETECTION DETAIL: {description}

        TASK:
        1. Briefly explain WHY this content is risky in 1–2 sentences.
        2. Propose a SAFE ALTERNATIVE in 1–2 sentences (how they can share safely).

        RULES:
        - Speak in plain English, very concise.
        - Address the user directly ("you").
        - Do NOT repeat the original secret.
        - Output in this exact format:

        Why unsafe: <one short paragraph>
        Safe alternative: <one short paragraph>
        """

        response = model.generate_content(prompt)
        return (response.text or "").strip()
    except Exception:
        return ""