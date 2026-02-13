# core/config.py

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    APP_NAME = "Blip Endpoint Sentinel"
    VERSION = "1.0.0"
    
    # Modes: "STANDARD" (Local Only) or "ENTERPRISE" (AI Powered)
    DEFAULT_MODE = "STANDARD"
    # Can be overridden via environment: BLIP_MODE=STANDARD|ENTERPRISE
    MODE = os.getenv("BLIP_MODE", DEFAULT_MODE).upper()
    
    # Gemini API Key (Required for Enterprise Mode)
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    
    # Severity Levels
    LEVEL_HIGH = "HIGH"   # Block Immediately (Aadhaar, Keys)
    LEVEL_MEDIUM = "MEDIUM" # Warn User (PII, Emails)
    
    # Notification Settings
    # Can be overridden via BLIP_SHOW_TOASTS=true|false
    SHOW_TOASTS = os.getenv("BLIP_SHOW_TOASTS", "true").lower() == "true"

    @property
    def is_enterprise(self) -> bool:
        """
        Returns True when running in Enterprise (AI + RAG) mode.
        """
        return self.MODE == "ENTERPRISE"

    @property
    def ai_enabled(self) -> bool:
        """
        Enterprise mode with a valid Gemini API key.
        """
        return self.is_enterprise and bool(self.GEMINI_API_KEY)

# Global Instance
settings = Config()