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
    
    # Gemini API Key (Required for Enterprise Mode)
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    
    # Severity Levels
    LEVEL_HIGH = "HIGH"   # Block Immediately (Aadhaar, Keys)
    LEVEL_MEDIUM = "MEDIUM" # Warn User (PII, Emails)
    
    # Notification Settings
    SHOW_TOASTS = True

# Global Instance
settings = Config()