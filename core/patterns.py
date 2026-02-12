# core/patterns.py
import re

# ==========================================
# 🛡️ BHARAT & DEV DEFENSE PATTERNS
# ==========================================
PATTERNS = {
    # --- A. NATIONAL IDENTITY (GovTech) ---
    "Aadhaar Number": {
        "regex": r"\b[2-9]{1}[0-9]{3}\s[0-9]{4}\s[0-9]{4}\b", 
        "desc": "Indian National ID (UIDAI)",
        "risk": "HIGH"
    },
    "PAN Card": {
        "regex": r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
        "desc": "Permanent Account Number (Tax ID)",
        "risk": "HIGH"
    },
    "GSTIN": {
        "regex": r"\b\d{2}[A-Z]{5}\d{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}\b",
        "desc": "GST Identification Number",
        "risk": "MEDIUM"
    },
    "Indian Mobile": {
        "regex": r"\b(\+91[\-\s]?)?[6-9]\d{9}\b",
        "desc": "Indian Mobile Number",
        "risk": "MEDIUM"
    },

    # --- B. DEVELOPER SECRETS (Startup India) ---
    "AWS Access Key": {
        "regex": r"(AKIA[0-9A-Z]{16})",
        "desc": "AWS Identity Access Key",
        "risk": "HIGH"
    },
    "Google API Key": {
        "regex": r"(AIza[0-9A-Za-z\\-_]{35})",
        "desc": "Google Cloud/Maps/Gemini Key",
        "risk": "HIGH"
    },
    "Private Key Block": {
        "regex": r"-----BEGIN (RSA|DSA|EC|OPENSSH|PRIVATE) KEY-----",
        "desc": "Cryptographic Private Key",
        "risk": "CRITICAL"
    },
    "Generic Database URL": {
        "regex": r"(postgres|mysql|mongodb|redis)://[a-zA-Z0-9]+:[a-zA-Z0-9]+@",
        "desc": "Database Connection String with Password",
        "risk": "HIGH"
    }
}

def scan_text(text):
    """
    Scans the provided text against all patterns.
    Returns a dict with threat details if found, else None.
    """
    if not text or len(text) > 100000:
        return None

    for name, data in PATTERNS.items():
        if re.search(data["regex"], text):
            return {
                "type": name,
                "description": data["desc"],
                "risk_level": data["risk"]
            }
    
    return None