import json
import os
from datetime import datetime

LOG_FILE = os.path.join(os.path.dirname(__file__), '..', 'logs', 'threats.json')

# Ensure logs directory exists
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

def log_incident(threat_type, threat_desc, action):
    """
    Logs a security incident to the JSON file.
    """
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "threat_type": threat_type,
        "description": threat_desc,
        "action_taken": action  # BLOCKED, ALLOWED, SANITIZED
    }

    try:
        # Read existing logs
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                logs = json.load(f)
        else:
            logs = []

        # Add new entry
        logs.append(entry)

        # Write back
        with open(LOG_FILE, 'w') as f:
            json.dump(logs, f, indent=4)
            
        print(f"📝 Logged incident: {action} -> {threat_type}")
        
    except Exception as e:
        print(f"❌ Logging failed: {e}")