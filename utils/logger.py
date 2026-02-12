import json
import os
from datetime import datetime

LOG_FILE = os.path.join(os.path.dirname(__file__), '..', 'logs', 'threats.json')

# Ensure logs directory exists
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

def log_incident(threat_type, threat_desc, action):
    """
    Logs a security incident to the JSON file safely.
    """
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "threat_type": threat_type,
        "description": threat_desc,
        "action_taken": action
    }

    try:
        logs = []
        # 1. Try to read existing logs
        if os.path.exists(LOG_FILE):
            try:
                with open(LOG_FILE, 'r') as f:
                    content = f.read().strip()
                    if content:  # Only load if file is not empty
                        logs = json.loads(content)
            except json.JSONDecodeError:
                print("⚠️  Log file corrupted. Starting fresh.")
                logs = [] # Reset if corrupted

        # 2. Add new entry
        logs.append(entry)

        # 3. Write back safely
        with open(LOG_FILE, 'w') as f:
            json.dump(logs, f, indent=4)
            
        print(f"📝 Logged incident: {action} -> {threat_type}")
        
    except Exception as e:
        print(f"❌ Logging failed: {e}")