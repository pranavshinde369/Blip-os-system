# test_step3.py
from ui.popup import show_alert

def handle_block():
    print("❌ Action: BLOCKED. Clipboard wiped.")

def handle_allow():
    print("✅ Action: ALLOWED. User accepted risk.")

print("Launching Popup Test...")

# Simulate a threat
show_alert(
    threat_type="Aadhaar Number",
    threat_desc="Indian National ID (UIDAI) pattern detected. Sharing this violates DPDP Act 2023.",
    on_allow=handle_allow,
    on_block=handle_block
)

print("Popup closed.")