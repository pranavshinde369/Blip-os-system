import time
import pyperclip
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.patterns import scan_text
from core.ai_engine import sanitize_text
from core.rag_engine import get_rag_engine # <--- NEW IMPORT
from ui.popup import show_alert
from plyer import notification
from utils.logger import log_incident

def start_monitoring():
    print("🛡️  Blip Endpoint Sentinel Active... (Press Ctrl+C to Stop)")
    
    # Initialize RAG Engine on Startup (Takes 2-3 seconds to load model)
    rag = get_rag_engine() 
    
    last_paste = ""
    
    try:
        while True:
            try:
                current_paste = pyperclip.paste()
            except:
                current_paste = "" 

            if current_paste != last_paste and current_paste.strip() != "":
                
                last_paste = current_paste
                
                # --- CHECK 1: Fast Regex (Identity/Keys) ---
                threat = scan_text(current_paste)
                
                # --- CHECK 2: Enterprise RAG (Code Leakage) ---
                if not threat:
                    is_leak, reason = rag.check_for_leaks(current_paste)
                    if is_leak:
                        threat = {
                            "type": "🚫 PROPRIETARY CODE LEAK",
                            "description": reason,
                            "risk_level": "CRITICAL"
                        }

                if threat:
                    print(f"⚠️  THREAT DETECTED: {threat['type']}")
                    
                    user_action = ["PENDING"] 

                    def on_block():
                        print("❌ BLOCKED")
                        pyperclip.copy("") 
                        user_action[0] = "BLOCKED"
                        log_incident(threat['type'], threat['description'], "BLOCKED")
                        notification.notify(title="Blip", message="Blocked by Enterprise Policy.", timeout=2)

                    def on_allow():
                        print("✅ ALLOWED")
                        user_action[0] = "ALLOWED"
                        log_incident(threat['type'], threat['description'], "ALLOWED")

                    def on_sanitize():
                        print("✨ SANITIZING...")
                        notification.notify(title="Blip AI", message="Sanitizing text...", timeout=2)
                        clean_text = sanitize_text(current_paste)
                        pyperclip.copy(clean_text)
                        user_action[0] = "SANITIZED"
                        log_incident(threat['type'], threat['description'], "SANITIZED")
                        notification.notify(title="Blip AI", message="Text Sanitized!", timeout=3)

                    # --- SHOW POPUP ---
                    show_alert(
                        threat_type=threat['type'],
                        threat_desc=threat['description'],
                        on_allow=on_allow,
                        on_block=on_block,
                        on_sanitize=on_sanitize
                    )
                    
                    # Memory Reset Logic
                    if user_action[0] == "BLOCKED":
                        last_paste = ""
                    elif user_action[0] == "SANITIZED":
                        last_paste = pyperclip.paste()

            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n🛑 Monitoring Stopped.")

if __name__ == "__main__":
    start_monitoring()