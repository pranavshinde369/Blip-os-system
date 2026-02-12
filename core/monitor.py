import time
import pyperclip
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.patterns import scan_text
from core.ai_engine import sanitize_text
from ui.popup import show_alert
from plyer import notification

def start_monitoring():
    print("🛡️  Blip Endpoint Sentinel Active... (Press Ctrl+C to Stop)")
    
    last_paste = ""
    
    try:
        while True:
            try:
                current_paste = pyperclip.paste()
            except:
                current_paste = "" 

            if current_paste != last_paste and current_paste.strip() != "":
                
                last_paste = current_paste
                threat = scan_text(current_paste)
                
                if threat:
                    print(f"⚠️  THREAT DETECTED: {threat['type']}")
                    
                    user_action = ["PENDING"] 

                    # --- HANDLERS ---
                    def on_block():
                        print("❌ BLOCKED")
                        pyperclip.copy("") 
                        user_action[0] = "BLOCKED"
                        notification.notify(title="Blip", message="Blocked.", timeout=2)

                    def on_allow():
                        print("✅ ALLOWED")
                        user_action[0] = "ALLOWED"

                    def on_sanitize():
                        print("✨ SANITIZING...")
                        notification.notify(title="Blip AI", message="Sanitizing text...", timeout=2)
                        
                        # 1. Call AI
                        clean_text = sanitize_text(current_paste)
                        
                        # 2. Update Clipboard
                        pyperclip.copy(clean_text)
                        
                        # 3. Update Memory so we don't re-flag the clean text
                        user_action[0] = "SANITIZED"
                        
                        notification.notify(title="Blip AI", message="Text Sanitized & Ready to Paste!", timeout=3)

                    # --- SHOW POPUP ---
                    show_alert(
                        threat_type=threat['type'],
                        threat_desc=threat['description'],
                        on_allow=on_allow,
                        on_block=on_block,
                        on_sanitize=on_sanitize
                    )
                    
                    # --- MEMORY RESET FIX ---
                    # If we blocked OR sanitized, we must allow the user to copy the same thing again if they really want to.
                    # But if they sanitized, 'last_paste' is now the clean text (handled by OS clipboard update).
                    if user_action[0] == "BLOCKED":
                        last_paste = ""
                    elif user_action[0] == "SANITIZED":
                        last_paste = pyperclip.paste() # Update memory to the new clean text

            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n🛑 Monitoring Stopped.")

if __name__ == "__main__":
    start_monitoring()