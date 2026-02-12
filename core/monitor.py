import time
import pyperclip
from patterns import scan_text
from plyer import notification

def start_monitoring():
    """
    Main loop that monitors the system clipboard for sensitive data.
    """
    print("🛡️  Blip Endpoint Sentinel Active... (Press Ctrl+C to Stop)")
    
    last_paste = ""
    
    try:
        while True:
            # 1. Get current clipboard content
            try:
                current_paste = pyperclip.paste()
            except Exception:
                current_paste = "" # Handle clipboard access errors gracefully

            # 2. Only process if content changed & isn't empty
            if current_paste != last_paste and current_paste.strip() != "":
                last_paste = current_paste
                
                # 3. SCAN for Threats (Standard Mode)
                threat = scan_text(current_paste)
                
                if threat:
                    print(f"⚠️  THREAT DETECTED: {threat['type']} ({threat['description']})")
                    
                    # --- ACTION: WIPE CLIPBOARD ---
                    pyperclip.copy("") 
                    
                    # --- ACTION: NOTIFY USER ---
                    notification.notify(
                        title="Blip Security Alert",
                        message=f"Blocked: {threat['type']} detected on clipboard.",
                        app_name="Blip Sentinel",
                        timeout=5
                    )
                    
            # 4. Sleep to prevent high CPU usage
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n🛑 Monitoring Stopped.")

if __name__ == "__main__":
    start_monitoring()