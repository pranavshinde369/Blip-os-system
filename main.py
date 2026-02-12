import os
import sys
from core.monitor import start_monitoring

def main():
    print("=========================================")
    print("   🛡️  BLIP ENDPOINT SENTINEL v1.0   ")
    print("   GovTech & Enterprise Security Agent   ")
    print("=========================================")
    
    # Check for .env
    if not os.path.exists(".env"):
        print("⚠️  WARNING: .env file not found.")
        print("   Enterprise AI features may not work.")
        print("   Please create .env with GEMINI_API_KEY=...")
        print("=========================================")

    # Ensure logs folder exists
    if not os.path.exists("logs"):
        os.makedirs("logs")

    # Start the Core Monitor
    try:
        start_monitoring()
    except KeyboardInterrupt:
        print("\n👋 Blip Shutting Down. Stay Safe.")
        sys.exit(0)

if __name__ == "__main__":
    main()