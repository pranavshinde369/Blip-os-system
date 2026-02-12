import google.generativeai as genai
import os
from dotenv import load_dotenv

# Load API Key
load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")

if API_KEY:
    genai.configure(api_key=API_KEY)
else:
    print("⚠️  WARNING: GEMINI_API_KEY not found in .env file.")

def sanitize_text(text):
    """
    Uses Google Gemini to remove sensitive info while preserving context.
    Returns: The sanitized string.
    """
    if not API_KEY:
        return "[BLIP ERROR] AI Sanitization unavailable. Missing API Key."

    try:
        model = genai.GenerativeModel('gemini-2.5-flash')
        
        # Strict System Prompt for DLP
        prompt = f"""
        You are a Data Loss Prevention (DLP) security agent.
        
        TASK:
        Sanitize the following text by replacing ANY sensitive information with [REDACTED_TYPE].
        Sensitive info includes: API Keys, Passwords, Credit Card Numbers, Aadhaar IDs, PAN, Emails, Phone Numbers.
        
        RULES:
        1. PRESERVE the original structure and non-sensitive words exactly.
        2. DO NOT add conversational filler (e.g., "Here is the text").
        3. ONLY output the sanitized text.
        
        INPUT TEXT:
        "{text}"
        """
        
        response = model.generate_content(prompt)
        return response.text.strip()
        
    except Exception as e:
        return f"[BLIP ERROR] Sanitization failed: {str(e)}"