
from dotenv import load_dotenv
load_dotenv()  # Load environment variables from .env file
import os
from google import genai

# 🔑 Replace with your API key
client = genai.Client(api_key=f"{os.getenv('GENAI_API_KEY')}")


def classify(email, user_context, screenshot_info,urls):
    prompt = f"""
You are a phishing detection classifier.

Analyze the following inputs and determine whether the content is phishing or safe.

INPUT

EMAIL_CONTENT: {email}
USER_CONTEXT: {user_context}
SCREENSHOT_INFO: {screenshot_info}
URLS RECIEVED/FOUND : {urls}

CLASSIFICATION RULES
Classify as PHISHING if there are signs of:
Urgency or pressure (e.g., “act now”, “account will be blocked”)
Suspicious or unknown links
Requests for sensitive information (passwords, OTPs, bank details)
Impersonation of trusted entities (banks, companies, services)
Grammar issues or unusual formatting
If uncertain, always choose PHISHING
Only classify as SAFE if clearly legitimate
OUTPUT FORMAT (STRICT)

Return ONLY one of the following tokens:
PHISHING
SAFE

IMPORTANT CONSTRAINTS
Do NOT explain
Do NOT add punctuation
Do NOT add extra text
Do NOT return JSON
Output must be EXACTLY one word: PHISHING or SAFE
"""

    response = client.models.generate_content(
        model="gemini-3-flash-preview",
        contents=prompt
    )

    result = response.text.strip()

    if "PHISHING" in result.upper():
        return "PHISHING"
    else:
        return "SAFE"

