# gemini_ai.py
import os
import sys
import json
import google.generativeai as genai

# Verifye si yo voye prompt lan
if len(sys.argv) < 2:
    print(json.dumps({"error": "No prompt provided"}))
    sys.exit(1)

prompt = sys.argv[1]

# Configure Gemini API
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

model = genai.GenerativeModel("gemini-1.5-pro")

try:
    response = model.generate_content(prompt)
    result = response.text
    print(json.dumps({"reply": result}))
except Exception as e:
    print(json.dumps({"error": str(e)}))