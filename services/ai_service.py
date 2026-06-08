# ============================================================
# AegisRecon AI — Ollama Integration (Optional)
# ============================================================

import requests
import json
from config import Config

def generate_ai_summary(findings, risk_score, target):
    if not Config.OLLAMA_ENABLED:
        return "AI summary disabled. Enable OLLAMA_ENABLED=true in environment."

    prompt = f"""
    You are a cybersecurity expert. Generate a short professional summary for a vulnerability scan.

    Target: {target}
    Risk Score: {risk_score.get('overall_score', 0)}/100 ({risk_score.get('risk_level')})
    Key Findings: {len(findings)} findings

    Summarize in 3-4 sentences: overall risk, main issues, and recommendations.
    Keep it professional and concise.
    """

    try:
        response = requests.post(
            f"{Config.OLLAMA_BASE_URL}/api/generate",
            json={
                "model": Config.OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False
            },
            timeout=Config.OLLAMA_TIMEOUT
        )
        if response.status_code == 200:
            return response.json().get("response", "AI summary not available.")
        return "AI service unavailable."
    except:
        return "Could not connect to Ollama. Make sure Ollama is running locally."