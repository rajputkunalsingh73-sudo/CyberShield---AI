import json
import os

import requests


SEVERITY_GUIDANCE = {
    "critical": "Critical findings require immediate owner review because the observed condition could create a severe risk if verified in application context.",
    "high": "High findings should be addressed promptly because the observed configuration could materially weaken security if applicable to sensitive routes.",
    "medium": "Medium findings merit planned remediation because this configuration gap may increase risk depending on exposure and application context.",
    "low": "Low findings are generally hardening opportunities and should be addressed as part of routine security maintenance.",
    "info": "Informational observations are context for administrators, not confirmed vulnerabilities on their own.",
}


def analyze_finding(vulnerability):
    evidence = vulnerability.evidence or "No response evidence was recorded."
    base = {
        "explanation": f"{vulnerability.name} is a {vulnerability.category.lower()} issue observed by checking a public response. It does not by itself prove that the website has been compromised.",
        "impact_analysis": vulnerability.impact,
        "evidence_explanation": f"The scanner observed: {evidence}. This is a bounded HTTP-response observation, not proof of exploitation.",
        "remediation": vulnerability.recommendation,
        "priority_explanation": SEVERITY_GUIDANCE.get(vulnerability.severity, SEVERITY_GUIDANCE["info"]),
    }
    api_url = os.getenv("AI_API_URL", "").strip()
    api_key = os.getenv("AI_API_KEY", "").strip()
    model = os.getenv("AI_MODEL", "gpt-4o-mini")
    if not api_url or not api_key:
        base["explanation"] += " This explanation was prepared from the built-in local guidance because no AI provider is configured."
        return base
    payload = {
        "model": model,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": "Explain defensive web-security findings for website owners in plain language. Use only the supplied evidence. Do not give exploitation steps. Return JSON keys explanation, impact_analysis, evidence_explanation, remediation, priority_explanation."},
            {"role": "user", "content": f"Name: {vulnerability.name}\nSeverity: {vulnerability.severity}\nDescription: {vulnerability.description}\nEvidence: {evidence}\nImpact: {vulnerability.impact}\nRecommendation: {vulnerability.recommendation}"},
        ],
        "response_format": {"type": "json_object"},
    }
    try:
        response = requests.post(api_url.rstrip("/") + "/chat/completions", json=payload, headers={"Authorization": f"Bearer {api_key}"}, timeout=(3, 12))
        response.raise_for_status()
        data = response.json()["choices"][0]["message"]["content"]
        parsed = json.loads(data)
        for key in base:
            if isinstance(parsed.get(key), str) and parsed[key].strip():
                base[key] = parsed[key][:4000]
    except (requests.RequestException, ValueError, KeyError, TypeError):
        base["explanation"] += " The configured AI service was unavailable, so local guidance is shown."
    return base
