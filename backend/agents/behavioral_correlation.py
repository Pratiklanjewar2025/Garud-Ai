"""
GARUD-AI Agent 2 — Behavioral Correlation Agent
Correlates static and dynamic evidence to build a comprehensive behavioral profile.
"""
import json
import logging
from agents import get_llm, call_llm_json

logger = logging.getLogger("garud_ai.agents.behavioral_correlation")

AGENT_NAME  = "behavioral_correlation"
AGENT_LABEL = "Behavioral Correlation Agent"
AGENT_INDEX = 2


def run(features: dict, dynamic_data: dict) -> dict:
    """
    Input: feature vector + dynamic analysis data
    Output: behavioral profile with correlated behaviors
    """
    llm = get_llm()

    behaviors_list = []
    if dynamic_data:
        for cat in ["sms_behaviors", "contact_behaviors", "file_behaviors", "network_behaviors", "screen_behaviors", "ui_behaviors"]:
            behaviors_list.extend(dynamic_data.get(cat, []))

    capabilities = {
        "intercept_sms":    dynamic_data.get("can_intercept_sms", False) if dynamic_data else False,
        "harvest_contacts": dynamic_data.get("can_harvest_contacts", False) if dynamic_data else False,
        "overlay_attack":   dynamic_data.get("can_record_screen", False) if dynamic_data else False,
        "keylogging":       dynamic_data.get("can_keylog", False) if dynamic_data else False,
        "data_exfiltration":dynamic_data.get("can_exfiltrate_data", False) if dynamic_data else False,
        "device_control":   dynamic_data.get("can_control_device", False) if dynamic_data else False,
        "send_sms":         dynamic_data.get("can_send_sms", False) if dynamic_data else False,
    }

    active_caps = [k for k, v in capabilities.items() if v]

    prompt = f"""You are the GARUD-AI Behavioral Correlation Agent — an expert in Android malware behavior analysis.

Analyze the correlated static and dynamic behaviors for this APK:

ACTIVE CAPABILITIES: {json.dumps(active_caps, indent=2)}
OBSERVED BEHAVIORS: {json.dumps([b.get("behavior", b) if isinstance(b, dict) else b for b in behaviors_list[:10]], indent=2)}
PERMISSION RISK SCORE: {features.get("permission_risk_score", 0)}/100
API CALL EVIDENCE: suspicious_count={features.get("suspicious_api_count", 0)}
CROSS-LAYER CORRELATION SCORE: {features.get("correlation_score", 0)}/100

Respond ONLY with a valid JSON object:
{{
  "behavioral_profile": "One sentence describing the app's behavioral archetype",
  "primary_attack_vector": "Main attack method (e.g. 'SMS OTP theft + overlay phishing')",
  "behaviors_confirmed": ["behavior 1", "behavior 2"],
  "kill_chain": ["Step 1 in attack chain", "Step 2", "Step 3"],
  "severity": "LOW | MEDIUM | HIGH | CRITICAL",
  "reasoning": ["Evidence point 1", "Evidence point 2", "Evidence point 3"],
  "confidence": 80
}}"""

    fallback = _heuristic_behavioral(features, capabilities, behaviors_list)
    result = call_llm_json(llm, prompt, fallback)
    logger.info(f"Behavioral Correlation: profile={result.get('behavioral_profile', 'N/A')[:50]}")
    return result


def _heuristic_behavioral(features, capabilities, behaviors):
    active = [k.replace("_", " ").title() for k, v in capabilities.items() if v]
    kill_chain = []
    if capabilities.get("intercept_sms") and capabilities.get("overlay_attack"):
        kill_chain = [
            "1. App installs and requests accessibility + overlay permissions",
            "2. Monitors for banking app launch via AccessibilityEvent",
            "3. Displays phishing overlay to capture credentials",
            "4. Intercepts OTP SMS to complete unauthorized transaction"
        ]
    elif capabilities.get("harvest_contacts") and capabilities.get("data_exfiltration"):
        kill_chain = [
            "1. App installs and requests contact/SMS/storage permissions",
            "2. Silently harvests contacts, SMS history, and media",
            "3. Encodes and exfiltrates collected data to remote server",
            "4. Data used for fraud, identity theft, or extortion"
        ]
    profile = "Standard application" if not active else f"{', '.join(active[:3])} capability application"
    severity = "CRITICAL" if len(active) >= 4 else "HIGH" if len(active) >= 2 else "MEDIUM" if active else "LOW"
    return {
        "behavioral_profile": profile,
        "primary_attack_vector": ", ".join(active[:2]) or "None detected",
        "behaviors_confirmed": [b.get("behavior", str(b)) if isinstance(b, dict) else str(b) for b in behaviors[:4]],
        "kill_chain": kill_chain or ["Insufficient evidence to construct kill chain"],
        "severity": severity,
        "reasoning": [f"Detected {len(active)} active malicious capabilities"],
        "confidence": min(len(active) * 15 + 20, 85)
    }
