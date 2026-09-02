"""
GARUD-AI Agent 1 — Threat Reasoning Agent
Analyzes all static and behavioral evidence to form an overall threat assessment.
"""
import json
import logging
from agents import get_llm, call_llm_json

logger = logging.getLogger("garud_ai.agents.threat_reasoning")

AGENT_NAME  = "threat_reasoning"
AGENT_LABEL = "Threat Reasoning Agent"
AGENT_INDEX = 1


def run(features: dict) -> dict:
    """
    Input: correlated feature vector
    Output: threat_assessment, reasoning bullets, confidence
    """
    llm = get_llm()
    package   = features.get("package_name", "Unknown")
    perms     = features.get("key_permissions", [])
    signals   = [s["description"] for s in features.get("risk_signals", [])]
    behaviors = [
        features.get("can_intercept_sms") and "Can intercept SMS/OTP messages",
        features.get("can_harvest_contacts") and "Can harvest device contacts",
        features.get("can_overlay") and "Can display phishing overlays",
        features.get("can_keylog") and "Can log keystrokes via Accessibility",
        features.get("can_exfiltrate") and "Can exfiltrate data to remote server",
        features.get("can_control_device") and "Has full device admin control",
    ]
    behaviors = [b for b in behaviors if b]
    family = features.get("suspected_family")

    prompt = f"""You are the GARUD-AI Threat Reasoning Agent — an expert Android malware analyst at an Indian cybersecurity SOC.

Analyze the following APK evidence and provide a comprehensive threat assessment:

PACKAGE: {package}
SUSPICIOUS PERMISSIONS: {json.dumps(perms, indent=2)}
CROSS-LAYER RISK SIGNALS: {json.dumps(signals, indent=2)}
INFERRED CAPABILITIES: {json.dumps(behaviors, indent=2)}
SUSPECTED MALWARE FAMILY: {family or "Unknown"}
CORRELATION SCORE: {features.get("correlation_score", 0)}/100
C2 CANDIDATES: {features.get("c2_candidates", 0)} detected
KNOWN VARIANT: {features.get("is_known_variant", False)}

Based on this evidence, respond ONLY with a valid JSON object:
{{
  "threat_assessment": "Short label of likely threat (e.g. 'Banking credential theft via overlay attack')",
  "reasoning": [
    "Bullet point 1 explaining key evidence",
    "Bullet point 2",
    "Bullet point 3",
    "Bullet point 4",
    "Bullet point 5"
  ],
  "confidence": 85,
  "threat_category": "MALICIOUS | SUSPICIOUS | SAFE",
  "evidence_summary": "One paragraph summarizing the threat evidence chain"
}}"""

    fallback = {
        "threat_assessment": _heuristic_assessment(features),
        "reasoning": _heuristic_reasoning(features),
        "confidence": features.get("correlation_score", 30),
        "threat_category": _heuristic_category(features),
        "evidence_summary": f"Heuristic analysis: {len(signals)} cross-layer risk signals detected. Correlation score: {features.get('correlation_score', 0)}/100."
    }

    result = call_llm_json(llm, prompt, fallback)
    logger.info(f"Threat Reasoning: {result.get('threat_assessment', 'N/A')} ({result.get('confidence', 0)}%)")
    return result


# ── Heuristic fallbacks ───────────────────────────────────────
def _heuristic_assessment(f: dict) -> str:
    if f.get("can_intercept_sms") and f.get("can_overlay"):
        return "Banking credential theft via SMS interception and overlay attack"
    if f.get("can_intercept_sms"):
        return "OTP interception — potential banking fraud enabler"
    if f.get("can_overlay"):
        return "Phishing overlay attack targeting banking applications"
    if f.get("can_control_device"):
        return "Remote Access Trojan — full device compromise"
    if f.get("can_exfiltrate") and f.get("can_harvest_contacts"):
        return "Spyware — harvesting contacts and personal data for fraud"
    family = f.get("suspected_family")
    if family:
        return f"Suspected {family} malware family"
    score = f.get("correlation_score", 0)
    if score > 60: return "High-risk application — multiple suspicious indicators"
    if score > 30: return "Suspicious application — requires investigation"
    return "Low-risk application"

def _heuristic_reasoning(f: dict) -> list:
    bullets = []
    if f.get("can_intercept_sms"):
        bullets.append("RECEIVE_SMS + READ_SMS permissions enable complete SMS inbox access and real-time OTP interception")
    if f.get("can_overlay"):
        bullets.append("SYSTEM_ALERT_WINDOW permission allows displaying phishing overlays over legitimate banking apps")
    if f.get("can_keylog"):
        bullets.append("BIND_ACCESSIBILITY_SERVICE enables keystroke capture and UI monitoring across all applications")
    if f.get("has_c2"):
        bullets.append(f"{f.get('c2_candidates', 0)} potential C2 server(s) detected for remote command and data exfiltration")
    if f.get("has_reflection"):
        bullets.append("Dynamic code loading via reflection indicates potential dropper or anti-analysis evasion")
    if not bullets:
        bullets.append("Low-severity indicators — standard application behavior")
    return bullets[:5]

def _heuristic_category(f: dict) -> str:
    score = f.get("correlation_score", 0)
    if score >= 70 or f.get("can_intercept_sms") and f.get("can_overlay"):
        return "MALICIOUS"
    if score >= 35:
        return "SUSPICIOUS"
    return "SAFE"
