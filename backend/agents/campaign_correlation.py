"""
GARUD-AI Agent 4 — Campaign Correlation Agent
Identifies whether the APK belongs to a known fraud/malware campaign.
"""
import json
import logging
from agents import get_llm, call_llm_json

logger = logging.getLogger("garud_ai.agents.campaign_correlation")

AGENT_NAME  = "campaign_correlation"
AGENT_LABEL = "Campaign Correlation Agent"
AGENT_INDEX = 4


def run(features: dict, dna_data: dict) -> dict:
    llm = get_llm()

    family = features.get("suspected_family")
    family_confidence = features.get("family_confidence", 0)
    is_known = features.get("is_known_variant", False)
    similar_id = features.get("similar_sample_id") if features.get("is_known_variant") else None
    package = features.get("package_name", "Unknown")
    signals = [s["signal"] for s in features.get("risk_signals", [])]

    prompt = f"""You are the GARUD-AI Campaign Correlation Agent — an expert in Android fraud campaign analysis in India.

Determine if this APK belongs to a known fraud or malware campaign:

SUSPECTED FAMILY: {family or "Unknown"} (confidence: {family_confidence}%)
IS KNOWN VARIANT: {is_known}
SIMILAR SAMPLE: {similar_id or "None"}
PACKAGE NAME: {package}
RISK SIGNALS: {json.dumps(signals, indent=2)}
CORRELATION SCORE: {features.get("correlation_score", 0)}/100

Focus on known Indian cyber fraud campaigns:
- FakeBank campaigns (impersonating SBI, HDFC, ICICI, Axis Bank)
- FakeUPI campaigns (impersonating PhonePe, Google Pay, BHIM, Paytm)
- Loan fraud campaigns (illegal loan apps harvesting contacts for extortion)
- SMS forwarder campaigns used for OTP theft
- Government impersonation campaigns (fake Aadhaar, Income Tax, CERT-In apps)

Respond ONLY with valid JSON:
{{
  "campaign_detected": true,
  "campaign_name": "Campaign name or 'No campaign detected'",
  "campaign_type": "Banking Fraud | UPI Fraud | Loan Fraud | SMS OTP Theft | Government Impersonation | Unknown",
  "campaign_description": "Description of the campaign and its tactics",
  "target_victims": "Description of likely targets (e.g. 'Indian banking customers using SBI/HDFC apps')",
  "related_indicators": ["indicator 1", "indicator 2"],
  "campaign_maturity": "Emerging | Active | Established | Declining",
  "reasoning": ["Campaign evidence point 1", "Point 2", "Point 3"],
  "confidence": 65
}}"""

    campaign_detected = bool(family and family_confidence and family_confidence > 50)
    fallback = {
        "campaign_detected": campaign_detected,
        "campaign_name": f"{family} Campaign" if campaign_detected else "No campaign detected",
        "campaign_type": _infer_campaign_type(features),
        "campaign_description": f"Heuristic analysis suggests {family} pattern" if campaign_detected else "Insufficient evidence for campaign attribution",
        "target_victims": "Indian banking and UPI application users" if features.get("can_intercept_sms") else "Unknown",
        "related_indicators": [package] if package and package != "Unknown" else [],
        "campaign_maturity": "Active" if is_known else "Unknown",
        "reasoning": [f"Family match: {family} at {family_confidence}% confidence" if campaign_detected else "No strong campaign signature detected"],
        "confidence": int(family_confidence) if campaign_detected else 20
    }

    result = call_llm_json(llm, prompt, fallback)
    logger.info(f"Campaign Correlation: campaign={result.get('campaign_name', 'N/A')}")
    return result


def _infer_campaign_type(f: dict) -> str:
    family = f.get("suspected_family", "")
    if "UPI" in family or "Fake" in family: return "UPI Fraud"
    if "Banking" in family: return "Banking Fraud"
    if "Loan" in family: return "Loan Fraud"
    if "SMS" in family: return "SMS OTP Theft"
    if f.get("can_intercept_sms"): return "SMS OTP Theft"
    return "Unknown"
