"""
GARUD-AI Agent 6 — Risk Scoring Agent
Computes final numeric risk score, confidence, severity, and malware classification.
"""
import json
import logging
from agents import get_llm, call_llm_json
from knowledge.threat_signatures import MALWARE_FAMILIES

logger = logging.getLogger("garud_ai.agents.risk_scoring")

AGENT_NAME  = "risk_scoring"
AGENT_LABEL = "Risk Scoring Agent"
AGENT_INDEX = 6


def run(features: dict, agent_verdicts: dict) -> dict:
    llm = get_llm()

    # Compute individual layer scores deterministically
    static_score   = min(features.get("permission_risk_score", 0), 100)
    dynamic_score  = _compute_dynamic_score(features)
    network_score  = min(features.get("c2_candidates", 0) * 15 + features.get("suspicious_domains", 0) * 5, 100)
    behavior_score = min(features.get("correlation_score", 0), 100)
    dna_score      = 70 if features.get("is_known_variant") else (features.get("family_confidence") or 0)

    # Weighted composite score
    raw_score = (
        static_score   * 0.25 +
        dynamic_score  * 0.25 +
        network_score  * 0.15 +
        behavior_score * 0.25 +
        dna_score      * 0.10
    )
    raw_score = min(int(raw_score), 100)

    # Family-based floor
    family = features.get("suspected_family")
    if family and family in MALWARE_FAMILIES:
        base = MALWARE_FAMILIES[family]["risk_score_base"]
        raw_score = max(raw_score, base)

    verdicts_summary = [
        {"agent": k, "verdict": v.get("threat_category") or v.get("threat_level") or v.get("severity") or "Unknown"}
        for k, v in (agent_verdicts or {}).items()
    ]

    prompt = f"""You are the GARUD-AI Risk Scoring Agent — the final numerical risk arbiter.

Compute the definitive risk score for this APK based on all evidence:

COMPUTED LAYER SCORES:
- Static Analysis Score:  {static_score}/100
- Dynamic Behavior Score: {dynamic_score}/100
- Network/IOC Score:      {network_score}/100
- Behavioral Correlation: {behavior_score}/100
- DNA/Family Score:       {dna_score}/100

RAW COMPOSITE SCORE: {raw_score}/100

AGENT VERDICTS: {json.dumps(verdicts_summary, indent=2)}

SUSPECTED MALWARE FAMILY: {family or "Unknown"}

Respond ONLY with valid JSON:
{{
  "risk_score": {raw_score},
  "confidence_score": 82,
  "severity": "CRITICAL | HIGH | MEDIUM | LOW",
  "classification": "MALICIOUS | SUSPICIOUS | SAFE",
  "malware_type": "Banking Trojan | Spyware | SMS Trojan | Credential Stealer | RAT | Loan Fraud App | Fake UPI App | Dropper | Safe Application",
  "malware_family": "Specific family name or 'Unknown'",
  "score_breakdown": {{
    "static_score": {static_score},
    "dynamic_score": {dynamic_score},
    "network_score": {network_score},
    "behavior_score": {behavior_score},
    "dna_score": {dna_score}
  }},
  "reasoning": ["Scoring factor 1", "Factor 2", "Factor 3"],
  "agent_consensus": "UNANIMOUS_MALICIOUS | MAJORITY_MALICIOUS | DIVIDED | MAJORITY_SAFE | UNANIMOUS_SAFE"
}}"""

    fallback = _heuristic_score(features, raw_score, static_score, dynamic_score, network_score, behavior_score, dna_score)
    result = call_llm_json(llm, prompt, fallback)
    logger.info(f"Risk Scoring: score={result.get('risk_score')}/100, class={result.get('classification')}, severity={result.get('severity')}")
    return result


def _compute_dynamic_score(f: dict) -> int:
    score = 0
    if f.get("can_intercept_sms"):    score += 30
    if f.get("can_overlay"):          score += 25
    if f.get("can_keylog"):           score += 25
    if f.get("can_exfiltrate"):       score += 15
    if f.get("can_harvest_contacts"): score += 10
    if f.get("can_control_device"):   score += 35
    if f.get("can_send_sms"):         score += 20
    return min(score, 100)


def _heuristic_score(f, raw, static, dynamic, network, behavior, dna):
    severity = "CRITICAL" if raw >= 80 else "HIGH" if raw >= 60 else "MEDIUM" if raw >= 35 else "LOW"
    classification = "MALICIOUS" if raw >= 65 else "SUSPICIOUS" if raw >= 35 else "SAFE"
    family = f.get("suspected_family", "Unknown")
    malware_type = MALWARE_FAMILIES.get(family, {}).get("malware_type", "Unknown") if family else "Unknown"
    if classification == "SAFE": malware_type = "Safe Application"
    return {
        "risk_score": raw,
        "confidence_score": min(40 + f.get("ioc_count", 0) * 3, 85),
        "severity": severity,
        "classification": classification,
        "malware_type": malware_type,
        "malware_family": family or "Unknown",
        "score_breakdown": {"static_score": static, "dynamic_score": dynamic, "network_score": network, "behavior_score": behavior, "dna_score": dna},
        "reasoning": [f"Composite score: {raw}/100 from multi-layer analysis", f"Static risk: {static}/100", f"Dynamic capabilities: {dynamic}/100"],
        "agent_consensus": "MAJORITY_MALICIOUS" if raw >= 65 else "DIVIDED"
    }
