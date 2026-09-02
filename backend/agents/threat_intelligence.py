"""
GARUD-AI Agent 3 — Threat Intelligence Agent
Cross-references IOCs and indicators with known threat intelligence.
"""
import json
import logging
from agents import get_llm, call_llm_json

logger = logging.getLogger("garud_ai.agents.threat_intelligence")

AGENT_NAME  = "threat_intelligence"
AGENT_LABEL = "Threat Intelligence Agent"
AGENT_INDEX = 3


def run(features: dict, iocs: list, network_data: dict) -> dict:
    llm = get_llm()

    ioc_summary = [{"type": i.get("ioc_type"), "value": i.get("ioc_value"), "risk": i.get("risk_level")} for i in (iocs or [])[:15]]
    c2_candidates = (network_data.get("c2_candidates") or []) if network_data else []
    susp_domains  = (network_data.get("suspicious_domains") or []) if network_data else []

    prompt = f"""You are the GARUD-AI Threat Intelligence Agent — an expert in Indian cybersecurity threat intelligence.

Cross-reference the following indicators with your threat intelligence knowledge:

IOC SUMMARY (sample): {json.dumps(ioc_summary, indent=2)}
C2 CANDIDATES: {json.dumps(c2_candidates[:5], indent=2)}
SUSPICIOUS DOMAINS: {json.dumps([d.get("domain") for d in susp_domains[:5]], indent=2)}
SUSPECTED FAMILY: {features.get("suspected_family", "Unknown")}
PACKAGE: {features.get("package_name", "Unknown")}
SHA256: {features.get("sha256", "Unknown")}

Respond ONLY with valid JSON:
{{
  "verdict": "One sentence intelligence verdict",
  "threat_actor_profile": "Description of likely threat actor / campaign type",
  "ioc_reputation": [
    {{"ioc": "...", "type": "DOMAIN", "assessment": "Malicious/Suspicious/Benign", "note": "..."}}
  ],
  "known_campaign_links": "Description of any known campaign links, or 'No known campaign links identified'",
  "threat_level": "LOW | MEDIUM | HIGH | CRITICAL",
  "reasoning": ["Intelligence finding 1", "Finding 2", "Finding 3"],
  "recommendations": ["Action 1", "Action 2"],
  "confidence": 70
}}"""

    fallback = {
        "verdict": f"Threat intelligence analysis of {len(ioc_summary)} IOCs — {len(c2_candidates)} potential C2 indicators found",
        "threat_actor_profile": "Financially motivated actor targeting Indian banking customers" if features.get("can_intercept_sms") else "Unknown threat actor profile",
        "ioc_reputation": [{"ioc": i.get("ioc_value", ""), "type": i.get("ioc_type", ""), "assessment": "Suspicious" if i.get("risk_level") in ("HIGH", "CRITICAL") else "Unknown", "note": i.get("context", "")} for i in (iocs or [])[:5]],
        "known_campaign_links": "No confirmed campaign attribution from heuristic analysis",
        "threat_level": "HIGH" if c2_candidates else "MEDIUM" if ioc_summary else "LOW",
        "reasoning": [f"Identified {len(ioc_summary)} indicators of compromise", f"{len(c2_candidates)} potential C2 servers flagged", f"Suspected malware family: {features.get('suspected_family', 'Unknown')}"],
        "recommendations": ["Block identified IOCs at network perimeter", "Submit hash to threat intelligence platforms (VirusTotal, MalwareBazaar)"],
        "confidence": 55
    }

    result = call_llm_json(llm, prompt, fallback)
    logger.info(f"Threat Intelligence: level={result.get('threat_level', 'N/A')}")
    return result
