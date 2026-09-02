"""
GARUD-AI Agent 5 — MITRE ATT&CK Mapping Agent
Maps observed behaviors to MITRE ATT&CK for Mobile techniques with evidence.
"""
import json
import logging
from agents import get_llm, call_llm_json
from knowledge.mitre_knowledge import (
    map_permissions_to_techniques,
    map_apis_to_techniques,
    MITRE_MOBILE_TECHNIQUES,
)

logger = logging.getLogger("garud_ai.agents.mitre_mapping")

AGENT_NAME  = "mitre_mapping"
AGENT_LABEL = "MITRE ATT&CK Mapping Agent"
AGENT_INDEX = 5


def run(features: dict, permissions: list, static_data: dict) -> dict:
    llm = get_llm()

    # Deterministic MITRE mapping from signatures
    perm_matches = map_permissions_to_techniques(permissions or [])
    api_calls = []
    if static_data and static_data.get("suspicious_apis"):
        api_calls = [a.get("class", "") + "." + a.get("method", "") for a in static_data["suspicious_apis"][:20]]
    api_matches = map_apis_to_techniques(api_calls)

    # Merge and deduplicate
    all_matches = {}
    for m in perm_matches + api_matches:
        tid = m["technique"]["id"]
        if tid not in all_matches:
            all_matches[tid] = {
                "id": tid,
                "name": m["technique"]["name"],
                "tactic": m["technique"]["tactic"],
                "severity": m["technique"]["severity"],
                "description": m["technique"]["description"],
                "matched_by": m["match_type"],
                "evidence": m["matched"],
                "confidence": 80 if m["match_type"] == "permission" else 65,
            }

    matched_techniques = list(all_matches.values())

    prompt = f"""You are the GARUD-AI MITRE ATT&CK Mapping Agent — expert in MITRE ATT&CK for Mobile.

Based on the pre-identified technique matches and additional behavioral evidence, validate and enrich the MITRE ATT&CK mapping:

PRE-MATCHED TECHNIQUES (from signatures): {json.dumps([{"id": t["id"], "name": t["name"], "tactic": t["tactic"], "evidence": t["evidence"]} for t in matched_techniques], indent=2)}
RISK SIGNALS: {json.dumps([s["signal"] for s in features.get("risk_signals", [])], indent=2)}
ACTIVE CAPABILITIES: intercept_sms={features.get("can_intercept_sms")}, overlay={features.get("can_overlay")}, keylog={features.get("can_keylog")}, exfil={features.get("can_exfiltrate")}

Confirm the techniques and add any additional relevant ones. Respond ONLY with valid JSON:
{{
  "techniques": [
    {{
      "id": "T1412",
      "name": "Capture SMS Messages",
      "tactic": "Collection",
      "confidence": 90,
      "evidence": "RECEIVE_SMS permission + SMS BroadcastReceiver API",
      "severity": "CRITICAL"
    }}
  ],
  "tactic_coverage": ["Collection", "Exfiltration", "Command and Control"],
  "attack_sophistication": "LOW | MEDIUM | HIGH",
  "reasoning": ["MITRE mapping rationale 1", "Rationale 2"]
}}"""

    fallback = {
        "techniques": matched_techniques,
        "tactic_coverage": list(set(t["tactic"] for t in matched_techniques)),
        "attack_sophistication": "HIGH" if len(matched_techniques) >= 5 else "MEDIUM" if len(matched_techniques) >= 2 else "LOW",
        "reasoning": [f"Deterministic MITRE mapping identified {len(matched_techniques)} techniques from permission and API signatures"]
    }

    result = call_llm_json(llm, prompt, fallback)
    logger.info(f"MITRE Mapping: {len(result.get('techniques', []))} techniques mapped")
    return result
