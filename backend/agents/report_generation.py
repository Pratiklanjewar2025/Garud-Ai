"""
GARUD-AI Agent 8 — Report Generation Agent
Generates the final executive + technical investigation report.
"""
import json
import logging
from agents import get_llm, call_llm_json

logger = logging.getLogger("garud_ai.agents.report_generation")

AGENT_NAME  = "report_generation"
AGENT_LABEL = "Report Generation Agent"
AGENT_INDEX = 8


def run(features: dict, all_data: dict) -> dict:
    llm = get_llm()

    sample  = all_data.get("sample", {})
    risk    = all_data.get("risk", {})
    agents  = all_data.get("agents", {})
    iocs    = all_data.get("iocs", [])

    package        = sample.get("package_name", "Unknown")
    filename       = sample.get("original_filename", "Unknown")
    risk_score     = risk.get("risk_score", 0)
    classification = risk.get("classification", "UNKNOWN")
    malware_type   = risk.get("malware_type", "Unknown")
    severity       = risk.get("severity", "UNKNOWN")

    threat_assessment_text = agents.get("threat_reasoning", {}).get("threat_assessment", "No assessment")
    behavior_profile = agents.get("behavioral_correlation", {}).get("behavioral_profile", "Unknown")
    kill_chain = agents.get("behavioral_correlation", {}).get("kill_chain", [])
    mitre_techniques = agents.get("mitre_mapping", {}).get("techniques", [])
    campaign = agents.get("campaign_correlation", {})
    ti_verdict = agents.get("threat_intelligence", {}).get("verdict", "No intelligence")

    prompt = f"""You are the GARUD-AI Report Generation Agent — an expert cybersecurity analyst writing threat intelligence reports for Indian banking SOC teams and CERT-In.

Generate a comprehensive investigation report for:

FILE: {filename}
PACKAGE: {package}
RISK SCORE: {risk_score}/100
CLASSIFICATION: {classification}
MALWARE TYPE: {malware_type}
SEVERITY: {severity}

THREAT ASSESSMENT: {threat_assessment_text}
BEHAVIORAL PROFILE: {behavior_profile}
ATTACK KILL CHAIN: {json.dumps(kill_chain, indent=2)}
INTELLIGENCE VERDICT: {ti_verdict}
CAMPAIGN DETECTED: {campaign.get("campaign_name", "None")}
MITRE TECHNIQUES: {json.dumps([t.get("id") + " " + t.get("name", "") for t in mitre_techniques[:6]], indent=2)}
IOC COUNT: {len(iocs)}

Write a professional report. Respond ONLY with valid JSON:
{{
  "executive_summary": "2-3 paragraph non-technical summary suitable for bank management and regulators. Explain what the app does, what threat it poses, and recommended response.",
  "threat_assessment": "{classification}",
  "technical_findings": {{
    "static_summary": "Technical summary of static analysis findings",
    "dynamic_summary": "Technical summary of behavioral findings",
    "network_summary": "Technical summary of network/C2 findings"
  }},
  "immediate_actions": [
    "Block identified domains and IPs at network perimeter",
    "Alert affected customers",
    "Submit sample to CERT-In",
    "Action item 4"
  ],
  "long_term_actions": [
    "Update YARA rules to detect this malware family",
    "Implement app reputation checks",
    "Long-term action 3"
  ]
}}"""

    fallback = _heuristic_report(features, sample, risk, agents, iocs, kill_chain, mitre_techniques, campaign)
    result = call_llm_json(llm, prompt, fallback)
    logger.info(f"Report Generation: executive_summary length={len(result.get('executive_summary', ''))}")
    return result


def _heuristic_report(features, sample, risk, agents, iocs, kill_chain, mitre, campaign):
    pkg = sample.get("package_name", "Unknown")
    score = risk.get("risk_score", 0)
    cls = risk.get("classification", "UNKNOWN")
    mtype = risk.get("malware_type", "Unknown")
    sev = risk.get("severity", "UNKNOWN")
    campaign_name = campaign.get("campaign_name", "no known campaign")

    exec_summary = (
        f"GARUD-AI CyberShield has completed a comprehensive automated security investigation of the submitted Android application "
        f"'{sample.get('original_filename', 'Unknown')}' (package: {pkg}). "
        f"The application has been classified as {cls} with a risk score of {score}/100 and severity level {sev}. "
        f"\n\nThe analysis identified this application as a '{mtype}'. "
        f"The investigation detected {len(iocs)} indicators of compromise, {features.get('c2_candidates', 0)} potential command-and-control servers, "
        f"and {features.get('suspicious_api_count', 0)} suspicious API calls. "
        f"The application is associated with {campaign_name}."
        f"\n\nImmediate action is recommended to block the identified indicators at the network perimeter, "
        f"alert potentially affected customers, and submit the sample to CERT-In for national threat intelligence sharing."
    )

    immediate = [
        f"Block SHA256 {sample.get('sha256', 'N/A')[:32]}... at endpoint security tools",
        "Alert banking customers who may have installed this application",
        "Submit IOCs to CERT-In and RBI Cyber Security Cell",
        "Deploy detection rules based on package name: " + (pkg or "Unknown"),
    ]
    if features.get("c2_candidates", 0) > 0:
        immediate.append("Block all identified C2 domains and IPs at network firewall")

    long_term = [
        "Update mobile banking app security advisory to warn about this malware family",
        "Implement certificate pinning in official banking apps to resist overlay attacks",
        "Enable SIEM alerting for package names matching identified patterns",
        "Consider user awareness campaign about fake banking app threats",
    ]

    return {
        "executive_summary": exec_summary,
        "threat_assessment": cls,
        "technical_findings": {
            "static_summary": f"Static analysis identified {features.get('dangerous_perm_count', 0)} dangerous permissions and {features.get('suspicious_api_count', 0)} suspicious API calls.",
            "dynamic_summary": f"Dynamic analysis inferred {features.get('can_intercept_sms') and 'SMS interception' or 'no critical runtime behaviors'}.",
            "network_summary": f"{features.get('suspicious_domains', 0)} suspicious domains and {features.get('c2_candidates', 0)} C2 candidates identified.",
        },
        "immediate_actions": immediate,
        "long_term_actions": long_term,
    }
