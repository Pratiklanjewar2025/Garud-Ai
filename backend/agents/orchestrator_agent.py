"""
GARUD-AI Agent 7 — Orchestrator Agent
Coordinates all 6 analysis agents, resolves conflicts, produces final consensus verdict.
Also runs Agent 8 (Report Generation) after all agents complete.
"""
import logging
from datetime import datetime
from sqlalchemy.orm import Session
from models import (
    APKSample, StaticAnalysisResult, DynamicAnalysisResult,
    NetworkAnalysisResult, MalwareDNAProfile, IOCRecord,
    AgentInvestigation, RiskScoreRecord, ThreatReport
)

logger = logging.getLogger("garud_ai.agents.orchestrator")

AGENT_REGISTRY = [
    ("threat_reasoning",       "Threat Reasoning Agent",       1),
    ("behavioral_correlation", "Behavioral Correlation Agent", 2),
    ("threat_intelligence",    "Threat Intelligence Agent",    3),
    ("campaign_correlation",   "Campaign Correlation Agent",   4),
    ("mitre_mapping",          "MITRE ATT&CK Mapping Agent",   5),
    ("risk_scoring",           "Risk Scoring Agent",           6),
    ("orchestrator_agent",     "Orchestrator Agent",           7),
    ("report_generation",      "Report Generation Agent",      8),
]


def run(sample_id: str, db: Session) -> None:
    """Run all 8 agents for the given sample."""
    logger.info(f"[{sample_id}] Agent Investigation: starting all 8 agents")

    # ── Load all analysis data ─────────────────────────────────
    sample  = db.query(APKSample).filter_by(sample_id=sample_id).first()
    static  = db.query(StaticAnalysisResult).filter_by(sample_id=sample_id).first()
    dynamic = db.query(DynamicAnalysisResult).filter_by(sample_id=sample_id).first()
    network = db.query(NetworkAnalysisResult).filter_by(sample_id=sample_id).first()
    dna     = db.query(MalwareDNAProfile).filter_by(sample_id=sample_id).first()
    iocs    = db.query(IOCRecord).filter_by(sample_id=sample_id).all()

    features = sample.correlated_features or {}

    # Prepare serializable data dicts
    static_dict  = _model_to_dict(static)
    dynamic_dict = _model_to_dict(dynamic)
    network_dict = _model_to_dict(network)
    dna_dict     = _model_to_dict(dna)
    ioc_list     = [{"ioc_type": i.ioc_type, "ioc_value": i.ioc_value, "risk_level": i.risk_level, "context": i.context} for i in iocs]

    # Pre-create agent records in DB with PENDING status
    _initialize_agent_records(sample_id, db)

    agent_outputs = {}

    # ── Agent 1: Threat Reasoning ──────────────────────────────
    agent_outputs["threat_reasoning"] = _run_agent(
        sample_id, "threat_reasoning", 1, db,
        lambda: __import__("agents.threat_reasoning", fromlist=["run"]).run(features)
    )

    # ── Agent 2: Behavioral Correlation ───────────────────────
    agent_outputs["behavioral_correlation"] = _run_agent(
        sample_id, "behavioral_correlation", 2, db,
        lambda: __import__("agents.behavioral_correlation", fromlist=["run"]).run(features, dynamic_dict)
    )

    # ── Agent 3: Threat Intelligence ──────────────────────────
    agent_outputs["threat_intelligence"] = _run_agent(
        sample_id, "threat_intelligence", 3, db,
        lambda: __import__("agents.threat_intelligence", fromlist=["run"]).run(features, ioc_list, network_dict)
    )

    # ── Agent 4: Campaign Correlation ─────────────────────────
    agent_outputs["campaign_correlation"] = _run_agent(
        sample_id, "campaign_correlation", 4, db,
        lambda: __import__("agents.campaign_correlation", fromlist=["run"]).run(features, dna_dict)
    )

    # ── Agent 5: MITRE Mapping ─────────────────────────────────
    permissions = sample.permissions or []
    mitre_result = _run_agent(
        sample_id, "mitre_mapping", 5, db,
        lambda: __import__("agents.mitre_mapping", fromlist=["run"]).run(features, permissions, static_dict)
    )
    agent_outputs["mitre_mapping"] = mitre_result
    # Store MITRE techniques on agent record
    _update_agent_mitre(sample_id, "mitre_mapping", mitre_result, db)

    # ── Agent 6: Risk Scoring ──────────────────────────────────
    risk_result = _run_agent(
        sample_id, "risk_scoring", 6, db,
        lambda: __import__("agents.risk_scoring", fromlist=["run"]).run(features, agent_outputs)
    )
    agent_outputs["risk_scoring"] = risk_result

    # ── Save Risk Score Record ─────────────────────────────────
    _save_risk_score(sample_id, risk_result, agent_outputs, db)

    # ── Agent 7: Orchestrator consensus ──────────────────────
    consensus = _compute_consensus(agent_outputs)
    _save_orchestrator_record(sample_id, consensus, db)
    agent_outputs["orchestrator"] = consensus

    # ── Agent 8: Report Generation ────────────────────────────
    all_data = {
        "sample": _model_to_dict(sample),
        "static": static_dict,
        "dynamic": dynamic_dict,
        "network": network_dict,
        "iocs": ioc_list,
        "agents": agent_outputs,
        "risk": risk_result,
    }
    report_result = _run_agent(
        sample_id, "report_generation", 8, db,
        lambda: __import__("agents.report_generation", fromlist=["run"]).run(features, all_data)
    )

    # ── Save Threat Report ─────────────────────────────────────
    _save_threat_report(sample_id, report_result, agent_outputs, risk_result, db)

    logger.info(f"[{sample_id}] All 8 agents completed")


def _run_agent(sample_id: str, agent_name: str, agent_index: int, db: Session, fn) -> dict:
    """Execute a single agent function with status tracking and error isolation."""
    logger.info(f"[{sample_id}] Running Agent {agent_index}: {agent_name}")

    rec = db.query(AgentInvestigation).filter_by(sample_id=sample_id, agent_name=agent_name).first()
    if rec:
        rec.status = "RUNNING"
        rec.started_at = datetime.utcnow()
        db.commit()

    try:
        result = fn()
        if not isinstance(result, dict):
            result = {"verdict": str(result), "confidence": 50}

        if rec:
            rec.status       = "COMPLETED"
            rec.completed_at = datetime.utcnow()
            rec.verdict      = str(result.get("verdict") or result.get("threat_assessment") or result.get("behavioral_profile") or result.get("campaign_name") or "Completed")[:500]
            rec.confidence   = int(result.get("confidence", 70))
            rec.reasoning    = result.get("reasoning", [])
            rec.evidence     = result.get("evidence", [])
            rec.recommendations = result.get("recommendations", [])
            db.commit()

        logger.info(f"[{sample_id}] Agent {agent_index} ({agent_name}): completed")
        return result

    except Exception as e:
        logger.error(f"[{sample_id}] Agent {agent_index} ({agent_name}) failed: {e}")
        if rec:
            rec.status = "FAILED"
            rec.error  = str(e)
            db.commit()
        return {"verdict": f"Agent failed: {e}", "confidence": 0, "error": str(e)}


def _initialize_agent_records(sample_id: str, db: Session) -> None:
    """Pre-create all 8 agent records with PENDING status."""
    for name, label, idx in AGENT_REGISTRY:
        existing = db.query(AgentInvestigation).filter_by(sample_id=sample_id, agent_name=name).first()
        if not existing:
            db.add(AgentInvestigation(
                sample_id=sample_id, agent_name=name,
                agent_label=label, agent_index=idx, status="PENDING"
            ))
    db.commit()


def _update_agent_mitre(sample_id: str, agent_name: str, mitre_result: dict, db: Session):
    rec = db.query(AgentInvestigation).filter_by(sample_id=sample_id, agent_name=agent_name).first()
    if rec:
        rec.mitre_techniques = mitre_result.get("techniques", [])
        db.commit()


def _save_risk_score(sample_id: str, risk_result: dict, agent_outputs: dict, db: Session):
    existing = db.query(RiskScoreRecord).filter_by(sample_id=sample_id).first()
    if not existing:
        existing = RiskScoreRecord(sample_id=sample_id)
        db.add(existing)

    breakdown = risk_result.get("score_breakdown", {})
    existing.risk_score       = risk_result.get("risk_score", 0)
    existing.confidence_score = risk_result.get("confidence_score", 50)
    existing.severity         = risk_result.get("severity", "MEDIUM")
    existing.classification   = risk_result.get("classification", "SUSPICIOUS")
    existing.malware_type     = risk_result.get("malware_type", "Unknown")
    existing.malware_family   = risk_result.get("malware_family", "Unknown")
    existing.static_score     = breakdown.get("static_score", 0)
    existing.dynamic_score    = breakdown.get("dynamic_score", 0)
    existing.network_score    = breakdown.get("network_score", 0)
    existing.behavior_score   = breakdown.get("behavior_score", 0)
    existing.dna_score        = breakdown.get("dna_score", 0)
    existing.agent_consensus  = risk_result.get("agent_consensus", "DIVIDED")

    # Also update risk scoring agent record
    rec = db.query(AgentInvestigation).filter_by(sample_id=sample_id, agent_name="risk_scoring").first()
    if rec:
        rec.risk_score     = existing.risk_score
        rec.severity       = existing.severity
        rec.classification = existing.classification
        rec.score_breakdown = breakdown

    db.commit()


def _compute_consensus(agent_outputs: dict) -> dict:
    """Agent 7: Compute consensus from all agents."""
    categories = []
    for name, output in agent_outputs.items():
        for key in ("threat_category", "classification", "threat_level", "severity"):
            if key in output:
                val = output[key]
                if val in ("MALICIOUS", "CRITICAL", "HIGH"):
                    categories.append("MALICIOUS")
                elif val in ("SUSPICIOUS", "MEDIUM"):
                    categories.append("SUSPICIOUS")
                elif val in ("SAFE", "LOW"):
                    categories.append("SAFE")
                break

    malicious  = categories.count("MALICIOUS")
    suspicious = categories.count("SUSPICIOUS")
    safe       = categories.count("SAFE")
    total      = max(len(categories), 1)

    if malicious / total >= 0.6:
        consensus = "UNANIMOUS_MALICIOUS" if malicious == total else "MAJORITY_MALICIOUS"
    elif safe / total >= 0.6:
        consensus = "MAJORITY_SAFE"
    else:
        consensus = "DIVIDED"

    return {
        "verdict": consensus,
        "confidence": 80,
        "reasoning": [f"{malicious}/{total} agents flagged MALICIOUS", f"{suspicious}/{total} flagged SUSPICIOUS", f"{safe}/{total} flagged SAFE"],
        "malicious_votes": malicious, "suspicious_votes": suspicious, "safe_votes": safe
    }


def _save_orchestrator_record(sample_id: str, consensus: dict, db: Session):
    rec = db.query(AgentInvestigation).filter_by(sample_id=sample_id, agent_name="orchestrator_agent").first()
    if rec:
        rec.status       = "COMPLETED"
        rec.completed_at = datetime.utcnow()
        rec.verdict      = consensus.get("verdict", "DIVIDED")
        rec.confidence   = consensus.get("confidence", 70)
        rec.reasoning    = consensus.get("reasoning", [])
        db.commit()


def _save_threat_report(sample_id: str, report_result: dict, agent_outputs: dict, risk: dict, db: Session):
    existing = db.query(ThreatReport).filter_by(sample_id=sample_id).first()
    if not existing:
        existing = ThreatReport(sample_id=sample_id)
        db.add(existing)

    existing.executive_summary = report_result.get("executive_summary", "")
    existing.threat_assessment = report_result.get("threat_assessment", risk.get("classification", "UNKNOWN"))
    existing.technical_findings = report_result.get("technical_findings", {})
    existing.behavioral_summary = {"profile": agent_outputs.get("behavioral_correlation", {}).get("behavioral_profile"), "kill_chain": agent_outputs.get("behavioral_correlation", {}).get("kill_chain")}
    existing.mitre_summary = agent_outputs.get("mitre_mapping", {}).get("techniques", [])
    existing.campaign_info = {"campaign_detected": agent_outputs.get("campaign_correlation", {}).get("campaign_detected"), "campaign_name": agent_outputs.get("campaign_correlation", {}).get("campaign_name")}
    existing.immediate_actions = report_result.get("immediate_actions", [])
    existing.long_term_actions = report_result.get("long_term_actions", [])
    db.commit()


def _model_to_dict(model) -> dict:
    """Convert SQLAlchemy model to plain dict for agent consumption."""
    if model is None:
        return {}
    result = {}
    for col in model.__table__.columns:
        val = getattr(model, col.name)
        result[col.name] = val
    return result
