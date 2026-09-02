"""
GARUD-AI — API Routes
All REST endpoints for the full analysis pipeline and investigation outputs.
"""
import os
import hashlib
import uuid
import logging
import aiofiles
from datetime import datetime
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from database import get_db, SessionLocal
from models import (
    APKSample, StaticAnalysisResult, DynamicAnalysisResult,
    NetworkAnalysisResult, MalwareDNAProfile, IOCRecord,
    AgentInvestigation, RiskScoreRecord, ThreatReport
)
from pipeline.orchestrator import run_full_pipeline

logger = logging.getLogger("garud_ai.routes")
router = APIRouter(prefix="/api/v1", tags=["garud-ai"])

STORAGE_DIR = os.getenv("STORAGE_DIR", "./storage")
os.makedirs(STORAGE_DIR, exist_ok=True)


# ─────────────────────────────────────────────────────────────
# APK UPLOAD
# ─────────────────────────────────────────────────────────────
@router.post("/apks/upload")
async def upload_apk(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only .apk files are supported.")

    content = await file.read()
    sha256  = hashlib.sha256(content).hexdigest()

    # Deduplicate
    existing = db.query(APKSample).filter_by(sha256=sha256).first()
    if existing:
        logger.info(f"Duplicate upload: {sha256[:16]} → {existing.sample_id}")
        return {"sample_id": existing.sample_id, "status": existing.status, "message": "Sample already analyzed"}

    sample_id = f"GARUD-APK-{str(uuid.uuid4())[:8].upper()}"
    file_path = os.path.join(STORAGE_DIR, f"{sample_id}.apk")

    async with aiofiles.open(file_path, "wb") as f:
        await f.write(content)

    db_sample = APKSample(
        sample_id=sample_id,
        original_filename=file.filename,
        sha256=sha256,
        storage_path=file_path,
        status="UPLOADED",
    )
    db.add(db_sample)
    db.commit()

    logger.info(f"APK uploaded: {sample_id} ({file.filename}, {len(content)//1024}KB)")
    background_tasks.add_task(run_full_pipeline, sample_id, file_path, SessionLocal)

    return {"sample_id": sample_id, "status": "UPLOADED"}


# ─────────────────────────────────────────────────────────────
# PIPELINE STATUS (live progress)
# ─────────────────────────────────────────────────────────────
PIPELINE_STAGE_ORDER = [
    "INTAKE", "MALWARE_DNA", "STATIC_ANALYSIS",
    "DYNAMIC_ANALYSIS", "NETWORK_ANALYSIS",
    "FEATURE_CORRELATION", "AGENT_INVESTIGATION", "COMPLETED"
]

@router.get("/apks/{sample_id}/pipeline-status")
def get_pipeline_status(sample_id: str, db: Session = Depends(get_db)):
    sample = _get_sample_or_404(sample_id, db)
    current = sample.pipeline_stage or "INTAKE"
    agents  = db.query(AgentInvestigation).filter_by(sample_id=sample_id).order_by(AgentInvestigation.agent_index).all()

    stage_idx = PIPELINE_STAGE_ORDER.index(current) if current in PIPELINE_STAGE_ORDER else 0
    stages = []
    for i, stage in enumerate(PIPELINE_STAGE_ORDER):
        if i < stage_idx:
            status = "COMPLETED"
        elif i == stage_idx:
            status = "RUNNING" if sample.status == "ANALYZING" else "COMPLETED" if sample.status == "COMPLETED" else "RUNNING"
        else:
            status = "PENDING"
        stages.append({"stage": stage, "status": status})

    return {
        "sample_id":    sample_id,
        "status":       sample.status,
        "current_stage": current,
        "stages":       stages,
        "agents": [
            {
                "name":        a.agent_name,
                "label":       a.agent_label,
                "index":       a.agent_index,
                "status":      a.status,
                "started_at":  a.started_at,
                "completed_at": a.completed_at,
            }
            for a in agents
        ],
        "upload_time":    sample.upload_time,
        "analysis_start": sample.analysis_start,
        "analysis_end":   sample.analysis_end,
    }


# ─────────────────────────────────────────────────────────────
# METADATA
# ─────────────────────────────────────────────────────────────
@router.get("/apks/{sample_id}/metadata")
def get_metadata(sample_id: str, db: Session = Depends(get_db)):
    s = _get_sample_or_404(sample_id, db)
    return {
        "sample_id":       s.sample_id,
        "status":          s.status,
        "pipeline_stage":  s.pipeline_stage,
        "sha256":          s.sha256,
        "md5":             s.md5,
        "sha1":            s.sha1,
        "file_size":       s.file_size,
        "original_filename": s.original_filename,
        "upload_time":     s.upload_time,
        "analysis_start":  s.analysis_start,
        "analysis_end":    s.analysis_end,
        "metadata": {
            "package_name": s.package_name,
            "app_name":     s.app_name,
            "version_name": s.version_name,
            "version_code": s.version_code,
            "min_sdk":      s.min_sdk,
            "target_sdk":   s.target_sdk,
            "permissions":  s.permissions or [],
            "activities":   s.activities or [],
            "services":     s.services or [],
            "receivers":    s.receivers or [],
            "providers":    s.providers or [],
        },
        "certificate": {
            "issuer":      s.cert_issuer,
            "subject":     s.cert_subject,
            "fingerprint": s.cert_fingerprint,
            "valid_from":  s.cert_valid_from,
            "valid_to":    s.cert_valid_to,
            "is_self_signed": s.is_self_signed,
        },
        "error": s.error_message,
    }


# ─────────────────────────────────────────────────────────────
# STATIC ANALYSIS
# ─────────────────────────────────────────────────────────────
@router.get("/apks/{sample_id}/static-analysis")
def get_static_analysis(sample_id: str, db: Session = Depends(get_db)):
    _get_sample_or_404(sample_id, db)
    result = db.query(StaticAnalysisResult).filter_by(sample_id=sample_id).first()
    if not result:
        return {"sample_id": sample_id, "available": False}
    return {
        "sample_id":           sample_id,
        "available":           True,
        "permission_risk_score": result.permission_risk_score,
        "dangerous_permissions": result.dangerous_permissions or [],
        "suspicious_apis":     result.suspicious_apis or [],
        "sms_apis":            result.sms_apis or [],
        "accessibility_apis":  result.accessibility_apis or [],
        "reflection_apis":     result.reflection_apis or [],
        "extracted_urls":      result.extracted_urls or [],
        "extracted_ips":       result.extracted_ips or [],
        "extracted_strings":   result.extracted_strings or [],
        "is_obfuscated":       result.is_obfuscated,
        "obfuscation_score":   result.obfuscation_score,
        "obfuscation_indicators": result.obfuscation_indicators or [],
        "dex_files_count":     result.dex_files_count,
        "native_libraries":    result.native_libraries or [],
        "risk_flags": {
            "accessibility_service": result.has_accessibility_service,
            "device_admin":          result.has_device_admin,
            "overlay":               result.has_overlay_permission,
            "sms_access":            result.has_sms_permissions,
            "contact_access":        result.has_contact_permissions,
            "location":              result.has_location_permissions,
            "camera":                result.has_camera_permissions,
            "microphone":            result.has_mic_permissions,
        },
        "raw_findings": result.raw_findings or {},
    }


# ─────────────────────────────────────────────────────────────
# DYNAMIC ANALYSIS
# ─────────────────────────────────────────────────────────────
@router.get("/apks/{sample_id}/dynamic-analysis")
def get_dynamic_analysis(sample_id: str, db: Session = Depends(get_db)):
    _get_sample_or_404(sample_id, db)
    result = db.query(DynamicAnalysisResult).filter_by(sample_id=sample_id).first()
    if not result:
        return {"sample_id": sample_id, "available": False}
    return {
        "sample_id":       sample_id,
        "available":       True,
        "analysis_method": result.analysis_method,
        "confidence":      result.confidence,
        "capabilities": {
            "intercept_sms":    result.can_intercept_sms,
            "harvest_contacts": result.can_harvest_contacts,
            "record_screen":    result.can_record_screen,
            "control_device":   result.can_control_device,
            "exfiltrate_data":  result.can_exfiltrate_data,
            "send_sms":         result.can_send_sms,
            "keylog":           result.can_keylog,
        },
        "behaviors": {
            "sms":     result.sms_behaviors or [],
            "contact": result.contact_behaviors or [],
            "file":    result.file_behaviors or [],
            "network": result.network_behaviors or [],
            "screen":  result.screen_behaviors or [],
            "ui":      result.ui_behaviors or [],
        },
        "runtime_events": result.runtime_events or [],
    }


# ─────────────────────────────────────────────────────────────
# NETWORK ANALYSIS
# ─────────────────────────────────────────────────────────────
@router.get("/apks/{sample_id}/network-analysis")
def get_network_analysis(sample_id: str, db: Session = Depends(get_db)):
    _get_sample_or_404(sample_id, db)
    result = db.query(NetworkAnalysisResult).filter_by(sample_id=sample_id).first()
    if not result:
        return {"sample_id": sample_id, "available": False}
    return {
        "sample_id":        sample_id,
        "available":        True,
        "domains":          result.domains or [],
        "suspicious_domains": result.suspicious_domains or [],
        "c2_candidates":    result.c2_candidates or [],
        "ip_addresses":     result.ip_addresses or [],
        "suspicious_ips":   result.suspicious_ips or [],
        "urls":             result.urls or [],
        "api_endpoints":    result.api_endpoints or [],
        "risk_flags": {
            "c2_communication":       result.has_c2_communication,
            "data_exfil_endpoint":    result.has_data_exfil_endpoint,
            "uses_tor":               result.uses_tor,
            "dynamic_dns":            result.uses_dynamic_dns,
            "dga":                    result.dga_indicators,
        },
    }


# ─────────────────────────────────────────────────────────────
# IOC RECORDS
# ─────────────────────────────────────────────────────────────
@router.get("/apks/{sample_id}/iocs")
def get_iocs(sample_id: str, db: Session = Depends(get_db)):
    _get_sample_or_404(sample_id, db)
    iocs = db.query(IOCRecord).filter_by(sample_id=sample_id).order_by(IOCRecord.risk_level).all()
    return {
        "sample_id": sample_id,
        "total":     len(iocs),
        "iocs": [
            {"id": i.id, "type": i.ioc_type, "value": i.ioc_value, "risk_level": i.risk_level, "context": i.context, "tags": i.tags or []}
            for i in iocs
        ],
    }


# ─────────────────────────────────────────────────────────────
# ALL AGENT INVESTIGATIONS
# ─────────────────────────────────────────────────────────────
@router.get("/apks/{sample_id}/agents")
def get_agents(sample_id: str, db: Session = Depends(get_db)):
    _get_sample_or_404(sample_id, db)
    agents = db.query(AgentInvestigation).filter_by(sample_id=sample_id).order_by(AgentInvestigation.agent_index).all()
    return {
        "sample_id": sample_id,
        "agents": [
            {
                "name":            a.agent_name,
                "label":           a.agent_label,
                "index":           a.agent_index,
                "status":          a.status,
                "verdict":         a.verdict,
                "confidence":      a.confidence,
                "reasoning":       a.reasoning or [],
                "recommendations": a.recommendations or [],
                "mitre_techniques": a.mitre_techniques or [],
                "risk_score":      a.risk_score,
                "severity":        a.severity,
                "classification":  a.classification,
                "score_breakdown": a.score_breakdown,
                "started_at":      a.started_at,
                "completed_at":    a.completed_at,
                "error":           a.error,
            }
            for a in agents
        ],
    }


# ─────────────────────────────────────────────────────────────
# RISK SCORE
# ─────────────────────────────────────────────────────────────
@router.get("/apks/{sample_id}/risk-score")
def get_risk_score(sample_id: str, db: Session = Depends(get_db)):
    _get_sample_or_404(sample_id, db)
    r = db.query(RiskScoreRecord).filter_by(sample_id=sample_id).first()
    if not r:
        return {"sample_id": sample_id, "available": False}
    return {
        "sample_id":       sample_id,
        "available":       True,
        "risk_score":      r.risk_score,
        "confidence_score": r.confidence_score,
        "severity":        r.severity,
        "classification":  r.classification,
        "malware_type":    r.malware_type,
        "malware_family":  r.malware_family,
        "score_breakdown": {
            "static":   r.static_score,
            "dynamic":  r.dynamic_score,
            "network":  r.network_score,
            "behavior": r.behavior_score,
            "dna":      r.dna_score,
        },
        "agent_consensus": r.agent_consensus,
        "scored_at":       r.scored_at,
    }


# ─────────────────────────────────────────────────────────────
# MITRE ATT&CK MAPPING
# ─────────────────────────────────────────────────────────────
@router.get("/apks/{sample_id}/mitre")
def get_mitre(sample_id: str, db: Session = Depends(get_db)):
    _get_sample_or_404(sample_id, db)
    mitre_agent = db.query(AgentInvestigation).filter_by(sample_id=sample_id, agent_name="mitre_mapping").first()
    if not mitre_agent or not mitre_agent.mitre_techniques:
        return {"sample_id": sample_id, "available": False, "techniques": []}
    return {
        "sample_id":  sample_id,
        "available":  True,
        "techniques": mitre_agent.mitre_techniques,
        "tactic_coverage": list(set(t.get("tactic") for t in mitre_agent.mitre_techniques if t.get("tactic"))),
    }


# ─────────────────────────────────────────────────────────────
# THREAT REPORT
# ─────────────────────────────────────────────────────────────
@router.get("/apks/{sample_id}/report")
def get_report(sample_id: str, db: Session = Depends(get_db)):
    _get_sample_or_404(sample_id, db)
    report = db.query(ThreatReport).filter_by(sample_id=sample_id).first()
    dna    = db.query(MalwareDNAProfile).filter_by(sample_id=sample_id).first()
    if not report:
        return {"sample_id": sample_id, "available": False}
    return {
        "sample_id":          sample_id,
        "available":          True,
        "executive_summary":  report.executive_summary,
        "threat_assessment":  report.threat_assessment,
        "technical_findings": report.technical_findings or {},
        "behavioral_summary": report.behavioral_summary or {},
        "campaign_info":      report.campaign_info or {},
        "mitre_summary":      report.mitre_summary or [],
        "immediate_actions":  report.immediate_actions or [],
        "long_term_actions":  report.long_term_actions or [],
        "dna": {
            "signature":      dna.dna_signature if dna else None,
            "suspected_family": dna.suspected_family if dna else None,
            "is_known_variant": dna.is_known_variant if dna else False,
        },
        "generated_at": report.generated_at,
    }


# ─────────────────────────────────────────────────────────────
# DASHBOARD STATS (real database counts)
# ─────────────────────────────────────────────────────────────
@router.get("/dashboard/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    from sqlalchemy import func

    total   = db.query(APKSample).count()
    analyzing = db.query(APKSample).filter(APKSample.status == "ANALYZING").count()
    failed  = db.query(APKSample).filter(APKSample.status == "FAILED").count()

    malicious   = db.query(RiskScoreRecord).filter(RiskScoreRecord.classification == "MALICIOUS").count()
    suspicious  = db.query(RiskScoreRecord).filter(RiskScoreRecord.classification == "SUSPICIOUS").count()
    safe        = db.query(RiskScoreRecord).filter(RiskScoreRecord.classification == "SAFE").count()

    # Recent investigations
    recent_samples = (
        db.query(APKSample)
        .order_by(APKSample.upload_time.desc())
        .limit(10)
        .all()
    )
    recent_ids = [s.sample_id for s in recent_samples]
    risk_map = {r.sample_id: r for r in db.query(RiskScoreRecord).filter(RiskScoreRecord.sample_id.in_(recent_ids)).all()}

    recent = []
    for s in recent_samples:
        r = risk_map.get(s.sample_id)
        recent.append({
            "sample_id":     s.sample_id,
            "filename":      s.original_filename,
            "status":        s.status,
            "classification": r.classification if r else None,
            "risk_score":    r.risk_score if r else None,
            "malware_type":  r.malware_type if r else None,
            "severity":      r.severity if r else None,
            "upload_time":   s.upload_time,
        })

    # Malware family breakdown
    families = (
        db.query(RiskScoreRecord.malware_family, func.count(RiskScoreRecord.id))
        .filter(RiskScoreRecord.malware_family != None, RiskScoreRecord.malware_family != "Unknown")
        .group_by(RiskScoreRecord.malware_family)
        .order_by(func.count(RiskScoreRecord.id).desc())
        .limit(5)
        .all()
    )

    return {
        "total_analyzed": total,
        "malicious":      malicious,
        "suspicious":     suspicious,
        "safe":           safe,
        "active_scans":   analyzing,
        "failed":         failed,
        "recent_investigations": recent,
        "top_malware_families": [{"family": f, "count": c} for f, c in families],
    }


# ─────────────────────────────────────────────────────────────
# LEGACY: AI analysis endpoint (kept for backward compat)
# ─────────────────────────────────────────────────────────────
@router.get("/apks/{sample_id}/ai-analysis")
def get_ai_analysis(sample_id: str, db: Session = Depends(get_db)):
    """Redirect to the full agents endpoint."""
    return get_agents(sample_id, db)


# ─────────────────────────────────────────────────────────────
# THREAT MEMORY
# ─────────────────────────────────────────────────────────────
@router.get("/threats/memory")
def get_threat_memory(db: Session = Depends(get_db)):
    # Join MalwareDNAProfile with APKSample to get file names
    results = db.query(MalwareDNAProfile, APKSample).join(
        APKSample, MalwareDNAProfile.sample_id == APKSample.sample_id
    ).order_by(MalwareDNAProfile.created_at.desc()).all()
    
    memory = []
    for dna, sample in results:
        memory.append({
            "sample_id": dna.sample_id,
            "filename": sample.original_filename,
            "sha256": sample.sha256,
            "dna_signature": dna.dna_signature,
            "suspected_family": dna.suspected_family,
            "is_known_variant": dna.is_known_variant,
            "similar_sample_id": dna.similar_sample_id,
            "family_confidence": dna.family_confidence,
            "created_at": dna.created_at,
        })
    return {"total": len(memory), "memory": memory}


# ─────────────────────────────────────────────────────────────
# INVESTIGATIONS LIST
# ─────────────────────────────────────────────────────────────
@router.get("/investigations")
def list_investigations(
    status: str = None,
    classification: str = None,
    page: int = 1,
    limit: int = 20,
    db: Session = Depends(get_db),
):
    """List all APK investigations with optional filters and pagination."""
    query = db.query(APKSample)
    if status:
        query = query.filter(APKSample.status == status.upper())
    total = query.count()
    samples = (
        query.order_by(APKSample.upload_time.desc())
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )
    sample_ids = [s.sample_id for s in samples]
    risk_map = {
        r.sample_id: r
        for r in db.query(RiskScoreRecord).filter(RiskScoreRecord.sample_id.in_(sample_ids)).all()
    }

    items = []
    for s in samples:
        r = risk_map.get(s.sample_id)
        if classification and r and r.classification != classification.upper():
            continue
        if classification and not r:
            continue
        items.append({
            "sample_id":      s.sample_id,
            "filename":       s.original_filename,
            "status":         s.status,
            "pipeline_stage": s.pipeline_stage,
            "sha256":         s.sha256,
            "package_name":   s.package_name,
            "app_name":       s.app_name,
            "upload_time":    s.upload_time,
            "analysis_start": s.analysis_start,
            "analysis_end":   s.analysis_end,
            "classification": r.classification if r else None,
            "risk_score":     r.risk_score if r else None,
            "severity":       r.severity if r else None,
            "malware_type":   r.malware_type if r else None,
            "malware_family": r.malware_family if r else None,
            "error":          s.error_message,
        })

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "items": items,
    }


# ─────────────────────────────────────────────────────────────
# REPORTS LIST
# ─────────────────────────────────────────────────────────────
@router.get("/reports")
def list_reports(
    page: int = 1,
    limit: int = 20,
    db: Session = Depends(get_db),
):
    """List all completed threat reports."""
    total = db.query(ThreatReport).count()
    reports = (
        db.query(ThreatReport, APKSample, RiskScoreRecord)
        .join(APKSample, ThreatReport.sample_id == APKSample.sample_id)
        .outerjoin(RiskScoreRecord, ThreatReport.sample_id == RiskScoreRecord.sample_id)
        .order_by(ThreatReport.generated_at.desc())
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )

    items = []
    for report, sample, risk in reports:
        items.append({
            "sample_id":         report.sample_id,
            "filename":          sample.original_filename,
            "package_name":      sample.package_name,
            "app_name":          sample.app_name,
            "sha256":            sample.sha256,
            "threat_assessment": report.threat_assessment,
            "executive_summary": (report.executive_summary or "")[:300],
            "immediate_actions": report.immediate_actions or [],
            "generated_at":      report.generated_at,
            "upload_time":       sample.upload_time,
            "risk_score":        risk.risk_score if risk else None,
            "severity":          risk.severity if risk else None,
            "classification":    risk.classification if risk else None,
            "malware_type":      risk.malware_type if risk else None,
            "malware_family":    risk.malware_family if risk else None,
        })

    return {"total": total, "page": page, "limit": limit, "items": items}


# ─────────────────────────────────────────────────────────────
# IOC SEARCH
# ─────────────────────────────────────────────────────────────
@router.get("/threats/search")
def search_iocs(
    q: str = "",
    ioc_type: str = None,
    risk_level: str = None,
    db: Session = Depends(get_db),
):
    """Search IOC records by value, type, or risk level."""
    if not q and not ioc_type and not risk_level:
        return {"total": 0, "query": q, "results": []}

    query = db.query(IOCRecord)
    if q:
        query = query.filter(IOCRecord.ioc_value.ilike(f"%{q}%"))
    if ioc_type:
        query = query.filter(IOCRecord.ioc_type == ioc_type.upper())
    if risk_level:
        query = query.filter(IOCRecord.risk_level == risk_level.upper())

    iocs = query.order_by(IOCRecord.risk_level.desc()).limit(100).all()
    total = query.count()

    # Get sample context for each IOC
    sample_ids = list(set(i.sample_id for i in iocs))
    sample_map = {
        s.sample_id: s
        for s in db.query(APKSample).filter(APKSample.sample_id.in_(sample_ids)).all()
    }

    results = []
    for i in iocs:
        s = sample_map.get(i.sample_id)
        results.append({
            "id":         i.id,
            "ioc_type":   i.ioc_type,
            "ioc_value":  i.ioc_value,
            "risk_level": i.risk_level,
            "context":    i.context,
            "tags":       i.tags or [],
            "sample_id":  i.sample_id,
            "filename":   s.original_filename if s else None,
            "app_name":   s.app_name if s else None,
            "created_at": i.created_at,
        })

    return {"total": total, "query": q, "results": results}


# ─────────────────────────────────────────────────────────────
# CAMPAIGNS
# ─────────────────────────────────────────────────────────────
@router.get("/campaigns")
def list_campaigns(db: Session = Depends(get_db)):
    """List all detected campaigns from Campaign Correlation Agent."""
    agents = (
        db.query(AgentInvestigation)
        .filter(
            AgentInvestigation.agent_name == "campaign_correlation",
            AgentInvestigation.status == "COMPLETED",
        )
        .order_by(AgentInvestigation.completed_at.desc())
        .all()
    )

    campaigns = {}
    for a in agents:
        verdict = a.verdict or ""
        # Extract campaign name from verdict
        if "CAMPAIGN" in verdict or "campaign" in (a.evidence or []):
            reasoning = a.reasoning or []
            campaign_name = next(
                (r for r in reasoning if "campaign" in r.lower()), verdict
            )
            if campaign_name not in campaigns:
                campaigns[campaign_name] = {
                    "campaign_name":    campaign_name,
                    "sample_ids":       [],
                    "first_seen":       a.completed_at,
                    "last_seen":        a.completed_at,
                    "total_samples":    0,
                }
            campaigns[campaign_name]["sample_ids"].append(a.sample_id)
            campaigns[campaign_name]["total_samples"] += 1
            if a.completed_at and a.completed_at > campaigns[campaign_name]["last_seen"]:
                campaigns[campaign_name]["last_seen"] = a.completed_at

    return {
        "total": len(campaigns),
        "campaigns": list(campaigns.values()),
    }


# ─────────────────────────────────────────────────────────────
# MALWARE FAMILIES
# ─────────────────────────────────────────────────────────────
@router.get("/malware-families")
def list_malware_families(db: Session = Depends(get_db)):
    """List all detected malware families with sample counts and stats."""
    from sqlalchemy import func

    family_rows = (
        db.query(
            RiskScoreRecord.malware_family,
            RiskScoreRecord.malware_type,
            func.count(RiskScoreRecord.id).label("count"),
            func.avg(RiskScoreRecord.risk_score).label("avg_risk"),
            func.max(RiskScoreRecord.risk_score).label("max_risk"),
        )
        .filter(
            RiskScoreRecord.malware_family != None,
            RiskScoreRecord.malware_family != "Unknown",
        )
        .group_by(RiskScoreRecord.malware_family, RiskScoreRecord.malware_type)
        .order_by(func.count(RiskScoreRecord.id).desc())
        .all()
    )

    families = []
    for row in family_rows:
        families.append({
            "family":      row.malware_family,
            "type":        row.malware_type,
            "count":       row.count,
            "avg_risk":    round(row.avg_risk or 0, 1),
            "max_risk":    row.max_risk or 0,
        })

    # Also include families from threat signatures knowledge base
    from knowledge.threat_signatures import MALWARE_FAMILIES
    known = [{"name": k, "description": v["description"], "type": v["malware_type"], "severity": v["severity"]} for k, v in MALWARE_FAMILIES.items()]

    return {
        "total": len(families),
        "detected_families": families,
        "known_signatures": known,
    }


# ─────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────
def _get_sample_or_404(sample_id: str, db: Session) -> APKSample:
    sample = db.query(APKSample).filter_by(sample_id=sample_id).first()
    if not sample:
        raise HTTPException(status_code=404, detail=f"Sample {sample_id} not found")
    return sample
