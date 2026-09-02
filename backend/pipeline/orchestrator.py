"""
GARUD-AI Pipeline Orchestrator
Master controller: sequences all 8 analysis stages, runs all AI agents, stores results.
"""
import logging
import traceback
from datetime import datetime
from sqlalchemy.orm import Session
from models import APKSample, MalwareDNAProfile, RiskScoreRecord, ThreatReport

logger = logging.getLogger("garud_ai.pipeline.orchestrator")


def run_full_pipeline(sample_id: str, file_path: str, SessionLocal) -> None:
    """
    Entry point called as FastAPI BackgroundTask.
    Creates its own DB session (the request-scoped session closes after HTTP response).
    """
    db: Session = SessionLocal()
    try:
        sample = db.query(APKSample).filter_by(sample_id=sample_id).first()
        if not sample:
            logger.error(f"[{sample_id}] Sample not found — aborting pipeline")
            return

        sample.status  = "ANALYZING"
        sample.analysis_start = datetime.utcnow()
        db.commit()

        logger.info(f"[{sample_id}] ══════════ GARUD-AI PIPELINE STARTED ══════════")

        # ── Stage 1: APK Intake ────────────────────────────────
        _run_stage(db, sample_id, "INTAKE", lambda: _stage_intake(sample_id, file_path, db))

        # ── Stage 2: Malware DNA ───────────────────────────────
        _run_stage(db, sample_id, "MALWARE_DNA", lambda: _stage_dna(sample_id, file_path, db))

        # ── Known variant shortcut ─────────────────────────────
        dna = db.query(MalwareDNAProfile).filter_by(sample_id=sample_id).first()
        if dna and dna.is_known_variant and dna.similar_sample_id:
            logger.info(f"[{sample_id}] ⚡ Known variant — reusing intelligence from {dna.similar_sample_id}")
            _copy_intelligence(sample_id, dna.similar_sample_id, db)
            sample = db.query(APKSample).filter_by(sample_id=sample_id).first()
            sample.status = "COMPLETED"
            sample.pipeline_stage = "COMPLETED"
            sample.analysis_end = datetime.utcnow()
            db.commit()
            logger.info(f"[{sample_id}] ══════════ PIPELINE COMPLETED (CACHED) ══════════")
            return

        # ── Stage 3: Static Analysis ───────────────────────────
        _run_stage(db, sample_id, "STATIC_ANALYSIS", lambda: _stage_static(sample_id, file_path, db))

        # ── Stage 4: Dynamic Analysis ──────────────────────────
        _run_stage(db, sample_id, "DYNAMIC_ANALYSIS", lambda: _stage_dynamic(sample_id, db))

        # ── Stage 5: Network Analysis ──────────────────────────
        _run_stage(db, sample_id, "NETWORK_ANALYSIS", lambda: _stage_network(sample_id, db))

        # ── Stage 6: Feature Correlation ──────────────────────
        _run_stage(db, sample_id, "FEATURE_CORRELATION", lambda: _stage_correlation(sample_id, db))

        # ── Stage 7–8: Agentic AI Investigation ───────────────
        _run_stage(db, sample_id, "AGENT_INVESTIGATION", lambda: _stage_agents(sample_id, db))

        # ── Mark Completed ─────────────────────────────────────
        sample = db.query(APKSample).filter_by(sample_id=sample_id).first()
        sample.status = "COMPLETED"
        sample.pipeline_stage = "COMPLETED"
        sample.analysis_end = datetime.utcnow()
        db.commit()

        duration = (sample.analysis_end - sample.analysis_start).total_seconds()
        logger.info(f"[{sample_id}] ══════════ PIPELINE COMPLETED in {duration:.1f}s ══════════")

    except Exception as e:
        logger.error(f"[{sample_id}] Pipeline failed: {e}\n{traceback.format_exc()}")
        try:
            db.rollback()
            sample = db.query(APKSample).filter_by(sample_id=sample_id).first()
            if sample:
                sample.status = "FAILED"
                sample.error_message = f"{type(e).__name__}: {str(e)}"
                db.commit()
        except Exception as inner:
            logger.error(f"[{sample_id}] Failed to record error state: {inner}")
    finally:
        db.close()


def _run_stage(db: Session, sample_id: str, stage_name: str, fn) -> None:
    """Run a single pipeline stage with status tracking and error isolation."""
    logger.info(f"[{sample_id}] ▶ Stage: {stage_name}")
    try:
        sample = db.query(APKSample).filter_by(sample_id=sample_id).first()
        if sample:
            sample.pipeline_stage = stage_name
            db.commit()
        fn()
        logger.info(f"[{sample_id}] ✓ Stage completed: {stage_name}")
    except Exception as e:
        logger.error(f"[{sample_id}] ✗ Stage failed: {stage_name} — {e}")
        raise  # Re-raise to fail the pipeline


# ── Stage dispatch functions ──────────────────────────────────
def _stage_intake(sample_id, file_path, db):
    from pipeline.intake import run
    run(sample_id, file_path, db)

def _stage_dna(sample_id, file_path, db):
    from pipeline.malware_dna import run
    run(sample_id, file_path, db)

def _stage_static(sample_id, file_path, db):
    from pipeline.static_analysis import run
    run(sample_id, file_path, db)

def _stage_dynamic(sample_id, db):
    from pipeline.dynamic_analysis import run
    run(sample_id, db)

def _stage_network(sample_id, db):
    from pipeline.network_analysis import run
    run(sample_id, db)

def _stage_correlation(sample_id, db):
    from pipeline.feature_correlation import run
    run(sample_id, db)

def _stage_agents(sample_id, db):
    from agents.orchestrator_agent import run
    run(sample_id, db)


def _copy_intelligence(new_id: str, source_id: str, db: Session) -> None:
    """Reuse threat intelligence from a known variant sample."""
    from models import RiskScoreRecord, ThreatReport, AgentInvestigation

    src_risk = db.query(RiskScoreRecord).filter_by(sample_id=source_id).first()
    if src_risk:
        risk = RiskScoreRecord(
            sample_id=new_id,
            risk_score       = src_risk.risk_score,
            confidence_score = max(0, (src_risk.confidence_score or 50) - 5),
            severity         = src_risk.severity,
            classification   = src_risk.classification,
            malware_type     = src_risk.malware_type,
            malware_family   = src_risk.malware_family,
            static_score     = src_risk.static_score,
            dynamic_score    = src_risk.dynamic_score,
            network_score    = src_risk.network_score,
            behavior_score   = src_risk.behavior_score,
            agent_consensus  = {"note": f"Intelligence reused from known variant {source_id}"},
        )
        db.add(risk)

    src_report = db.query(ThreatReport).filter_by(sample_id=source_id).first()
    if src_report:
        report = ThreatReport(
            sample_id          = new_id,
            executive_summary  = f"[Known Variant] This sample is a confirmed variant of {source_id}. " + (src_report.executive_summary or ""),
            threat_assessment  = src_report.threat_assessment,
            ioc_summary        = src_report.ioc_summary,
            mitre_summary      = src_report.mitre_summary,
            behavioral_summary = src_report.behavioral_summary,
            immediate_actions  = src_report.immediate_actions,
            long_term_actions  = src_report.long_term_actions,
        )
        db.add(report)

    db.commit()
    logger.info(f"[{new_id}] Intelligence copied from {source_id}")
