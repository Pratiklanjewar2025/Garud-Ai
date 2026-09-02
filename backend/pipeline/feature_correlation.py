"""
GARUD-AI Pipeline Stage 6 — Feature Correlation Engine
Merges evidence from all analysis layers into a unified feature vector for AI agents.
"""
import logging
from sqlalchemy.orm import Session
from models import (
    APKSample, StaticAnalysisResult, DynamicAnalysisResult,
    NetworkAnalysisResult, MalwareDNAProfile, IOCRecord
)
from knowledge.threat_signatures import match_malware_family

logger = logging.getLogger("garud_ai.pipeline.feature_correlation")


def run(sample_id: str, db: Session) -> None:
    """Stage 6: Correlate all analysis layers into unified feature vector."""
    logger.info(f"[{sample_id}] Feature correlation: starting")

    sample  = db.query(APKSample).filter_by(sample_id=sample_id).first()
    static  = db.query(StaticAnalysisResult).filter_by(sample_id=sample_id).first()
    dynamic = db.query(DynamicAnalysisResult).filter_by(sample_id=sample_id).first()
    network = db.query(NetworkAnalysisResult).filter_by(sample_id=sample_id).first()
    dna     = db.query(MalwareDNAProfile).filter_by(sample_id=sample_id).first()
    iocs    = db.query(IOCRecord).filter_by(sample_id=sample_id).all()

    # ── Cross-layer correlation signals ───────────────────────
    risk_signals = []

    # Signal 1: SMS permission + network = potential OTP theft
    has_sms  = static.has_sms_permissions if static else False
    has_net  = "android.permission.INTERNET" in (sample.permissions or [])
    if has_sms and has_net:
        risk_signals.append({"signal": "OTP_THEFT_VECTOR", "weight": 25,
                             "description": "SMS read/receive combined with internet access — OTP interception pathway"})

    # Signal 2: Accessibility + overlay = banking credential theft
    has_acc  = static.has_accessibility_service if static else False
    has_over = static.has_overlay_permission if static else False
    if has_acc and has_over:
        risk_signals.append({"signal": "BANKING_CREDENTIAL_THEFT", "weight": 30,
                             "description": "Accessibility service + overlay — classic banking overlay attack vector"})

    # Signal 3: C2 + data collection = exfiltration
    has_c2   = network.has_c2_communication if network else False
    has_exfil = dynamic.can_exfiltrate_data if dynamic else False
    if has_c2 and has_exfil:
        risk_signals.append({"signal": "DATA_EXFILTRATION", "weight": 25,
                             "description": "C2 server detected + data collection capabilities — active exfiltration risk"})

    # Signal 4: Obfuscation + suspicious API = active evasion
    if static and static.is_obfuscated and static.reflection_apis:
        risk_signals.append({"signal": "ACTIVE_EVASION", "weight": 20,
                             "description": "Code obfuscation + dynamic class loading — active anti-analysis evasion"})

    # Signal 5: Self-signed cert + network = untrusted app communicating to internet
    if sample.is_self_signed and has_net:
        risk_signals.append({"signal": "UNTRUSTED_NETWORK_APP", "weight": 10,
                             "description": "Self-signed certificate + internet access — not from legitimate source"})

    # Signal 6: Device admin + boot persistence = RAT/rootkit
    has_admin = static.has_device_admin if static else False
    has_boot  = "android.permission.RECEIVE_BOOT_COMPLETED" in (sample.permissions or [])
    if has_admin and has_boot:
        risk_signals.append({"signal": "PERSISTENCE_MECHANISM", "weight": 25,
                             "description": "Device admin + boot persistence — ransomware or RAT persistence"})

    # ── Compute cross-layer risk score ────────────────────────
    raw_score = sum(s["weight"] for s in risk_signals)
    # Add base scores from individual layers
    static_base  = (static.permission_risk_score or 0) * 0.3 if static else 0
    dynamic_base = (len(dynamic.runtime_events or []) * 3) if dynamic else 0
    network_base = (len(network.c2_candidates or []) * 8) if network else 0
    dns_score    = (len(dna.suspected_family or "") * 2) if dna and dna.suspected_family else 0

    total_score = min(int(raw_score + static_base + dynamic_base + network_base + dns_score), 100)

    # ── Malware family re-check with full API evidence ────────
    api_categories = []
    if static and static.suspicious_apis:
        api_categories = list(set(a.get("category", "") for a in static.suspicious_apis))

    full_family_match = match_malware_family(
        permissions=sample.permissions or [],
        apis=api_categories,
        package_name=sample.package_name or ""
    )

    # Update DNA profile with richer family info
    if dna and full_family_match and (full_family_match.get("confidence", 0) > (dna.family_confidence or 0)):
        dna.suspected_family  = full_family_match["family"]
        dna.family_confidence = full_family_match["confidence"]
        dna.family_match_reason = full_family_match["reasons"]

    # ── Build unified feature vector ─────────────────────────
    feature_vector = {
        # Sample identity
        "sample_id":   sample_id,
        "package_name": sample.package_name,
        "sha256":       sample.sha256,

        # Permission evidence
        "permission_count":  len(sample.permissions or []),
        "dangerous_perm_count": len(static.dangerous_permissions or []) if static else 0,
        "permission_risk_score": static.permission_risk_score if static else 0,
        "key_permissions": [
            p for p in (sample.permissions or [])
            if any(kw in p for kw in ["SMS", "CONTACT", "LOCATION", "CAMERA", "ACCESSIBILITY", "ADMIN", "OVERLAY"])
        ],

        # Static evidence
        "suspicious_api_count":   len(static.suspicious_apis or []) if static else 0,
        "obfuscation_score":      static.obfuscation_score if static else 0,
        "has_reflection":         bool(static.reflection_apis) if static else False,
        "extracted_url_count":    len(static.extracted_urls or []) if static else 0,

        # Risk flags
        "has_accessibility_service": static.has_accessibility_service if static else False,
        "has_overlay":               static.has_overlay_permission if static else False,
        "has_device_admin":          static.has_device_admin if static else False,
        "has_sms_access":            static.has_sms_permissions if static else False,
        "has_contact_access":        static.has_contact_permissions if static else False,

        # Dynamic capabilities
        "can_intercept_sms":    dynamic.can_intercept_sms if dynamic else False,
        "can_harvest_contacts": dynamic.can_harvest_contacts if dynamic else False,
        "can_overlay":          dynamic.can_record_screen if dynamic else False,
        "can_keylog":           dynamic.can_keylog if dynamic else False,
        "can_exfiltrate":       dynamic.can_exfiltrate_data if dynamic else False,
        "can_control_device":   dynamic.can_control_device if dynamic else False,

        # Network/IOC
        "domain_count":       len(network.domains or []) if network else 0,
        "suspicious_domains": len(network.suspicious_domains or []) if network else 0,
        "c2_candidates":      len(network.c2_candidates or []) if network else 0,
        "has_c2":             network.has_c2_communication if network else False,
        "ioc_count":          len(iocs),

        # DNA
        "is_known_variant":  dna.is_known_variant if dna else False,
        "suspected_family":  dna.suspected_family if dna else None,
        "family_confidence": dna.family_confidence if dna else 0,

        # Cross-layer signals
        "risk_signals":       risk_signals,
        "correlation_score":  total_score,

        # Certificate
        "is_self_signed": sample.is_self_signed,
    }

    # ── Persist feature vector ────────────────────────────────
    sample.correlated_features = feature_vector
    db.commit()
    logger.info(f"[{sample_id}] Feature correlation: completed — correlation_score={total_score}, signals={len(risk_signals)}")
