"""
GARUD-AI CyberShield — Complete Database Models
9 tables covering the full analysis pipeline as per system design.
"""
from sqlalchemy import (
    Column, String, Integer, Float, Text, DateTime,
    JSON, Boolean, ForeignKey
)
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base


# ─────────────────────────────────────────────────────────────
# TABLE 1: APK Samples (core record for every uploaded APK)
# ─────────────────────────────────────────────────────────────
class APKSample(Base):
    __tablename__ = "apk_samples"

    sample_id         = Column(String, primary_key=True, index=True)
    original_filename = Column(String)
    sha256            = Column(String, unique=True, index=True)
    md5               = Column(String, nullable=True, index=True)
    sha1              = Column(String, nullable=True)
    file_size         = Column(Integer, nullable=True)
    storage_path      = Column(String)
    source            = Column(String, nullable=True)  # MANUAL, WHATSAPP, SMS, TELEGRAM

    # Pipeline status
    status          = Column(String, default="UPLOADED")   # UPLOADED | ANALYZING | COMPLETED | FAILED
    pipeline_stage  = Column(String, nullable=True)        # Current stage name
    upload_time     = Column(DateTime, default=datetime.utcnow)
    analysis_start  = Column(DateTime, nullable=True)
    analysis_end    = Column(DateTime, nullable=True)

    # APK Manifest metadata
    package_name  = Column(String, nullable=True)
    app_name      = Column(String, nullable=True)
    version_name  = Column(String, nullable=True)
    version_code  = Column(String, nullable=True)
    min_sdk       = Column(String, nullable=True)
    target_sdk    = Column(String, nullable=True)

    # Manifest components (JSON arrays)
    permissions = Column(JSON, nullable=True)
    activities  = Column(JSON, nullable=True)
    services    = Column(JSON, nullable=True)
    receivers   = Column(JSON, nullable=True)
    providers   = Column(JSON, nullable=True)

    # Certificate info
    cert_issuer      = Column(String, nullable=True)
    cert_subject     = Column(String, nullable=True)
    cert_fingerprint = Column(String, nullable=True)
    cert_valid_from  = Column(String, nullable=True)
    cert_valid_to    = Column(String, nullable=True)
    is_self_signed   = Column(Boolean, nullable=True)

    # Certificate deep validation (Enhancement 3)
    cert_is_debug      = Column(Boolean, nullable=True)   # Android debug certificate
    cert_is_expired    = Column(Boolean, nullable=True)   # Certificate past validity
    cert_validity_days = Column(Integer, nullable=True)   # Total validity period in days
    cert_key_size      = Column(Integer, nullable=True)   # RSA key size in bits
    cert_risk_flags    = Column(JSON, nullable=True)      # List of cert risk reasons

    # Cross-layer correlated feature vector (JSON)
    correlated_features = Column(JSON, nullable=True)

    # Error tracking
    error_message = Column(Text, nullable=True)

    # Relationships
    dna_profile      = relationship("MalwareDNAProfile",   back_populates="sample", uselist=False)
    static_analysis  = relationship("StaticAnalysisResult", back_populates="sample", uselist=False)
    dynamic_analysis = relationship("DynamicAnalysisResult", back_populates="sample", uselist=False)
    network_analysis = relationship("NetworkAnalysisResult", back_populates="sample", uselist=False)
    iocs             = relationship("IOCRecord",            back_populates="sample")
    agent_investigations = relationship("AgentInvestigation", back_populates="sample")
    risk_score       = relationship("RiskScoreRecord",      back_populates="sample", uselist=False)
    threat_report    = relationship("ThreatReport",         back_populates="sample", uselist=False)


# ─────────────────────────────────────────────────────────────
# TABLE 2: Malware DNA Profile
# ─────────────────────────────────────────────────────────────
class MalwareDNAProfile(Base):
    __tablename__ = "malware_dna_profiles"

    id        = Column(Integer, primary_key=True, autoincrement=True)
    sample_id = Column(String, ForeignKey("apk_samples.sample_id"), unique=True, index=True)

    # DNA Fingerprint components
    permission_hash = Column(String, nullable=True)   # Hash of sorted permission set
    api_hash        = Column(String, nullable=True)   # Hash of dangerous API patterns
    cert_hash       = Column(String, nullable=True)   # Certificate fingerprint hash
    manifest_hash   = Column(String, nullable=True)   # Hash of manifest structure
    dna_signature   = Column(String, nullable=True)   # Combined DNA string

    # Threat memory result
    is_known_variant  = Column(Boolean, default=False)
    similar_sample_id = Column(String, nullable=True)   # ID of closest matching sample
    similarity_score  = Column(Float, nullable=True)    # 0.0 → 1.0

    # Family detection from signatures
    suspected_family    = Column(String, nullable=True)
    family_confidence   = Column(Float, nullable=True)
    family_match_reason = Column(JSON, nullable=True)

    # VirusTotal results (Enhancement 1)
    vt_positives     = Column(Integer, nullable=True)   # Number of engines flagging as malicious
    vt_total_engines = Column(Integer, nullable=True)   # Total engines checked
    vt_verdict       = Column(String, nullable=True)    # MALICIOUS | SUSPICIOUS | CLEAN | NOT_FOUND
    vt_family        = Column(String, nullable=True)    # Malware family label from VT
    vt_checked       = Column(Boolean, default=False)   # Whether VT was queried
    vt_engine_hits   = Column(JSON, nullable=True)      # Top engine names that flagged it

    created_at = Column(DateTime, default=datetime.utcnow)
    sample = relationship("APKSample", back_populates="dna_profile")


# ─────────────────────────────────────────────────────────────
# TABLE 3: Static Analysis Result
# ─────────────────────────────────────────────────────────────
class StaticAnalysisResult(Base):
    __tablename__ = "static_analysis_results"

    id        = Column(Integer, primary_key=True, autoincrement=True)
    sample_id = Column(String, ForeignKey("apk_samples.sample_id"), unique=True, index=True)

    # Permission analysis
    dangerous_permissions  = Column(JSON, nullable=True)
    permission_risk_score  = Column(Integer, default=0)   # 0-100

    # API call analysis
    suspicious_apis    = Column(JSON, nullable=True)
    sms_apis           = Column(JSON, nullable=True)
    network_apis       = Column(JSON, nullable=True)
    crypto_apis        = Column(JSON, nullable=True)
    accessibility_apis = Column(JSON, nullable=True)
    reflection_apis    = Column(JSON, nullable=True)
    exec_apis          = Column(JSON, nullable=True)    # Runtime.exec() etc.

    # String/artifact extraction
    extracted_urls     = Column(JSON, nullable=True)
    extracted_ips      = Column(JSON, nullable=True)
    extracted_strings  = Column(JSON, nullable=True)

    # Obfuscation
    is_obfuscated          = Column(Boolean, default=False)
    obfuscation_score      = Column(Integer, default=0)    # 0-100
    obfuscation_indicators = Column(JSON, nullable=True)

    # Code structure
    dex_files_count    = Column(Integer, default=1)
    native_libraries   = Column(JSON, nullable=True)
    assets             = Column(JSON, nullable=True)

    # Critical risk flags
    has_accessibility_service = Column(Boolean, default=False)
    has_device_admin          = Column(Boolean, default=False)
    has_overlay_permission    = Column(Boolean, default=False)
    has_sms_permissions       = Column(Boolean, default=False)
    has_contact_permissions   = Column(Boolean, default=False)
    has_location_permissions  = Column(Boolean, default=False)
    has_camera_permissions    = Column(Boolean, default=False)
    has_mic_permissions       = Column(Boolean, default=False)

    # Entropy analysis (Enhancement 2)
    entropy_score       = Column(Float, nullable=True)    # Average entropy of APK contents (0-8)
    high_entropy_files  = Column(JSON, nullable=True)     # Files with entropy > 7.2 (likely encrypted)
    has_encrypted_payload = Column(Boolean, default=False) # True if any entry has very high entropy

    # Manifest deep analysis (Enhancement 4)
    manifest_flags       = Column(JSON, nullable=True)    # Dict of all manifest security flags
    manifest_risk_score  = Column(Integer, default=0)     # 0-100 manifest-specific risk score
    is_debuggable        = Column(Boolean, default=False) # android:debuggable=true
    allows_backup        = Column(Boolean, default=False) # android:allowBackup=true
    has_exported_components = Column(Boolean, default=False) # Exposed components without permission
    targets_old_sdk      = Column(Boolean, default=False) # targetSdk < 28
    allows_cleartext     = Column(Boolean, default=False) # Cleartext HTTP allowed
    package_impersonates = Column(String, nullable=True)  # Name of app being impersonated, if any

    raw_findings = Column(JSON, nullable=True)
    analyzed_at  = Column(DateTime, default=datetime.utcnow)
    sample = relationship("APKSample", back_populates="static_analysis")


# ─────────────────────────────────────────────────────────────
# TABLE 4: Dynamic Analysis Result
# ─────────────────────────────────────────────────────────────
class DynamicAnalysisResult(Base):
    __tablename__ = "dynamic_analysis_results"

    id        = Column(Integer, primary_key=True, autoincrement=True)
    sample_id = Column(String, ForeignKey("apk_samples.sample_id"), unique=True, index=True)

    # Behavior categories
    sms_behaviors     = Column(JSON, nullable=True)
    contact_behaviors = Column(JSON, nullable=True)
    file_behaviors    = Column(JSON, nullable=True)
    network_behaviors = Column(JSON, nullable=True)
    screen_behaviors  = Column(JSON, nullable=True)
    ui_behaviors      = Column(JSON, nullable=True)

    # Capability flags
    can_intercept_sms    = Column(Boolean, default=False)
    can_harvest_contacts = Column(Boolean, default=False)
    can_record_screen    = Column(Boolean, default=False)
    can_control_device   = Column(Boolean, default=False)
    can_exfiltrate_data  = Column(Boolean, default=False)
    can_send_sms         = Column(Boolean, default=False)
    can_keylog           = Column(Boolean, default=False)

    # Analysis method and confidence
    analysis_method = Column(String, default="STATIC_INFERENCE")
    confidence      = Column(Float, default=0.75)

    runtime_events = Column(JSON, nullable=True)
    analyzed_at    = Column(DateTime, default=datetime.utcnow)
    sample = relationship("APKSample", back_populates="dynamic_analysis")


# ─────────────────────────────────────────────────────────────
# TABLE 5: Network Analysis Result
# ─────────────────────────────────────────────────────────────
class NetworkAnalysisResult(Base):
    __tablename__ = "network_analysis_results"

    id        = Column(Integer, primary_key=True, autoincrement=True)
    sample_id = Column(String, ForeignKey("apk_samples.sample_id"), unique=True, index=True)

    domains            = Column(JSON, nullable=True)
    suspicious_domains = Column(JSON, nullable=True)
    c2_candidates      = Column(JSON, nullable=True)
    ip_addresses       = Column(JSON, nullable=True)
    suspicious_ips     = Column(JSON, nullable=True)
    urls               = Column(JSON, nullable=True)
    api_endpoints      = Column(JSON, nullable=True)
    dns_patterns       = Column(JSON, nullable=True)

    # Risk flags
    has_c2_communication          = Column(Boolean, default=False)
    has_data_exfil_endpoint       = Column(Boolean, default=False)
    uses_tor                      = Column(Boolean, default=False)
    uses_dynamic_dns              = Column(Boolean, default=False)
    dga_indicators                = Column(Boolean, default=False)
    has_hardcoded_credentials     = Column(Boolean, default=False)

    analyzed_at = Column(DateTime, default=datetime.utcnow)
    sample = relationship("APKSample", back_populates="network_analysis")


# ─────────────────────────────────────────────────────────────
# TABLE 6: IOC Records (individual indicators of compromise)
# ─────────────────────────────────────────────────────────────
class IOCRecord(Base):
    __tablename__ = "ioc_records"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    sample_id  = Column(String, ForeignKey("apk_samples.sample_id"), index=True)

    ioc_type   = Column(String)           # DOMAIN | IP | URL | HASH | EMAIL | CERT
    ioc_value  = Column(String, index=True)
    context    = Column(String, nullable=True)    # Where/how found
    risk_level = Column(String, default="MEDIUM") # LOW | MEDIUM | HIGH | CRITICAL
    is_confirmed = Column(Boolean, default=False)
    tags       = Column(JSON, nullable=True)       # e.g. ["c2", "banking"]

    created_at = Column(DateTime, default=datetime.utcnow)
    sample = relationship("APKSample", back_populates="iocs")


# ─────────────────────────────────────────────────────────────
# TABLE 7: Agent Investigations (one row per agent per sample)
# ─────────────────────────────────────────────────────────────
class AgentInvestigation(Base):
    __tablename__ = "agent_investigations"

    id        = Column(Integer, primary_key=True, autoincrement=True)
    sample_id = Column(String, ForeignKey("apk_samples.sample_id"), index=True)

    agent_name  = Column(String)   # e.g. "threat_reasoning"
    agent_label = Column(String)   # e.g. "Threat Reasoning Agent"
    agent_index = Column(Integer)  # 1–8

    # Agent output
    verdict         = Column(String, nullable=True)
    confidence      = Column(Integer, default=0)       # 0-100
    reasoning       = Column(JSON, nullable=True)      # List[str] of bullets
    evidence        = Column(JSON, nullable=True)      # Supporting evidence
    recommendations = Column(JSON, nullable=True)

    # MITRE output (Agent 5 only)
    mitre_techniques = Column(JSON, nullable=True)   # [{id, name, tactic, evidence}]

    # Risk scoring output (Agent 6 only)
    risk_score     = Column(Integer, nullable=True)
    severity       = Column(String, nullable=True)
    classification = Column(String, nullable=True)
    score_breakdown = Column(JSON, nullable=True)

    # Status
    status      = Column(String, default="PENDING")  # PENDING | RUNNING | COMPLETED | FAILED
    error       = Column(Text, nullable=True)
    started_at  = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    sample = relationship("APKSample", back_populates="agent_investigations")


# ─────────────────────────────────────────────────────────────
# TABLE 8: Risk Score Record
# ─────────────────────────────────────────────────────────────
class RiskScoreRecord(Base):
    __tablename__ = "risk_score_records"

    id        = Column(Integer, primary_key=True, autoincrement=True)
    sample_id = Column(String, ForeignKey("apk_samples.sample_id"), unique=True, index=True)

    risk_score       = Column(Integer, default=0)    # 0-100
    confidence_score = Column(Integer, default=0)    # 0-100
    severity         = Column(String, nullable=True) # LOW | MEDIUM | HIGH | CRITICAL

    classification = Column(String, nullable=True)   # SAFE | SUSPICIOUS | MALICIOUS
    malware_type   = Column(String, nullable=True)   # Banking Trojan | Spyware | etc.
    malware_family = Column(String, nullable=True)   # FakeBank.X | SMSForwarder.Y | etc.

    # Score breakdown
    static_score    = Column(Integer, default=0)
    dynamic_score   = Column(Integer, default=0)
    network_score   = Column(Integer, default=0)
    behavior_score  = Column(Integer, default=0)
    dna_score       = Column(Integer, default=0)

    agent_consensus = Column(JSON, nullable=True)    # Summary of all agent verdicts
    scored_at       = Column(DateTime, default=datetime.utcnow)
    sample = relationship("APKSample", back_populates="risk_score")


# ─────────────────────────────────────────────────────────────
# TABLE 9: Threat Report
# ─────────────────────────────────────────────────────────────
class ThreatReport(Base):
    __tablename__ = "threat_reports"

    id        = Column(Integer, primary_key=True, autoincrement=True)
    sample_id = Column(String, ForeignKey("apk_samples.sample_id"), unique=True, index=True)

    executive_summary = Column(Text, nullable=True)
    threat_assessment = Column(String, nullable=True)

    technical_findings  = Column(JSON, nullable=True)
    ioc_summary         = Column(JSON, nullable=True)
    mitre_summary       = Column(JSON, nullable=True)
    behavioral_summary  = Column(JSON, nullable=True)
    campaign_info       = Column(JSON, nullable=True)

    immediate_actions   = Column(JSON, nullable=True)
    long_term_actions   = Column(JSON, nullable=True)

    report_version = Column(String, default="1.0")
    generated_at   = Column(DateTime, default=datetime.utcnow)
    sample = relationship("APKSample", back_populates="threat_report")
