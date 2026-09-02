"""
GARUD-AI Pipeline Stage 1 — APK Intake
Validates the APK, computes hashes, extracts manifest metadata, and certificate info.
Updates APKSample with all extracted data.
"""
import os
import re
import hashlib
import logging
import traceback
from datetime import datetime
from sqlalchemy.orm import Session
from models import APKSample

logger = logging.getLogger("garud_ai.pipeline.intake")

VALID_EXTENSIONS = {".apk", ".xapk"}
MAX_FILE_SIZE_BYTES = 200 * 1024 * 1024   # 200 MB


def run(sample_id: str, file_path: str, db: Session) -> None:
    """Stage 1: Validate APK, compute hashes, extract metadata and certificate."""
    logger.info(f"[{sample_id}] Intake: starting")

    sample = db.query(APKSample).filter_by(sample_id=sample_id).first()
    if not sample:
        raise RuntimeError(f"Sample {sample_id} not found")

    # ── File validation ──────────────────────────────────────
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"APK file not found: {file_path}")

    file_size = os.path.getsize(file_path)
    if file_size > MAX_FILE_SIZE_BYTES:
        raise ValueError(f"APK exceeds maximum size: {file_size} bytes")

    # ── Hash computation ─────────────────────────────────────
    with open(file_path, "rb") as f:
        content = f.read()

    sample.md5   = hashlib.md5(content).hexdigest()
    sample.sha1  = hashlib.sha1(content).hexdigest()
    sample.sha256 = hashlib.sha256(content).hexdigest()
    sample.file_size = file_size
    logger.info(f"[{sample_id}] Hashes computed — SHA256: {sample.sha256[:16]}...")

    # ── Androguard metadata extraction ───────────────────────
    try:
        from androguard.core.bytecodes.apk import APK
        a = APK(file_path)

        sample.package_name  = a.get_package()
        sample.app_name      = a.get_app_name()
        sample.version_name  = a.get_androidversion_name()
        sample.version_code  = str(a.get_androidversion_code())
        sample.min_sdk       = str(a.get_min_sdk_version())
        sample.target_sdk    = str(a.get_target_sdk_version())
        sample.permissions   = list(a.get_permissions())
        sample.activities    = list(a.get_activities())
        sample.services      = list(a.get_services())
        sample.receivers     = list(a.get_receivers())
        sample.providers     = list(a.get_providers())

        logger.info(f"[{sample_id}] Metadata extracted: pkg={sample.package_name}, perms={len(sample.permissions or [])}")

        # ── Certificate extraction ─────────────────────────
        try:
            _extract_certificate(a, sample)
        except Exception as cert_err:
            logger.warning(f"[{sample_id}] Certificate extraction failed (non-fatal): {cert_err}")

    except Exception as e:
        logger.warning(f"[{sample_id}] Androguard metadata extraction error: {e}")
        # Non-fatal — we still have hashes; continue pipeline

    db.commit()
    logger.info(f"[{sample_id}] Intake: completed")


def _extract_certificate(a, sample: APKSample) -> None:
    """Extract and store certificate details from the APK."""
    try:
        # Androguard 3.4 — get_certificates() returns pyOpenSSL or cryptography objects
        certs = a.get_certificates_der_v2()
        if not certs:
            certs = a.get_certificates()

        if certs:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            cert_der = list(certs.values())[0] if isinstance(certs, dict) else certs[0]
            if isinstance(cert_der, (bytes, bytearray)):
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                sample.cert_issuer  = cert.issuer.rfc4514_string()
                sample.cert_subject = cert.subject.rfc4514_string()
                sample.cert_fingerprint = cert.fingerprint(
                    __import__("cryptography.hazmat.primitives.hashes", fromlist=["SHA256"]).SHA256()
                ).hex()
                sample.cert_valid_from = str(cert.not_valid_before)
                sample.cert_valid_to   = str(cert.not_valid_after)
                sample.is_self_signed  = (cert.issuer == cert.subject)
                
                # --- Enhancement 3: Certificate Deep Validation ---
                try:
                    now = datetime.utcnow()
                    sample.cert_is_expired = cert.not_valid_after < now
                    delta = cert.not_valid_after - cert.not_valid_before
                    sample.cert_validity_days = delta.days
                except Exception:
                    pass

                try:
                    pub_key = cert.public_key()
                    from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
                    if isinstance(pub_key, rsa.RSAPublicKey):
                        sample.cert_key_size = pub_key.key_size
                    elif isinstance(pub_key, dsa.DSAPublicKey):
                        sample.cert_key_size = pub_key.key_size
                    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                        sample.cert_key_size = pub_key.curve.key_size
                except Exception:
                    pass

                sample.cert_is_debug = "Android Debug" in sample.cert_subject or "Android Debug" in sample.cert_issuer
                
                risk_flags = []
                if sample.cert_is_debug:
                    risk_flags.append("Debug Certificate (Not meant for production)")
                if sample.is_self_signed and not sample.cert_is_debug:
                    risk_flags.append("Self-Signed Certificate (Suspicious for banking apps)")
                if sample.cert_is_expired:
                    risk_flags.append("Expired Certificate")
                if sample.cert_validity_days and sample.cert_validity_days > 3650:
                    risk_flags.append(f"Excessive Validity Period ({sample.cert_validity_days} days)")
                if sample.cert_key_size and sample.cert_key_size < 2048:
                    risk_flags.append(f"Weak Key Size ({sample.cert_key_size} bits)")
                    
                sample.cert_risk_flags = risk_flags
    except Exception as e:
        # Try alternative Androguard API
        try:
            sigs = a.get_signature_names()
            if sigs:
                sample.cert_fingerprint = str(sigs[0])
                # Detect self-signed by checking common issuer/subject equality heuristic
                sample.is_self_signed = True  # Conservative default
        except Exception:
            pass
