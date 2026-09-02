"""
GARUD-AI Pipeline Stage 5 — Network Analysis & IOC Extraction
Extracts domains, IPs, URLs from static findings. Detects C2 patterns. Creates IOC records.
"""
import re
import logging
from sqlalchemy.orm import Session
from models import APKSample, StaticAnalysisResult, NetworkAnalysisResult, IOCRecord

logger = logging.getLogger("garud_ai.pipeline.network_analysis")

# Known benign / CDN domains to exclude from flagging
BENIGN_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "firebase.io", "firebaseio.com",
    "firebase.google.com", "crashlytics.com", "facebook.com", "instagram.com",
    "twitter.com", "amazon.com", "amazonaws.com", "cloudfront.net",
    "github.com", "githubusercontent.com", "cdn.jsdelivr.net", "cloudflare.com",
    "android.googlesource.com", "play.google.com", "www.google.com",
}

# Suspicious TLDs often used by malicious actors
SUSPICIOUS_TLDS = {".tk", ".cf", ".ga", ".ml", ".gq", ".xyz", ".top", ".club",
                   ".online", ".site", ".live", ".pw", ".cc", ".su"}

# C2-like URL patterns
C2_PATTERNS = [
    r'/gate\.php', r'/panel', r'/bot', r'/cmd', r'/command',
    r'/upload', r'/collect', r'/data', r'/report', r'/post',
    r'api/v\d+/\w+', r'/receive', r'/fetch', r'/payload',
]

# Dynamic DNS providers (often used for C2)
DDNS_PROVIDERS = {
    "no-ip.com", "noip.com", "ddns.net", "duckdns.org", "freedns.afraid.org",
    "changeip.com", "hopto.org", "servebeer.com", "servecounterstrike.com",
}


def run(sample_id: str, db: Session) -> None:
    """Stage 5: Network analysis and IOC extraction."""
    logger.info(f"[{sample_id}] Network analysis: starting")

    sample = db.query(APKSample).filter_by(sample_id=sample_id).first()
    static = db.query(StaticAnalysisResult).filter_by(sample_id=sample_id).first()

    if not sample:
        raise RuntimeError(f"Sample {sample_id} not found")

    urls_raw  = (static.extracted_urls or []) if static else []
    ips_raw   = (static.extracted_ips or []) if static else []

    # ── Domain extraction from URLs ───────────────────────────
    all_domains = []
    for url in urls_raw:
        domain = _extract_domain(url)
        if domain:
            all_domains.append(domain)
    all_domains = list(set(all_domains))

    # ── Domain classification ─────────────────────────────────
    suspicious_domains = []
    c2_candidates      = []
    uses_ddns          = False

    for domain in all_domains:
        if _is_benign(domain):
            continue
        flags = _analyze_domain(domain)
        if flags["is_suspicious"]:
            suspicious_domains.append({"domain": domain, "reasons": flags["reasons"]})
        if flags["is_c2_candidate"]:
            c2_candidates.append({"domain": domain, "reasons": flags["reasons"]})
        if flags.get("is_ddns"):
            uses_ddns = True

    # ── C2 detection from URL patterns ───────────────────────
    api_endpoints    = []
    has_c2_comm      = bool(c2_candidates)
    has_exfil_ep     = False
    c2_pattern_hits  = []

    for url in urls_raw:
        for pattern in C2_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                c2_pattern_hits.append({"url": url, "pattern": pattern})
                has_c2_comm  = True
                has_exfil_ep = True
                break
        # Detect API-like endpoints
        if re.search(r'/api/', url, re.IGNORECASE):
            api_endpoints.append(url)

    # ── IP classification ─────────────────────────────────────
    suspicious_ips = []
    for ip in ips_raw:
        if not _is_private_ip(ip):
            suspicious_ips.append({"ip": ip, "note": "Hardcoded public IP — potential C2"})
            if ip not in [i["ip"] for i in suspicious_ips[:-1]]:
                has_c2_comm = True

    # ── Persist NetworkAnalysisResult ────────────────────────
    existing = db.query(NetworkAnalysisResult).filter_by(sample_id=sample_id).first()
    if existing:
        net = existing
    else:
        net = NetworkAnalysisResult(sample_id=sample_id)
        db.add(net)

    net.domains             = all_domains[:50]
    net.suspicious_domains  = suspicious_domains[:20]
    net.c2_candidates       = c2_candidates[:10]
    net.ip_addresses        = ips_raw[:30]
    net.suspicious_ips      = suspicious_ips[:20]
    net.urls                = urls_raw[:50]
    net.api_endpoints       = api_endpoints[:20]
    net.dns_patterns        = c2_pattern_hits[:10]
    net.has_c2_communication    = has_c2_comm
    net.has_data_exfil_endpoint = has_exfil_ep
    net.uses_dynamic_dns        = uses_ddns
    db.flush()

    # ── Create IOC Records ────────────────────────────────────
    _clear_existing_iocs(sample_id, db)
    iocs_created = 0

    # SHA256 hash IOC
    if sample.sha256:
        db.add(IOCRecord(sample_id=sample_id, ioc_type="HASH", ioc_value=sample.sha256,
                         context="SHA256 file hash", risk_level="MEDIUM"))
        iocs_created += 1

    # Domain IOCs
    for dom_info in suspicious_domains:
        db.add(IOCRecord(
            sample_id=sample_id, ioc_type="DOMAIN",
            ioc_value=dom_info["domain"],
            context=", ".join(dom_info["reasons"]),
            risk_level="HIGH",
            tags=["suspicious_domain"]
        ))
        iocs_created += 1

    for c2 in c2_candidates:
        db.add(IOCRecord(
            sample_id=sample_id, ioc_type="DOMAIN",
            ioc_value=c2["domain"],
            context="Potential C2: " + ", ".join(c2["reasons"]),
            risk_level="CRITICAL",
            tags=["c2", "command_control"]
        ))
        iocs_created += 1

    # IP IOCs
    for ip_info in suspicious_ips[:10]:
        db.add(IOCRecord(
            sample_id=sample_id, ioc_type="IP",
            ioc_value=ip_info["ip"],
            context=ip_info["note"],
            risk_level="HIGH",
            tags=["hardcoded_ip"]
        ))
        iocs_created += 1

    # URL IOCs (C2 endpoints)
    for hit in c2_pattern_hits[:5]:
        db.add(IOCRecord(
            sample_id=sample_id, ioc_type="URL",
            ioc_value=hit["url"],
            context=f"C2 pattern: {hit['pattern']}",
            risk_level="CRITICAL",
            tags=["c2_endpoint"]
        ))
        iocs_created += 1

    # Certificate IOC
    if sample.cert_fingerprint:
        db.add(IOCRecord(
            sample_id=sample_id, ioc_type="CERT",
            ioc_value=sample.cert_fingerprint,
            context="APK signing certificate fingerprint",
            risk_level="MEDIUM" if sample.is_self_signed else "LOW",
            tags=["self_signed"] if sample.is_self_signed else []
        ))
        iocs_created += 1

    db.commit()
    logger.info(f"[{sample_id}] Network analysis: completed — {len(all_domains)} domains, {len(suspicious_domains)} suspicious, {iocs_created} IOCs created")


# ── Helpers ──────────────────────────────────────────────────
def _extract_domain(url: str) -> str:
    match = re.search(r'https?://([^/\?:]+)', url, re.IGNORECASE)
    return match.group(1).lower() if match else None


def _is_benign(domain: str) -> bool:
    for benign in BENIGN_DOMAINS:
        if domain == benign or domain.endswith("." + benign):
            return True
    return False


def _is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    first, second = int(parts[0]), int(parts[1])
    return (first == 10 or first == 127 or
            (first == 172 and 16 <= second <= 31) or
            (first == 192 and second == 168))


def _analyze_domain(domain: str) -> dict:
    reasons = []
    is_suspicious = False
    is_c2 = False
    is_ddns = False

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            is_suspicious = True
            reasons.append(f"Suspicious TLD: {tld}")
            break

    # DDNS provider
    for ddns in DDNS_PROVIDERS:
        if ddns in domain:
            is_suspicious = True
            is_c2 = True
            is_ddns = True
            reasons.append(f"Dynamic DNS provider: {ddns}")
            break

    # Very short domain (potential DGA)
    base = domain.split(".")[0]
    if len(base) <= 5 and base.isalpha():
        reasons.append("Very short domain name (possible DGA)")
        is_suspicious = True

    # Random-looking domain (high consonant ratio)
    consonants = sum(1 for c in base if c.lower() in "bcdfghjklmnpqrstvwxyz")
    if len(base) > 6 and consonants / len(base) > 0.75:
        reasons.append("High consonant ratio — possible DGA or random subdomain")
        is_suspicious = True
        is_c2 = True

    return {"is_suspicious": is_suspicious, "is_c2_candidate": is_c2, "is_ddns": is_ddns, "reasons": reasons}


def _clear_existing_iocs(sample_id: str, db: Session):
    db.query(IOCRecord).filter_by(sample_id=sample_id).delete()
    db.flush()
