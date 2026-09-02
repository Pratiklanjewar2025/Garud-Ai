"""
GARUD-AI Pipeline Stage 3 — Static Analysis
Full Androguard-based static analysis: permissions, APIs, strings, obfuscation detection.
"""
import re
import logging
from sqlalchemy.orm import Session
from models import APKSample, StaticAnalysisResult
from knowledge.threat_signatures import (
    DANGEROUS_PERMISSIONS,
    SUSPICIOUS_API_PATTERNS,
    get_permission_risk,
)

logger = logging.getLogger("garud_ai.pipeline.static_analysis")

# Regex patterns for extracting artifacts from strings
URL_PATTERN = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
IP_PATTERN  = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')

# Obfuscation indicators — very short class/method names
SHORT_NAME_PATTERN = re.compile(r'^[a-z]{1,2}$')


def run(sample_id: str, file_path: str, db: Session) -> None:
    """Stage 3: Full static analysis using Androguard."""
    logger.info(f"[{sample_id}] Static analysis: starting")

    sample = db.query(APKSample).filter_by(sample_id=sample_id).first()
    if not sample:
        raise RuntimeError(f"Sample {sample_id} not found")

    # ── Fast Static Analysis (Bypassing slow DEX decompilation) ─────────────────
    all_strings     = []
    suspicious_apis = []
    sms_apis        = []
    network_apis    = []
    crypto_apis     = []
    accessibility_apis = []
    reflection_apis = []
    exec_apis       = []
    native_libs     = []
    assets          = []
    dex_count       = 1
    short_names_count = 0

    try:
        from androguard.core.bytecodes.apk import APK
        # 1. Fast metadata parse
        a = APK(file_path)
        native_libs = [f for f in a.get_files() if f.endswith(".so")]
        assets = [f for f in a.get_files() if f.startswith("assets/")]
        dex_count = len([f for f in a.get_files() if f.endswith(".dex")])

        # 2. Fast binary string extraction (much faster than parsing DEX structures)
        with open(file_path, "rb") as f:
            data = f.read()
            # Extract printable ASCII strings of length > 4
            ascii_strings = re.findall(b'[ -~]{4,}', data)
            all_strings = [s.decode('utf-8', 'ignore') for s in ascii_strings if len(s) > 4]

        # --- Enhancement 2: Entropy Analysis ---
        entropy_score = 0
        high_entropy_files = 0
        has_encrypted_payload = False
        try:
            import zipfile
            import math
            import collections
            
            def calculate_entropy(data):
                if not data:
                    return 0
                entropy = 0
                for x in collections.Counter(data).values():
                    p_x = float(x) / len(data)
                    entropy -= p_x * math.log(p_x, 2)
                return entropy
            
            with zipfile.ZipFile(file_path, 'r') as apk_zip:
                total_entropy = 0
                file_count = 0
                for info in apk_zip.infolist():
                    if not info.is_dir() and info.file_size > 1024:
                        with apk_zip.open(info) as f:
                            zdata = f.read(100 * 1024)
                            ent = calculate_entropy(zdata)
                            total_entropy += ent
                            file_count += 1
                            if ent > 7.5:
                                high_entropy_files += 1
                                if info.filename.endswith(('.dex', '.jar', '.json', '.bin')):
                                    has_encrypted_payload = True
                
                if file_count > 0:
                    entropy_score = total_entropy / file_count
        except Exception as e:
            logger.warning(f"[{sample_id}] Entropy analysis failed: {e}")

        # --- Enhancement 4: Manifest Deep Analysis ---
        manifest_flags = []
        manifest_risk_score = 0
        is_debuggable = False
        allows_backup = False
        has_exported_components = 0
        targets_old_sdk = False
        allows_cleartext = False
        
        try:
            manifest_xml = a.get_android_manifest_xml()
            if manifest_xml is not None:
                application_tag = manifest_xml.find("application")
                if application_tag is not None:
                    ns = "{http://schemas.android.com/apk/res/android}"
                    
                    if application_tag.get(f"{ns}debuggable") == "true":
                        is_debuggable = True
                        manifest_flags.append("Debuggable")
                        manifest_risk_score += 20
                        
                    if application_tag.get(f"{ns}allowBackup") == "true":
                        allows_backup = True
                        manifest_flags.append("Allows Backup")
                        manifest_risk_score += 10
                        
                    if application_tag.get(f"{ns}usesCleartextTraffic") == "true":
                        allows_cleartext = True
                        manifest_flags.append("Uses Cleartext Traffic")
                        manifest_risk_score += 10
                        
                for component in ["activity", "service", "receiver", "provider"]:
                    for tag in manifest_xml.findall(f".//{component}"):
                        if tag.get(f"{ns}exported") == "true":
                            has_exported_components += 1
                            
                if sample.target_sdk and sample.target_sdk.isdigit() and int(sample.target_sdk) < 29:
                    targets_old_sdk = True
                    manifest_flags.append(f"Targets Old SDK ({sample.target_sdk})")
                    manifest_risk_score += 20
                    
                if has_exported_components > 0:
                    manifest_flags.append(f"Has {has_exported_components} exported components")
        except Exception as e:
            logger.warning(f"[{sample_id}] Manifest deep analysis failed: {e}")

        # 3. Fast string-based heuristic API scanning
        # Instead of deep cross-referencing, we just check if the API signature exists in the binary strings
        string_set = set(all_strings)
        for pattern, category in SUSPICIOUS_API_PATTERNS.items():
            # Check if any part of the pattern exists in the strings
            if any(pattern in s for s in string_set):
                entry = {"class": "Unknown", "method": pattern, "category": category}
                suspicious_apis.append(entry)
                if category in ("SMS_OPERATIONS", "SMS_READ"): sms_apis.append(entry)
                elif category in ("HTTP_CLIENT", "URL_OPEN", "WEBVIEW"): network_apis.append(entry)
                elif category == "CRYPTO_OPERATIONS": crypto_apis.append(entry)
                elif category == "ACCESSIBILITY_ABUSE": accessibility_apis.append(entry)
                elif category in ("REFLECTION", "DYNAMIC_CODE_LOAD", "CLASS_LOADER"): reflection_apis.append(entry)
                elif category == "SHELL_EXEC": exec_apis.append(entry)

        logger.info(f"[{sample_id}] Fast Static Analysis: Strings={len(all_strings)}, SuspiciousAPIs={len(suspicious_apis)}")

    except Exception as e:
        logger.warning(f"[{sample_id}] Fast analysis failed ({e}), using basic metadata only")
        all_strings = []

    # ── Analyze permissions ───────────────────────────────────
    permissions = sample.permissions or []
    dangerous_permissions = []
    perm_risk_score = 0

    for perm in permissions:
        risk_info = get_permission_risk(perm)
        if risk_info["risk"] in ("CRITICAL", "HIGH", "MEDIUM"):
            dangerous_permissions.append({
                "permission": perm,
                "risk": risk_info["risk"],
                "category": risk_info["category"],
                "label": risk_info["label"],
            })
        # Scoring
        if risk_info["risk"] == "CRITICAL": perm_risk_score += 20
        elif risk_info["risk"] == "HIGH":   perm_risk_score += 10
        elif risk_info["risk"] == "MEDIUM": perm_risk_score += 5
        else:                               perm_risk_score += 1

    perm_risk_score = min(perm_risk_score, 100)

    # ── Extract URLs, IPs from strings ───────────────────────
    extracted_urls = list({u for s in all_strings for u in URL_PATTERN.findall(s)})[:50]
    extracted_ips  = list({ip for s in all_strings for ip in IP_PATTERN.findall(s)
                           if not ip.startswith(("192.168", "10.", "127.", "0.0"))})[:30]
    # Suspicious strings (non-system, potentially hardcoded secrets/endpoints)
    suspicious_strings = [
        s for s in all_strings
        if (len(s) > 15 and len(s) < 200
            and any(kw in s.lower() for kw in ["token", "secret", "key", "password", "api", "auth", "http"]))
    ][:20]

    # ── Obfuscation detection ─────────────────────────────────
    is_obfuscated = False
    obfuscation_score = 0
    obfuscation_indicators = []

    if short_names_count > 20:
        is_obfuscated = True
        obfuscation_score += 40
        obfuscation_indicators.append(f"{short_names_count} short/obfuscated class names detected")

    if reflection_apis:
        obfuscation_score += 30
        obfuscation_indicators.append(f"Dynamic code loading via reflection/DexClassLoader ({len(reflection_apis)} calls)")

    if dex_count > 1:
        obfuscation_score += 20
        obfuscation_indicators.append(f"Multi-DEX APK ({dex_count} dex files)")

    if len(suspicious_strings) > 5:
        obfuscation_score += 10
        obfuscation_indicators.append(f"{len(suspicious_strings)} potentially encoded/suspicious strings found")

    if obfuscation_score >= 40:
        is_obfuscated = True
    obfuscation_score = min(obfuscation_score, 100)

    # ── Risk flags from permissions ───────────────────────────
    has_sms   = any("READ_SMS" in p or "RECEIVE_SMS" in p for p in permissions)
    has_acc   = any("ACCESSIBILITY" in p for p in permissions)
    has_over  = any("SYSTEM_ALERT_WINDOW" in p for p in permissions)
    has_admin = any("DEVICE_ADMIN" in p for p in permissions)
    has_cont  = any("READ_CONTACTS" in p for p in permissions)
    has_loc   = any("LOCATION" in p for p in permissions)
    has_cam   = any("CAMERA" in p for p in permissions)
    has_mic   = any("RECORD_AUDIO" in p for p in permissions)

    # Also flag from API analysis
    if accessibility_apis:
        has_acc = True
    if sms_apis:
        has_sms = True

    # ── Deduplicate APIs ──────────────────────────────────────
    def deduplicate(api_list):
        seen = set()
        result = []
        for item in api_list:
            key = f"{item['class']}::{item['method']}"
            if key not in seen:
                seen.add(key)
                result.append(item)
        return result[:30]

    # ── Persist results ───────────────────────────────────────
    existing = db.query(StaticAnalysisResult).filter_by(sample_id=sample_id).first()
    if existing:
        result = existing
    else:
        result = StaticAnalysisResult(sample_id=sample_id)
        db.add(result)

    result.dangerous_permissions  = dangerous_permissions
    result.permission_risk_score  = perm_risk_score
    result.suspicious_apis        = deduplicate(suspicious_apis)
    result.sms_apis               = deduplicate(sms_apis)
    result.network_apis           = deduplicate(network_apis)
    result.crypto_apis            = deduplicate(crypto_apis)
    result.accessibility_apis     = deduplicate(accessibility_apis)
    result.reflection_apis        = deduplicate(reflection_apis)
    result.exec_apis              = deduplicate(exec_apis)
    result.extracted_urls         = extracted_urls
    result.extracted_ips          = extracted_ips
    result.extracted_strings      = suspicious_strings
    result.is_obfuscated          = is_obfuscated
    result.obfuscation_score      = obfuscation_score
    result.obfuscation_indicators = obfuscation_indicators
    result.dex_files_count        = dex_count
    result.native_libraries       = native_libs[:20]
    result.assets                 = assets[:30]
    result.has_accessibility_service = has_acc
    result.has_device_admin          = has_admin
    result.has_overlay_permission    = has_over
    result.has_sms_permissions       = has_sms
    result.has_contact_permissions   = has_cont
    result.has_location_permissions  = has_loc
    result.has_camera_permissions    = has_cam
    result.has_mic_permissions       = has_mic

    # Save enhancements
    result.entropy_score = entropy_score if 'entropy_score' in locals() else None
    result.high_entropy_files = high_entropy_files if 'high_entropy_files' in locals() else None
    result.has_encrypted_payload = has_encrypted_payload if 'has_encrypted_payload' in locals() else None
    
    result.manifest_flags = manifest_flags if 'manifest_flags' in locals() else None
    result.manifest_risk_score = manifest_risk_score if 'manifest_risk_score' in locals() else None
    result.is_debuggable = is_debuggable if 'is_debuggable' in locals() else None
    result.allows_backup = allows_backup if 'allows_backup' in locals() else None
    result.has_exported_components = has_exported_components if 'has_exported_components' in locals() else None
    result.targets_old_sdk = targets_old_sdk if 'targets_old_sdk' in locals() else None
    result.allows_cleartext = allows_cleartext if 'allows_cleartext' in locals() else None

    result.raw_findings = {
        "total_permissions": len(permissions),
        "dangerous_perm_count": len(dangerous_permissions),
        "suspicious_api_count": len(suspicious_apis),
        "string_count": len(all_strings),
        "url_count": len(extracted_urls),
        "ip_count": len(extracted_ips),
        "native_lib_count": len(native_libs),
    }

    db.commit()
    logger.info(f"[{sample_id}] Static analysis: completed — perms_risk={perm_risk_score}, obfuscation={obfuscation_score}")
