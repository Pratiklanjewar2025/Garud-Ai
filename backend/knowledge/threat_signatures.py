"""
GARUD-AI Threat Intelligence Signatures
Malware family patterns for Android threat classification.
"""

# ─────────────────────────────────────────────────────────────
# DANGEROUS ANDROID PERMISSIONS (risk-classified)
# ─────────────────────────────────────────────────────────────
DANGEROUS_PERMISSIONS = {
    # CRITICAL - direct data theft / device control
    "android.permission.READ_SMS":                  {"risk": "CRITICAL", "category": "sms", "label": "Read SMS"},
    "android.permission.RECEIVE_SMS":               {"risk": "CRITICAL", "category": "sms", "label": "Receive SMS"},
    "android.permission.SEND_SMS":                  {"risk": "CRITICAL", "category": "sms", "label": "Send SMS"},
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {"risk": "CRITICAL", "category": "accessibility", "label": "Accessibility Service"},
    "android.permission.SYSTEM_ALERT_WINDOW":       {"risk": "CRITICAL", "category": "overlay", "label": "Display over other apps"},
    "android.permission.BIND_DEVICE_ADMIN":         {"risk": "CRITICAL", "category": "admin", "label": "Device Administrator"},
    "android.permission.READ_CALL_LOG":             {"risk": "HIGH",     "category": "call", "label": "Read Call Log"},
    "android.permission.PROCESS_OUTGOING_CALLS":    {"risk": "HIGH",     "category": "call", "label": "Intercept Outgoing Calls"},

    # HIGH - significant surveillance capability
    "android.permission.READ_CONTACTS":             {"risk": "HIGH", "category": "contacts", "label": "Read Contacts"},
    "android.permission.WRITE_CONTACTS":            {"risk": "HIGH", "category": "contacts", "label": "Write Contacts"},
    "android.permission.ACCESS_FINE_LOCATION":      {"risk": "HIGH", "category": "location", "label": "Precise Location"},
    "android.permission.ACCESS_COARSE_LOCATION":    {"risk": "MEDIUM", "category": "location", "label": "Approximate Location"},
    "android.permission.RECORD_AUDIO":              {"risk": "HIGH", "category": "mic", "label": "Record Audio (Microphone)"},
    "android.permission.CAMERA":                    {"risk": "HIGH", "category": "camera", "label": "Camera Access"},
    "android.permission.READ_EXTERNAL_STORAGE":     {"risk": "MEDIUM", "category": "storage", "label": "Read External Storage"},
    "android.permission.WRITE_EXTERNAL_STORAGE":    {"risk": "MEDIUM", "category": "storage", "label": "Write External Storage"},

    # MEDIUM - data collection
    "android.permission.GET_ACCOUNTS":              {"risk": "MEDIUM", "category": "accounts", "label": "Get Accounts"},
    "android.permission.USE_CREDENTIALS":           {"risk": "HIGH",   "category": "accounts", "label": "Use Account Credentials"},
    "android.permission.INTERNET":                  {"risk": "LOW",    "category": "network", "label": "Internet Access"},
    "android.permission.RECEIVE_BOOT_COMPLETED":    {"risk": "MEDIUM", "category": "persistence", "label": "Run at Boot"},
    "android.permission.QUERY_ALL_PACKAGES":        {"risk": "LOW",    "category": "discovery", "label": "Query All Packages"},
    "android.permission.REQUEST_INSTALL_PACKAGES":  {"risk": "HIGH",   "category": "install", "label": "Install Packages"},
}


# ─────────────────────────────────────────────────────────────
# SUSPICIOUS API PATTERNS
# ─────────────────────────────────────────────────────────────
SUSPICIOUS_API_PATTERNS = {
    # SMS
    "Landroid/telephony/SmsManager":            "SMS_OPERATIONS",
    "Landroid/provider/Telephony$Sms":          "SMS_READ",

    # Contacts
    "Landroid/provider/ContactsContract":       "CONTACT_HARVEST",

    # Accessibility (overlay / keylogging attacks)
    "Landroid/accessibilityservice/Accessibility": "ACCESSIBILITY_ABUSE",
    "Landroid/view/accessibility/AccessibilityEvent": "ACCESSIBILITY_EVENTS",

    # Overlay attacks
    "Landroid/view/WindowManager":              "OVERLAY_DRAW",

    # Device admin (ransomware / persistence)
    "Landroid/app/admin/DevicePolicyManager":   "DEVICE_ADMIN",

    # Camera & microphone (spyware)
    "Landroid/hardware/Camera":                 "CAMERA_CAPTURE",
    "Landroid/media/AudioRecord":               "AUDIO_RECORD",
    "Landroid/media/MediaRecorder":             "MEDIA_RECORD",

    # Location
    "Landroid/location/LocationManager":        "LOCATION_TRACK",

    # Account stealing
    "Landroid/accounts/AccountManager":         "ACCOUNT_ACCESS",

    # Crypto (used to encrypt C2 traffic or encrypted payloads)
    "Ljavax/crypto/":                           "CRYPTO_OPERATIONS",
    "Ljava/security/":                          "CRYPTO_OPERATIONS",

    # Reflection / dynamic code loading (obfuscation / dropper)
    "Ljava/lang/reflect/":                      "REFLECTION",
    "Ldalvik/system/DexClassLoader":            "DYNAMIC_CODE_LOAD",
    "Ldalvik/system/InMemoryDexClassLoader":    "DYNAMIC_CODE_LOAD",
    "Ljava/lang/ClassLoader":                   "CLASS_LOADER",

    # Shell execution (root exploits)
    "Ljava/lang/Runtime":                       "SHELL_EXEC",
    "Ljava/lang/ProcessBuilder":                "SHELL_EXEC",

    # Network
    "Ljava/net/HttpURLConnection":              "HTTP_CLIENT",
    "Ljava/net/URL":                            "URL_OPEN",
    "Landroid/webkit/WebView":                  "WEBVIEW",

    # Clipboard
    "Landroid/content/ClipboardManager":        "CLIPBOARD_ACCESS",

    # Boot persistence
    "android.intent.action.BOOT_COMPLETED":     "BOOT_PERSISTENCE",
}


# ─────────────────────────────────────────────────────────────
# MALWARE FAMILY SIGNATURES
# ─────────────────────────────────────────────────────────────
MALWARE_FAMILIES = {

    "BankingTrojan": {
        "description": "Banking credential-stealing Trojan using overlay attacks",
        "malware_type": "Banking Trojan",
        "required_permissions": ["android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.INTERNET"],
        "optional_permissions": ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS"],
        "required_apis": ["ACCESSIBILITY_ABUSE", "OVERLAY_DRAW"],
        "package_patterns": ["com.bank", "com.secure", "com.wallet", "bank", "secure", "update"],
        "risk_score_base": 85,
        "severity": "CRITICAL",
    },

    "SMSForwarder": {
        "description": "SMS interception and forwarding malware for OTP theft",
        "malware_type": "SMS Trojan",
        "required_permissions": ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.INTERNET"],
        "optional_permissions": ["android.permission.READ_CONTACTS"],
        "required_apis": ["SMS_OPERATIONS", "SMS_READ"],
        "package_patterns": [],
        "risk_score_base": 80,
        "severity": "CRITICAL",
    },

    "CredentialStealer": {
        "description": "Phishing overlay application for banking/UPI credential theft",
        "malware_type": "Credential Stealer",
        "required_permissions": ["android.permission.SYSTEM_ALERT_WINDOW", "android.permission.INTERNET"],
        "optional_permissions": ["android.permission.BIND_ACCESSIBILITY_SERVICE"],
        "required_apis": ["OVERLAY_DRAW", "WEBVIEW"],
        "package_patterns": ["com.upi", "com.payment", "com.bhim", "com.phonepe", "com.gpay"],
        "risk_score_base": 82,
        "severity": "CRITICAL",
    },

    "Spyware": {
        "description": "Comprehensive spyware collecting location, contacts, audio, and device data",
        "malware_type": "Spyware",
        "required_permissions": ["android.permission.READ_CONTACTS", "android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET"],
        "optional_permissions": ["android.permission.RECORD_AUDIO", "android.permission.CAMERA"],
        "required_apis": ["LOCATION_TRACK", "CONTACT_HARVEST"],
        "package_patterns": ["com.track", "com.monitor", "com.spy"],
        "risk_score_base": 78,
        "severity": "HIGH",
    },

    "RAT": {
        "description": "Remote Access Trojan with full device control",
        "malware_type": "Remote Access Trojan",
        "required_permissions": ["android.permission.BIND_DEVICE_ADMIN", "android.permission.INTERNET", "android.permission.RECEIVE_BOOT_COMPLETED"],
        "optional_permissions": [],
        "required_apis": ["DEVICE_ADMIN", "BOOT_PERSISTENCE"],
        "package_patterns": [],
        "risk_score_base": 90,
        "severity": "CRITICAL",
    },

    "LoanFraudApp": {
        "description": "Fraudulent loan application harvesting contacts and media for extortion",
        "malware_type": "Loan Fraud App",
        "required_permissions": ["android.permission.READ_CONTACTS", "android.permission.READ_SMS", "android.permission.READ_CALL_LOG", "android.permission.READ_EXTERNAL_STORAGE"],
        "optional_permissions": ["android.permission.CAMERA"],
        "required_apis": ["CONTACT_HARVEST"],
        "package_patterns": ["loan", "credit", "finance", "money"],
        "risk_score_base": 72,
        "severity": "HIGH",
    },

    "FakeUPIApp": {
        "description": "Counterfeit UPI payment application for banking credential phishing",
        "malware_type": "Fake UPI App",
        "required_permissions": ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.INTERNET"],
        "optional_permissions": ["android.permission.READ_CONTACTS"],
        "required_apis": ["SMS_READ", "WEBVIEW"],
        "package_patterns": ["upi", "payment", "bhim", "gpay", "phonepe", "paytm"],
        "risk_score_base": 75,
        "severity": "HIGH",
    },

    "Dropper": {
        "description": "Dropper/loader that downloads and installs additional malicious payloads",
        "malware_type": "Dropper",
        "required_permissions": ["android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.INTERNET"],
        "optional_permissions": [],
        "required_apis": ["DYNAMIC_CODE_LOAD", "HTTP_CLIENT"],
        "package_patterns": [],
        "risk_score_base": 88,
        "severity": "CRITICAL",
    },
}


def match_malware_family(permissions: list, apis: list, package_name: str = "") -> dict:
    """
    Score each malware family against the given evidence.
    Returns the best matching family, or None if no strong match.
    """
    if not permissions:
        permissions = []
    if not apis:
        apis = []

    pkg = (package_name or "").lower()
    best_match = None
    best_score = 0.0

    for family_name, sig in MALWARE_FAMILIES.items():
        score = 0.0
        reasons = []

        # Required permissions
        req_perms_matched = [p for p in sig["required_permissions"] if p in permissions]
        if len(sig["required_permissions"]) > 0:
            perm_ratio = len(req_perms_matched) / len(sig["required_permissions"])
            score += perm_ratio * 50
            if req_perms_matched:
                reasons.append(f"Matched required permissions: {', '.join(req_perms_matched)}")

        # Optional permissions
        opt_matched = [p for p in sig.get("optional_permissions", []) if p in permissions]
        score += len(opt_matched) * 5
        if opt_matched:
            reasons.append(f"Matched optional permissions: {', '.join(opt_matched)}")

        # Required APIs
        req_apis_matched = [a for a in sig["required_apis"] if a in apis]
        if len(sig["required_apis"]) > 0:
            api_ratio = len(req_apis_matched) / len(sig["required_apis"])
            score += api_ratio * 35
            if req_apis_matched:
                reasons.append(f"Matched API patterns: {', '.join(req_apis_matched)}")

        # Package name patterns
        for pattern in sig.get("package_patterns", []):
            if pattern in pkg:
                score += 15
                reasons.append(f"Package name matches pattern: '{pattern}'")
                break

        if score > best_score and score >= 40:  # Min 40% match threshold
            best_score = score
            best_match = {
                "family": family_name,
                "malware_type": sig["malware_type"],
                "confidence": min(round(score), 100),
                "reasons": reasons,
                "risk_score_base": sig["risk_score_base"],
                "severity": sig["severity"],
            }

    return best_match


def get_permission_risk(permission: str) -> dict:
    """Get risk classification for a single permission."""
    return DANGEROUS_PERMISSIONS.get(permission, {"risk": "LOW", "category": "other", "label": permission.split(".")[-1]})
