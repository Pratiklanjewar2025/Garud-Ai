"""
MITRE ATT&CK Mobile — Android Malware Technique Knowledge Base
Source: MITRE ATT&CK for Mobile (https://attack.mitre.org/matrices/mobile/)
"""

# Complete lookup: Technique ID → details
MITRE_MOBILE_TECHNIQUES = {

    # ── Credential Access ──────────────────────────────────────────────────
    "T1412": {
        "id": "T1412",
        "name": "Capture SMS Messages",
        "tactic": "Collection",
        "description": "Adversaries may capture SMS messages to obtain authentication codes, OTPs, or other sensitive information transmitted via SMS.",
        "permission_indicators": ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS"],
        "api_indicators": ["SmsManager", "SmsMessage", "BroadcastReceiver"],
        "severity": "CRITICAL",
    },
    "T1417": {
        "id": "T1417",
        "name": "Input Capture",
        "tactic": "Collection",
        "description": "Adversaries may use methods of capturing user input to obtain credentials or collect information. This includes keylogging and overlay attacks.",
        "permission_indicators": ["android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SYSTEM_ALERT_WINDOW"],
        "api_indicators": ["AccessibilityService", "WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY"],
        "severity": "CRITICAL",
    },
    "T1634": {
        "id": "T1634",
        "name": "Credentials from Password Store",
        "tactic": "Credential Access",
        "description": "Adversaries may acquire user credentials from Android KeyStore or account managers.",
        "permission_indicators": ["android.permission.USE_CREDENTIALS", "android.permission.GET_ACCOUNTS"],
        "api_indicators": ["AccountManager", "KeyStore"],
        "severity": "HIGH",
    },

    # ── Collection ─────────────────────────────────────────────────────────
    "T1533": {
        "id": "T1533",
        "name": "Data from Local System",
        "tactic": "Collection",
        "description": "Adversaries may search for files and information in the device file system that contain sensitive user data.",
        "permission_indicators": ["android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE"],
        "api_indicators": ["File", "FileInputStream", "ContentResolver"],
        "severity": "HIGH",
    },
    "T1414": {
        "id": "T1414",
        "name": "Capture Clipboard Data",
        "tactic": "Collection",
        "description": "Adversaries may abuse clipboard functionality to collect sensitive copied content including passwords and OTPs.",
        "permission_indicators": [],
        "api_indicators": ["ClipboardManager", "ClipData"],
        "severity": "MEDIUM",
    },
    "T1429": {
        "id": "T1429",
        "name": "Capture Audio",
        "tactic": "Collection",
        "description": "An adversary may capture audio, including phone calls, using the device microphone.",
        "permission_indicators": ["android.permission.RECORD_AUDIO", "android.permission.CAPTURE_AUDIO_OUTPUT"],
        "api_indicators": ["MediaRecorder", "AudioRecord"],
        "severity": "HIGH",
    },
    "T1512": {
        "id": "T1512",
        "name": "Video Capture",
        "tactic": "Collection",
        "description": "An adversary may capture video, including the device camera or screen.",
        "permission_indicators": ["android.permission.CAMERA"],
        "api_indicators": ["Camera", "Camera2", "MediaProjection"],
        "severity": "HIGH",
    },
    "T1636": {
        "id": "T1636",
        "name": "Protected User Data: Contact List",
        "tactic": "Collection",
        "description": "Adversaries may access contact list data to collect victim personal details and enable social engineering.",
        "permission_indicators": ["android.permission.READ_CONTACTS"],
        "api_indicators": ["ContactsContract", "ContentResolver"],
        "severity": "MEDIUM",
    },
    "T1432": {
        "id": "T1432",
        "name": "Access Contact List",
        "tactic": "Collection",
        "description": "An adversary may utilize standard Android APIs to gather contact list data from a device.",
        "permission_indicators": ["android.permission.READ_CONTACTS"],
        "api_indicators": ["ContactsContract"],
        "severity": "MEDIUM",
    },
    "T1433": {
        "id": "T1433",
        "name": "Access Call Log",
        "tactic": "Collection",
        "description": "An adversary may utilize standard Android APIs to gather call log data from a device.",
        "permission_indicators": ["android.permission.READ_CALL_LOG"],
        "api_indicators": ["CallLog"],
        "severity": "MEDIUM",
    },

    # ── Command and Control ────────────────────────────────────────────────
    "T1437": {
        "id": "T1437",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols to blend with existing traffic.",
        "permission_indicators": ["android.permission.INTERNET"],
        "api_indicators": ["HttpURLConnection", "OkHttp", "Retrofit", "WebSocket"],
        "severity": "MEDIUM",
    },
    "T1521": {
        "id": "T1521",
        "name": "Encrypted Channel",
        "tactic": "Command and Control",
        "description": "Adversaries may employ a known cryptographic algorithm to conceal command and control traffic.",
        "permission_indicators": ["android.permission.INTERNET"],
        "api_indicators": ["SSLSocket", "TrustManager", "javax.crypto"],
        "severity": "MEDIUM",
    },
    "T1644": {
        "id": "T1644",
        "name": "Out of Band C2 Channel",
        "tactic": "Command and Control",
        "description": "Adversaries may use SMS, phone calls, or other out-of-band methods for C2.",
        "permission_indicators": ["android.permission.SEND_SMS", "android.permission.RECEIVE_SMS"],
        "api_indicators": ["SmsManager.sendTextMessage"],
        "severity": "HIGH",
    },

    # ── Exfiltration ───────────────────────────────────────────────────────
    "T1646": {
        "id": "T1646",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over an existing C2 channel.",
        "permission_indicators": ["android.permission.INTERNET"],
        "api_indicators": ["HttpURLConnection", "URL.openConnection"],
        "severity": "HIGH",
    },
    "T1639": {
        "id": "T1639",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over a different protocol than that used for C2.",
        "permission_indicators": ["android.permission.SEND_SMS", "android.permission.INTERNET"],
        "api_indicators": ["SmsManager.sendTextMessage", "FTP", "SMTP"],
        "severity": "HIGH",
    },

    # ── Defense Evasion ────────────────────────────────────────────────────
    "T1406": {
        "id": "T1406",
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze.",
        "permission_indicators": [],
        "api_indicators": ["ClassLoader", "DexClassLoader", "InMemoryDexClassLoader"],
        "severity": "HIGH",
    },
    "T1629": {
        "id": "T1629",
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "description": "Adversaries may maliciously modify components of a victim's environment to hinder defenses.",
        "permission_indicators": ["android.permission.BIND_DEVICE_ADMIN"],
        "api_indicators": ["DevicePolicyManager"],
        "severity": "CRITICAL",
    },

    # ── Persistence ────────────────────────────────────────────────────────
    "T1398": {
        "id": "T1398",
        "name": "Boot or Logon Initialization Scripts",
        "tactic": "Persistence",
        "description": "Adversaries may use scripts that run on device boot/logon to maintain persistence.",
        "permission_indicators": ["android.permission.RECEIVE_BOOT_COMPLETED"],
        "api_indicators": ["BOOT_COMPLETED"],
        "severity": "HIGH",
    },
    "T1626": {
        "id": "T1626",
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may circumvent mechanisms designed to control privilege elevation to gain higher-level permissions.",
        "permission_indicators": ["android.permission.BIND_DEVICE_ADMIN"],
        "api_indicators": ["DevicePolicyManager.resetPassword", "Runtime.exec"],
        "severity": "CRITICAL",
    },

    # ── Discovery ──────────────────────────────────────────────────────────
    "T1418": {
        "id": "T1418",
        "name": "Software Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of applications installed on a device.",
        "permission_indicators": ["android.permission.QUERY_ALL_PACKAGES"],
        "api_indicators": ["PackageManager.getInstalledApplications"],
        "severity": "LOW",
    },
    "T1426": {
        "id": "T1426",
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get detailed information about the device OS and hardware.",
        "permission_indicators": [],
        "api_indicators": ["android.os.Build", "TelephonyManager.getDeviceId"],
        "severity": "LOW",
    },

    # ── Impact ─────────────────────────────────────────────────────────────
    "T1448": {
        "id": "T1448",
        "name": "Carrier Billing Fraud",
        "tactic": "Impact",
        "description": "Adversaries may trigger unauthorized SMS-based premium rate subscriptions.",
        "permission_indicators": ["android.permission.SEND_SMS", "android.permission.RECEIVE_SMS"],
        "api_indicators": ["SmsManager.sendTextMessage"],
        "severity": "HIGH",
    },
    "T1641": {
        "id": "T1641",
        "name": "Data Manipulation",
        "tactic": "Impact",
        "description": "Adversaries may insert, delete, or manipulate data in order to influence external outcomes.",
        "permission_indicators": ["android.permission.WRITE_EXTERNAL_STORAGE"],
        "api_indicators": ["ContentResolver.update", "FileOutputStream"],
        "severity": "MEDIUM",
    },
}


def get_technique(technique_id: str) -> dict:
    """Return technique details by ID, or None."""
    return MITRE_MOBILE_TECHNIQUES.get(technique_id)


def map_permissions_to_techniques(permissions: list) -> list:
    """Given a list of Android permissions, return matching MITRE techniques."""
    if not permissions:
        return []
    matched = []
    seen = set()
    for tech_id, tech in MITRE_MOBILE_TECHNIQUES.items():
        for indicator in tech.get("permission_indicators", []):
            if indicator in permissions and tech_id not in seen:
                matched.append({"technique": tech, "match_type": "permission", "matched": indicator})
                seen.add(tech_id)
                break
    return matched


def map_apis_to_techniques(api_calls: list) -> list:
    """Given a list of API class/method names, return matching MITRE techniques."""
    if not api_calls:
        return []
    api_str = " ".join(api_calls)
    matched = []
    seen = set()
    for tech_id, tech in MITRE_MOBILE_TECHNIQUES.items():
        for indicator in tech.get("api_indicators", []):
            if indicator.lower() in api_str.lower() and tech_id not in seen:
                matched.append({"technique": tech, "match_type": "api", "matched": indicator})
                seen.add(tech_id)
                break
    return matched
