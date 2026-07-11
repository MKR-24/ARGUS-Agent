"""
Local MITRE ATT&CK technique mapper.
Maps vulnerability characteristics to ATT&CK techniques without external API calls.
Covers the most common techniques seen in CVE-based alerts.
"""

# Technique definitions: id, name, tactic, url
TECHNIQUE_DB = {
    "T1190": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190",
    },
    "T1659": {
        "technique_id": "T1659",
        "technique_name": "Content Injection",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1659",
    },
    "T1059": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059",
    },
    "T1059.001": {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/001",
    },
    "T1059.004": {
        "technique_id": "T1059.004",
        "technique_name": "Unix Shell",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/004",
    },
    "T1059.006": {
        "technique_id": "T1059.006",
        "technique_name": "Python",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/006",
    },
    "T1059.007": {
        "technique_id": "T1059.007",
        "technique_name": "JavaScript",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/007",
    },
    "T1203": {
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1203",
    },
    "T1505": {
        "technique_id": "T1505",
        "technique_name": "Server Software Component",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1505",
    },
    "T1068": {
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1068",
    },
    "T1548": {
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1548",
    },
    "T1548.001": {
        "technique_id": "T1548.001",
        "technique_name": "Setuid and Setgid",
        "tactic": "Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1548/001",
    },
    "T1548.002": {
        "technique_id": "T1548.002",
        "technique_name": "Bypass User Account Control",
        "tactic": "Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1548/002",
    },
    "T1212": {
        "technique_id": "T1212",
        "technique_name": "Exploitation for Credential Access",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1212",
    },
    "T1210": {
        "technique_id": "T1210",
        "technique_name": "Exploitation of Remote Services",
        "tactic": "Lateral Movement",
        "url": "https://attack.mitre.org/techniques/T1210",
    },
    "T1071": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071",
    },
    "T1071.001": {
        "technique_id": "T1071.001",
        "technique_name": "Web Protocols",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/001",
    },
    "T1071.004": {
        "technique_id": "T1071.004",
        "technique_name": "DNS",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/004",
    },
    "T1485": {
        "technique_id": "T1485",
        "technique_name": "Data Destruction",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1485",
    },
    "T1486": {
        "technique_id": "T1486",
        "technique_name": "	Data Encrypted for Impact",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1486",
    },
}
# Mapping rules: CVE keywords/characteristics → technique IDs
MAPPING_RULES = [
    # Internet-reachable service → Initial Access
    {
        "condition": lambda findings: findings.get("graph_findings", {}).get(
            "reachable_from_internet"
        ),
        "techniques": ["T1190"],
    },
    # Content/parameter injection (XSS, SQLi, SSTI)
    {
        "condition": lambda findings: any(
            kw
            in (findings.get("cve_findings", {}).get("description", "") or "").lower()
            for kw in [
                "injection",
                "xss",
                "cross-site",
                "sql injection",
                "ssti",
                "template injection",
            ]
        ),
        "techniques": ["T1659"],
    },
    # Generic RCE → Execution
    {
        "condition": lambda findings: any(
            kw
            in (findings.get("cve_findings", {}).get("description", "") or "").lower()
            for kw in [
                "remote code execution",
                "rce",
                "arbitrary code",
                "code execution",
            ]
        ),
        "techniques": ["T1059", "T1203"],
    },
    # Language-specific execution based on service language
    {
        "condition": lambda findings: (
            findings.get("graph_findings", {}).get("service_info", {}).get("language")
            == "python"
            and "remote code execution"
            in (findings.get("cve_findings", {}).get("description", "") or "").lower()
        ),
        "techniques": ["T1059.006"],
    },
    {
        "condition": lambda findings: (
            findings.get("graph_findings", {}).get("service_info", {}).get("language")
            == "node"
            and "remote code execution"
            in (findings.get("cve_findings", {}).get("description", "") or "").lower()
        ),
        "techniques": ["T1059.007"],
    },
    {
        "condition": lambda findings: (
            findings.get("graph_findings", {}).get("service_info", {}).get("language")
            == "java"
            and "remote code execution"
            in (findings.get("cve_findings", {}).get("description", "") or "").lower()
        ),
        "techniques": [
            "T1059.001",
            "T1059.004",
        ],  # PowerShell or Unix shell spawned by Java RCE
    },
    # Webshell / server component persistence
    {
        "condition": lambda findings: any(
            kw
            in (findings.get("cve_findings", {}).get("description", "") or "").lower()
            for kw in ["webshell", "web shell", "file upload", "arbitrary file"]
        ),
        "techniques": ["T1505"],
    },
    # Privilege escalation
    {
        "condition": lambda findings: any(
            kw
            in (findings.get("cve_findings", {}).get("description", "") or "").lower()
            for kw in ["privilege escalation", "root", "elevated", "administrator"]
        ),
        "techniques": ["T1068"],
    },
    # Linux-specific privesc
    {
        "condition": lambda findings: any(
            kw
            in (findings.get("cve_findings", {}).get("description", "") or "").lower()
            for kw in ["setuid", "setgid", "suid", "sgid", "sudo"]
        ),
        "techniques": ["T1548", "T1548.001"],
    },
    # Windows UAC bypass
    {
        "condition": lambda findings: any(
            kw
            in (findings.get("cve_findings", {}).get("description", "") or "").lower()
            for kw in ["uac", "user account control", "windows", "bypass"]
        ),
        "techniques": ["T1548.002"],
    },
    # Credential theft
    {
        "condition": lambda findings: any(
            kw
            in (findings.get("cve_findings", {}).get("description", "") or "").lower()
            for kw in [
                "credential",
                "password",
                "authentication bypass",
                "auth bypass",
                "token",
            ]
        ),
        "techniques": ["T1212"],
    },
    # Lateral movement via multi-hop attack path
    {
        "condition": lambda findings: (
            (findings.get("graph_findings", {}).get("hop_count") or 0) > 1
        ),
        "techniques": ["T1210"],
    },
    # Log4Shell / JNDI specific → C2 via DNS/HTTP callbacks
    {
        "condition": lambda findings: any(
            kw
            in (findings.get("cve_findings", {}).get("description", "") or "").lower()
            for kw in ["jndi", "ldap", "log4j", "log4shell"]
        ),
        "techniques": ["T1190", "T1059", "T1071", "T1071.004"],
    },
    # HTTP-based C2 (generic web exploit with outbound connection)
    {
        "condition": lambda findings: (
            findings.get("graph_findings", {}).get("reachable_from_internet")
            and any(
                kw
                in (
                    findings.get("cve_findings", {}).get("description", "") or ""
                ).lower()
                for kw in ["remote code execution", "rce", "deserialization"]
            )
        ),
        "techniques": ["T1071", "T1071.001"],
    },
    # Data destruction / ransomware
    {
        "condition": lambda findings: any(
            kw
            in (findings.get("cve_findings", {}).get("description", "") or "").lower()
            for kw in ["destroy", "wipe", "ransomware", "encrypt", "deletion"]
        ),
        "techniques": ["T1485", "T1486"],
    },
]


def map_to_mitre(findings: dict) -> list[dict]:
    """
    Map investigation findings to MITRE ATT&CK techniques.
    Returns a deduplicated list of technique dicts.
    """
    matched_ids: set[str] = set()
    for rule in MAPPING_RULES:
        try:
            if rule["condition"](findings):
                matched_ids.update(rule["techniques"])
        except Exception:
            continue  # rule evaluation failure is non-fatal

    return [TECHNIQUE_DB[tid] for tid in sorted(matched_ids) if tid in TECHNIQUE_DB]
