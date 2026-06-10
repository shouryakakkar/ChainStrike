"""
Parser module: extracts structured findings from Nmap, Gobuster, and Nikto output.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ─── Data model ──────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """A single security finding."""
    title: str
    description: str
    source: str                         # "nmap" | "gobuster" | "nikto"
    severity: str = "Info"              # Critical / High / Medium / Low / Info
    owasp: str = "N/A"
    mitre_ttp: str = "N/A"
    mitre_ttp_name: str = "N/A"
    cve: str = ""
    reproduction: str = ""
    remediation: str = ""
    raw: str = ""
    extra: dict = field(default_factory=dict)


# ─── Nmap parser ─────────────────────────────────────────────────────────────

# Services that are almost always interesting from a security perspective
_SENSITIVE_SERVICES = {
    "ftp":       ("High",   "Unencrypted FTP service exposed"),
    "telnet":    ("High",   "Unencrypted Telnet service exposed"),
    "smtp":      ("Medium", "SMTP service exposed"),
    "pop3":      ("Medium", "POP3 service exposed"),
    "imap":      ("Medium", "IMAP service exposed"),
    "mysql":     ("High",   "MySQL database port exposed"),
    "mssql":     ("High",   "MSSQL database port exposed"),
    "mongodb":   ("High",   "MongoDB port exposed (often unauthenticated)"),
    "redis":     ("High",   "Redis port exposed (often unauthenticated)"),
    "postgresql":("High",   "PostgreSQL database port exposed"),
    "vnc":       ("High",   "VNC remote desktop exposed"),
    "rdp":       ("Medium", "RDP remote desktop exposed"),
    "smb":       ("Medium", "SMB file-sharing port exposed"),
    "netbios":   ("Medium", "NetBIOS service exposed"),
    "snmp":      ("Medium", "SNMP service exposed"),
    "rpcbind":   ("Medium", "RPCBind service exposed"),
    "ssh":       ("Info",   "SSH service detected"),
    "http":      ("Info",   "HTTP web service detected"),
    "https":     ("Info",   "HTTPS web service detected"),
    "http-proxy":("Medium", "HTTP proxy service detected"),
}

PORT_LINE_RE = re.compile(
    r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)?$", re.MULTILINE
)


def parse_nmap(output: str) -> list[Finding]:
    """Parse Nmap output and return a list of Finding objects."""
    findings: list[Finding] = []
    if not output:
        return findings

    for match in PORT_LINE_RE.finditer(output):
        port, service_raw, version = match.group(1), match.group(2).lower(), match.group(3).strip()
        service_key = service_raw.replace("ssl/", "").split("-")[0]

        sev, desc = _SENSITIVE_SERVICES.get(service_key, ("Info", f"Open port detected: {service_raw}"))

        finding = Finding(
            title=f"Open Port {port}/tcp – {service_raw.upper()}",
            description=f"{desc}. Version: {version}" if version else desc,
            source="nmap",
            severity=sev,
            owasp="A05:2021 – Security Misconfiguration",
            mitre_ttp="T1046",
            mitre_ttp_name="Network Service Discovery",
            reproduction=f"nmap -sV -p {port} <target>",
            remediation=(
                "Close the port if not required. Apply firewall rules to restrict "
                "access. Ensure services are patched and running with least privilege."
            ),
            raw=match.group(0),
            extra={"port": port, "service": service_raw, "version": version},
        )

        # Upgrade severity for certain dangerous well-known versions
        if "vsftpd 2.3.4" in version:
            finding.severity = "Critical"
            finding.cve = "CVE-2011-2523"
            finding.description += " ⚠ vsftpd 2.3.4 contains a backdoor (CVE-2011-2523)."
            finding.mitre_ttp = "T1190"
            finding.mitre_ttp_name = "Exploit Public-Facing Application"
            finding.owasp = "A06:2021 – Vulnerable and Outdated Components"

        findings.append(finding)

    logger.info("Nmap: extracted %d port findings.", len(findings))
    return findings


# ─── Gobuster parser ──────────────────────────────────────────────────────────

# Paths that indicate a particularly sensitive exposure
_SENSITIVE_PATHS = {
    r"\.git":       ("High",     "A09:2021 – Security Logging and Monitoring Failures",
                     "Source code repository (.git) is publicly accessible. Attackers can "
                     "clone the entire codebase and extract credentials / logic."),
    r"\.env":       ("Critical", "A02:2021 – Cryptographic Failures",
                     "Environment file (.env) is publicly accessible. May expose DB passwords, "
                     "API keys, and other secrets."),
    r"backup":      ("High",     "A05:2021 – Security Misconfiguration",
                     "Backup directory/file is accessible. Could contain sensitive data or full "
                     "application archives."),
    r"phpmyadmin":  ("High",     "A05:2021 – Security Misconfiguration",
                     "phpMyAdmin is publicly accessible. Could allow direct database access."),
    r"admin":       ("Medium",   "A01:2021 – Broken Access Control",
                     "Admin panel is reachable without authentication check."),
    r"wp-admin":    ("Medium",   "A01:2021 – Broken Access Control",
                     "WordPress admin panel detected."),
    r"config":      ("High",     "A05:2021 – Security Misconfiguration",
                     "Configuration directory/file is accessible."),
    r"upload":      ("Medium",   "A04:2021 – Insecure Design",
                     "Upload directory is accessible. Attackers may read or enumerate uploaded files."),
    r"api":         ("Info",     "A01:2021 – Broken Access Control",
                     "API endpoint discovered. Verify authentication requirements."),
}

GOBUSTER_LINE_RE = re.compile(
    r"^(/\S+)\s+\(Status:\s*(\d+)\)",
    re.MULTILINE,
)


def parse_gobuster(output: str) -> list[Finding]:
    """Parse Gobuster output and return a list of Finding objects."""
    findings: list[Finding] = []
    if not output:
        return findings

    for match in GOBUSTER_LINE_RE.finditer(output):
        path, status = match.group(1), match.group(2)
        status_int = int(status)

        # Skip redirects or forbidden unless they are sensitive
        if status_int in (301, 302, 403):
            interesting = any(re.search(pat, path, re.IGNORECASE) for pat in _SENSITIVE_PATHS)
            if not interesting and status_int in (301, 302):
                continue

        sev, owasp, desc = "Info", "A05:2021 – Security Misconfiguration", f"Directory/file discovered: {path}"
        for pat, (s, o, d) in _SENSITIVE_PATHS.items():
            if re.search(pat, path, re.IGNORECASE):
                sev, owasp, desc = s, o, d
                break

        finding = Finding(
            title=f"Exposed Path: {path}",
            description=f"{desc} (HTTP {status})",
            source="gobuster",
            severity=sev,
            owasp=owasp,
            mitre_ttp="T1083",
            mitre_ttp_name="File and Directory Discovery",
            reproduction=f"curl -v http://<target>{path}",
            remediation=(
                "Remove or restrict access to this resource. Apply authentication and "
                "authorisation controls. Review web-server configuration."
            ),
            raw=match.group(0),
            extra={"path": path, "status": status},
        )
        findings.append(finding)

    logger.info("Gobuster: extracted %d path findings.", len(findings))
    return findings


# ─── Nikto parser ─────────────────────────────────────────────────────────────

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
OSVDB_RE = re.compile(r"OSVDB-\d+")

# Keyword → (severity, owasp, mitre_ttp, mitre_ttp_name)
_NIKTO_RULES: list[tuple[str, str, str, str, str]] = [
    # keyword,              severity,   owasp,                              ttp,     ttp_name
    ("path traversal",      "Critical", "A01:2021 – Broken Access Control", "T1190", "Exploit Public-Facing Application"),
    ("remote code",         "Critical", "A03:2021 – Injection",             "T1190", "Exploit Public-Facing Application"),
    ("rce",                 "Critical", "A03:2021 – Injection",             "T1190", "Exploit Public-Facing Application"),
    ("sql injection",       "Critical", "A03:2021 – Injection",             "T1190", "Exploit Public-Facing Application"),
    ("xss",                 "High",     "A03:2021 – Injection",             "T1059", "Command and Scripting Interpreter"),
    ("cross-site",          "High",     "A03:2021 – Injection",             "T1059", "Command and Scripting Interpreter"),
    ("clickjacking",        "Medium",   "A05:2021 – Security Misconfiguration", "T1185", "Browser Session Hijacking"),
    ("x-frame-options",     "Medium",   "A05:2021 – Security Misconfiguration", "T1185", "Browser Session Hijacking"),
    ("x-xss-protection",    "Medium",   "A05:2021 – Security Misconfiguration", "T1059", "Command and Scripting Interpreter"),
    ("x-content-type",      "Low",      "A05:2021 – Security Misconfiguration", "T1190", "Exploit Public-Facing Application"),
    ("httponly",            "Medium",   "A07:2021 – Identification and Authentication Failures", "T1539", "Steal Web Session Cookie"),
    ("cookie",              "Medium",   "A07:2021 – Identification and Authentication Failures", "T1539", "Steal Web Session Cookie"),
    ("phpmyadmin",          "High",     "A05:2021 – Security Misconfiguration", "T1190", "Exploit Public-Facing Application"),
    ("outdated",            "Medium",   "A06:2021 – Vulnerable and Outdated Components", "T1190", "Exploit Public-Facing Application"),
    ("default file",        "Low",      "A05:2021 – Security Misconfiguration", "T1083", "File and Directory Discovery"),
    (".git",                "High",     "A09:2021 – Security Logging and Monitoring Failures", "T1083", "File and Directory Discovery"),
    ("trace",               "Medium",   "A05:2021 – Security Misconfiguration", "T1557", "Adversary-in-the-Middle"),
    ("delete",              "Medium",   "A05:2021 – Security Misconfiguration", "T1190", "Exploit Public-Facing Application"),
    ("upload",              "Medium",   "A04:2021 – Insecure Design",       "T1105", "Ingress Tool Transfer"),
    ("etag",                "Low",      "A05:2021 – Security Misconfiguration", "T1592", "Gather Victim Host Information"),
    ("inode",               "Low",      "A05:2021 – Security Misconfiguration", "T1592", "Gather Victim Host Information"),
    ("server",              "Info",     "A05:2021 – Security Misconfiguration", "T1592", "Gather Victim Host Information"),
]

NIKTO_FINDING_RE = re.compile(r"^\+\s+(.+)$", re.MULTILINE)


def _classify_nikto_line(line: str) -> tuple[str, str, str, str]:
    """Return (severity, owasp, mitre_ttp, mitre_ttp_name) for a Nikto line."""
    lower = line.lower()
    for keyword, sev, owasp, ttp, ttp_name in _NIKTO_RULES:
        if keyword in lower:
            return sev, owasp, ttp, ttp_name
    return "Info", "A05:2021 – Security Misconfiguration", "T1592", "Gather Victim Host Information"


def parse_nikto(output: str) -> list[Finding]:
    """Parse Nikto output and return a list of Finding objects."""
    findings: list[Finding] = []
    if not output:
        return findings

    for match in NIKTO_FINDING_RE.finditer(output):
        line = match.group(1).strip()
        # Skip header / summary lines
        if any(skip in line for skip in ["Target IP", "Target Host", "Target Port",
                                          "Start Time", "End Time", "requests:",
                                          "host(s) tested", "Nikto v"]):
            continue
        if not line:
            continue

        cves = CVE_RE.findall(line)
        osvdbs = OSVDB_RE.findall(line)

        sev, owasp, ttp, ttp_name = _classify_nikto_line(line)

        # CVE findings always at least High
        if cves and sev == "Info":
            sev = "High"

        # Build a short title from the first ~80 chars
        title_raw = re.sub(r"(CVE-\S+|OSVDB-\d+):\s*", "", line).strip()
        title = (title_raw[:80] + "…") if len(title_raw) > 80 else title_raw

        finding = Finding(
            title=title,
            description=line,
            source="nikto",
            severity=sev,
            owasp=owasp,
            mitre_ttp=ttp,
            mitre_ttp_name=ttp_name,
            cve=", ".join(cves),
            reproduction=f"nikto -h <target>  # then inspect: {line[:60]}",
            remediation=_remediation_for(line),
            raw=line,
            extra={"osvdb": osvdbs},
        )
        findings.append(finding)

    logger.info("Nikto: extracted %d findings.", len(findings))
    return findings


def _remediation_for(line: str) -> str:
    """Return a generic remediation hint based on the Nikto finding line."""
    lower = line.lower()
    if "x-frame-options" in lower or "clickjacking" in lower:
        return "Add the 'X-Frame-Options: DENY' or 'SAMEORIGIN' response header."
    if "x-xss-protection" in lower:
        return "Add the 'X-XSS-Protection: 1; mode=block' response header."
    if "x-content-type" in lower:
        return "Add the 'X-Content-Type-Options: nosniff' response header."
    if "httponly" in lower or "cookie" in lower:
        return "Set the HttpOnly and Secure flags on all session cookies."
    if "trace" in lower:
        return "Disable the HTTP TRACE method in the web server configuration."
    if "outdated" in lower or "old" in lower:
        return "Update the web server / framework to the latest stable version."
    if "path traversal" in lower or "traversal" in lower:
        return "Apply the latest security patches. Restrict directory access in web server config."
    if "rce" in lower or "remote code" in lower:
        return "Apply vendor patches immediately. Consider WAF and egress filtering."
    if ".git" in lower:
        return "Move the .git directory outside the web root or deny access via server config."
    if "phpmyadmin" in lower:
        return "Restrict phpMyAdmin to trusted IPs only. Use strong credentials."
    if "upload" in lower:
        return "Restrict file uploads by type. Store uploads outside the web root."
    if "etag" in lower or "inode" in lower:
        return "Configure the web server to not include inode information in ETags."
    return "Review the finding and apply the relevant CIS/vendor hardening guidance."
