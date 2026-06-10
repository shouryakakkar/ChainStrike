#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pure-Python web vulnerability scanner — zero external dependencies.

Used as a fallback when Nikto / Perl is not available.
Output is formatted to closely mimic Nikto's text output so that the
existing parse_nikto() parser can consume it without any changes.
"""

import http.client
import json
import socket
import ssl
import sys
import urllib.parse
from datetime import datetime
from typing import NamedTuple


# ─── Helpers ──────────────────────────────────────────────────────────────────

class PortResult(NamedTuple):
    host: str
    port: int
    scheme: str          # "http" or "https"
    server: str
    headers: dict        # lowercase key → value
    status: int


_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode    = ssl.CERT_NONE

_WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 7070, 2869]


def _get(host: str, port: int, path: str, scheme: str,
         method: str = "GET", timeout: int = 8) -> tuple[int, dict, str]:
    """
    Make a single HTTP/HTTPS request.
    Returns (status_code, headers_dict, body_snippet).
    """
    try:
        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=timeout,
                                               context=_SSL_CTX)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        conn.request(method, path,
                     headers={"Host": host,
                               "User-Agent": "ChainStrike-Scanner/1.0",
                               "Connection": "close"})
        resp = conn.getresponse()
        raw_headers = {k.lower(): v for k, v in resp.getheaders()}
        body = resp.read(512).decode("utf-8", errors="replace")
        conn.close()
        return resp.status, raw_headers, body
    except Exception:
        return 0, {}, ""


def _probe_ports(host: str) -> list[PortResult]:
    """Discover which web ports are open and collect their base headers."""
    results = []
    for port in _WEB_PORTS:
        for scheme in ("https", "http"):
            if scheme == "http" and port in (443, 8443):
                continue
            if scheme == "https" and port in (80, 8080, 8000, 8888, 3000, 5000, 7070, 2869):
                continue
            code, hdrs, _ = _get(host, port, "/", scheme, timeout=5)
            if code:
                results.append(PortResult(
                    host=host,
                    port=port,
                    scheme=scheme,
                    server=hdrs.get("server", ""),
                    headers=hdrs,
                    status=code,
                ))
                break   # found a responding scheme, move to next port
    return results


# ─── Check functions — each returns list[str] of Nikto-style finding lines ───

def _check_headers(pr: PortResult) -> list[str]:
    findings = []
    h = pr.headers

    if "x-frame-options" not in h:
        findings.append(
            "The anti-clickjacking X-Frame-Options header is not present."
        )
    if "x-xss-protection" not in h:
        findings.append(
            "The X-XSS-Protection header is not defined. This header can hint "
            "to the user agent to protect against some forms of XSS"
        )
    if "x-content-type-options" not in h:
        findings.append(
            "The X-Content-Type-Options header is not set. This could allow "
            "the user agent to render the content of the site in a different "
            "fashion to the MIME type"
        )
    if "strict-transport-security" not in h and pr.scheme == "https":
        findings.append(
            "The site uses HTTPS but the Strict-Transport-Security (HSTS) "
            "header is not set."
        )
    if "content-security-policy" not in h:
        findings.append(
            "Content-Security-Policy (CSP) header is not set. This increases "
            "the risk of XSS and data injection attacks."
        )
    if "referrer-policy" not in h:
        findings.append(
            "Referrer-Policy header is not set. This may leak sensitive URL "
            "information to third parties."
        )

    # Server version disclosure
    srv = h.get("server", "")
    if srv:
        findings.append(f"Server: {srv}")
        # Flag common outdated servers
        if any(v in srv for v in ["Apache/2.4.49", "Apache/2.4.50",
                                    "Apache/2.2", "nginx/1.14", "nginx/1.16",
                                    "IIS/6.0", "IIS/7.0"]):
            findings.append(
                f"{srv} appears to be outdated. Update to a supported version."
            )

    # X-Powered-By disclosure
    pwby = h.get("x-powered-by", "")
    if pwby:
        findings.append(f"X-Powered-By: {pwby} header found")

    # Cookie flags (check via Set-Cookie)
    sc = h.get("set-cookie", "")
    if sc:
        if "httponly" not in sc.lower():
            findings.append(
                "Cookie created without the httponly flag"
            )
        if "secure" not in sc.lower() and pr.scheme == "https":
            findings.append(
                "Cookie created without the Secure flag on an HTTPS site"
            )
        if "samesite" not in sc.lower():
            findings.append(
                "Cookie missing the SameSite attribute. Vulnerable to CSRF."
            )

    return findings


def _check_http_methods(pr: PortResult) -> list[str]:
    findings = []
    code, hdrs, _ = _get(pr.host, pr.port, "/", pr.scheme, method="OPTIONS")
    allow = hdrs.get("allow", hdrs.get("public", ""))
    if allow:
        findings.append(f"Allowed HTTP Methods: {allow}")
        if "TRACE" in allow.upper():
            findings.append(
                "TRACE HTTP method is active, suggesting the host is "
                "vulnerable to XST"
            )
        if "DELETE" in allow.upper():
            findings.append(
                "DELETE HTTP method is enabled. This may allow file deletion."
            )
        if "PUT" in allow.upper():
            findings.append(
                "PUT HTTP method is enabled. This may allow file upload."
            )
    return findings


# Paths to probe — (path, nikto-style message)
_SENSITIVE_PATHS: list[tuple[str, str]] = [
    ("/.git/HEAD",           "OSVDB-3093: /.git/: .git directory found."),
    ("/.git/config",         "OSVDB-3093: /.git/config: Git config file found."),
    ("/.env",                "OSVDB-3268: /.env: Environment file found. May expose credentials."),
    ("/.env.local",          "OSVDB-3268: /.env.local: Local environment file found."),
    ("/.htaccess",           "OSVDB-3092: /.htaccess: Apache .htaccess file found."),
    ("/.htpasswd",           "OSVDB-3093: /.htpasswd: Contains encrypted passwords."),
    ("/backup/",             "OSVDB-3092: /backup/: This might be interesting..."),
    ("/backup.zip",          "OSVDB-3092: /backup.zip: Backup archive accessible."),
    ("/config/",             "OSVDB-3268: /config/: Directory indexing found."),
    ("/phpmyadmin/",         "/phpmyadmin/: phpMyAdmin directory found"),
    ("/phpMyAdmin/",         "/phpMyAdmin/: phpMyAdmin directory found"),
    ("/admin/",              "/admin/: Admin panel accessible."),
    ("/wp-admin/",           "/wp-admin/: WordPress admin panel found."),
    ("/wp-login.php",        "/wp-login.php: WordPress login found."),
    ("/xmlrpc.php",          "/xmlrpc.php: WordPress XML-RPC interface found."),
    ("/server-status",       "/server-status: Apache server status page found."),
    ("/server-info",         "/server-info: Apache server info page found."),
    ("/upload/",             "/upload/: Upload directory found - files may be uploaded here."),
    ("/uploads/",            "/uploads/: Uploads directory found."),
    ("/robots.txt",          "Server leaks information via robots.txt"),
    ("/crossdomain.xml",     "/crossdomain.xml: Adobe cross-domain policy found."),
    ("/elmah.axd",           "/elmah.axd: ELMAH error log accessible (ASP.NET)."),
    ("/trace.axd",           "/trace.axd: ASP.NET trace viewer accessible."),
    ("/web.config",          "/web.config: IIS configuration file accessible."),
    ("/WEB-INF/web.xml",     "/WEB-INF/web.xml: Java web application descriptor accessible."),
    ("/actuator",            "/actuator: Spring Boot Actuator endpoints exposed."),
    ("/actuator/env",        "/actuator/env: Spring Boot environment variables exposed."),
    ("/actuator/health",     "/actuator/health: Spring Boot health endpoint exposed."),
    ("/.DS_Store",           "/.DS_Store: macOS directory metadata file exposed."),
    ("/composer.json",       "/composer.json: PHP composer config exposed."),
    ("/package.json",        "/package.json: Node.js package manifest exposed."),
    ("/Gemfile",             "/Gemfile: Ruby Gemfile exposed."),
    ("/requirements.txt",    "/requirements.txt: Python requirements file exposed."),
    ("/phpinfo.php",         "/phpinfo.php: phpinfo() output page found."),
    ("/info.php",            "/info.php: phpinfo() output page found."),
    ("/test.php",            "/test.php: Test PHP file found."),
]

_INTERESTING_STATUS = {200, 204, 301, 302, 307, 401, 403}


def _check_paths(pr: PortResult) -> list[str]:
    findings = []
    for path, msg in _SENSITIVE_PATHS:
        code, hdrs, body = _get(pr.host, pr.port, path, pr.scheme, timeout=6)
        if code in _INTERESTING_STATUS:
            findings.append(f"{msg} (HTTP {code})")
    return findings


def _check_ssl(pr: PortResult) -> list[str]:
    if pr.scheme != "https":
        return []
    findings = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((pr.host, pr.port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=pr.host) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
                if proto in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                    findings.append(
                        f"Outdated TLS protocol in use: {proto}. "
                        "Upgrade to TLS 1.2 or 1.3."
                    )
    except Exception:
        pass
    return findings


# ─── Main entry point ─────────────────────────────────────────────────────────

def run_python_web_scan(target: str) -> str:
    """
    Run the pure-Python web scanner against *target* and return output
    formatted to mimic Nikto's text format (so parse_nikto() works unchanged).
    """
    host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    header = (
        f"- ChainStrike Python Web Scanner (Nikto-compatible output)\n"
        f"---------------------------------------------------------------------------\n"
    )

    ports = _probe_ports(host)
    if not ports:
        return (
            header
            + f"+ Target: {host}\n"
            + "+ No open web ports found on common ports.\n"
            + f"---------------------------------------------------------------------------\n"
            + f"+ 1 host(s) tested\n"
        )

    output_parts = [header]

    for pr in ports:
        output_parts.append(
            f"+ Target IP:          {host}\n"
            f"+ Target Hostname:    {host}\n"
            f"+ Target Port:        {pr.port}\n"
            f"+ Start Time:         {start}\n"
            f"---------------------------------------------------------------------------\n"
        )

        all_findings: list[str] = []
        all_findings += _check_headers(pr)
        all_findings += _check_http_methods(pr)
        all_findings += _check_paths(pr)
        all_findings += _check_ssl(pr)

        for f in all_findings:
            output_parts.append(f"+ {f}\n")

        end = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        output_parts.append(
            f"+ End Time:           {end}\n"
            f"---------------------------------------------------------------------------\n"
        )

    output_parts.append(f"+ {len(ports)} port(s) tested\n")
    return "".join(output_parts)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    print(run_python_web_scan(target))
