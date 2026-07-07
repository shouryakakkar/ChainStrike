#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ChainStrike - Automated Recon & Vulnerability Assessment CLI
============================================================
Usage:
    python main.py --target 192.168.1.100
    python main.py --target example.com --output-dir ./reports
    python main.py --target 10.0.0.1 --wordlist C:\\wordlists\\common.txt
    python main.py --target demo --mock
"""

import argparse
import logging
import os
import platform
import sys
from datetime import datetime

# ── Windows: reconfigure stdout to UTF-8 so extended ASCII prints correctly ──
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from chainstrike.scanner import run_nmap, run_gobuster, run_nikto, resolve_wordlist
from chainstrike.parser  import parse_nmap, parse_gobuster, parse_nikto
from chainstrike.reporter import generate_report, SEVERITY_ORDER

# ─── Logging setup ────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("chainstrike")

IS_WINDOWS = platform.system() == "Windows"

# ─── Banner ───────────────────────────────────────────────────────────────────

BANNER = r"""
  ____  _           _         ____  _        _ _
 / ___|| |__   __ _(_)_ __  / ___|| |_ _ __(_) | _____
| |    | '_ \ / _` | | '_ \ \___ \| __| '__| | |/ / _ \
| |___ | | | | (_| | | | | | ___) | |_| |  | |   <  __/
 \____||_| |_|\__,_|_|_| |_||____/ \__|_|  |_|_|\_\___|

  Automated Recon & Vulnerability Assessment  |  v1.0.0
"""


# ─── CLI arguments ────────────────────────────────────────────────────────────

_DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"  # overridden at runtime


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="chainstrike",
        description="ChainStrike: chain Nmap -> Gobuster -> Nikto and produce a rich HTML report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--target", "-t",
        required=True,
        help="Target IP address or domain name (e.g. 192.168.1.1 or example.com).",
    )
    p.add_argument(
        "--output-dir", "-o",
        default="reports",
        metavar="DIR",
        help="Directory to save the HTML report (default: ./reports).",
    )
    p.add_argument(
        "--wordlist", "-w",
        default=None,
        metavar="PATH",
        help=(
            "Wordlist for Gobuster. Defaults to the system dirb wordlist on Linux "
            "or the bundled wordlist on Windows if neither is found."
        ),
    )
    p.add_argument(
        "--mock",
        action="store_true",
        help="Use static mock outputs instead of running real tools (good for CI/testing).",
    )
    p.add_argument(
        "--skip-nmap",     action="store_true", help="Skip the Nmap phase.")
    p.add_argument(
        "--skip-gobuster", action="store_true", help="Skip the Gobuster phase.")
    p.add_argument(
        "--skip-nikto",    action="store_true", help="Skip the Nikto phase.")
    p.add_argument(
        "--full-scan",
        action="store_true",
        help=(
            "Scan all 65535 ports with Nmap instead of just the top 1000. "
            "Much slower — not recommended inside Docker on Windows."
        ),
    )
    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose / debug logging.",
    )
    return p


# ─── Section header helper ────────────────────────────────────────────────────

def _section(title: str) -> None:
    """Print a visible phase separator line."""
    sep = "-" * 70
    print(f"\n{sep}")
    print(f"  {title}")
    print(f"{sep}\n")
    sys.stdout.flush()


# ─── Phase runners ────────────────────────────────────────────────────────────

def _phase_nmap(target: str, mock: bool, full_scan: bool = False) -> tuple[list, str]:
    _section("Phase 1/3 | Nmap  (port scan + service detection)")
    raw = run_nmap(target, mock=mock, full_scan=full_scan)
    if not raw:
        logger.warning("Nmap returned no output.")
        return [], "ERROR - no output"
    findings = parse_nmap(raw)
    logger.info("Nmap:     %d findings extracted.", len(findings))
    return findings, f"OK - {len(findings)} port findings"


def _phase_gobuster(target: str, wordlist: str, mock: bool) -> tuple[list, str]:
    _section(f"Phase 2/3 | Gobuster  ({target})")

    raw = run_gobuster(target, wordlist, mock=mock)
    if not raw:
        if not mock:
            logger.warning("Gobuster returned no output (tool may not be installed or target timed out).")
        return [], "ERROR - no output"
    findings = parse_gobuster(raw)
    logger.info("Gobuster (%s): %d findings extracted.", target, len(findings))
    return findings, f"OK - {len(findings)} path findings"


def _phase_nikto(target: str, mock: bool) -> tuple[list, str]:
    _section(f"Phase 3/3 | Nikto  ({target})")
    raw = run_nikto(target, mock=mock)
    if not raw:
        if not mock:
            logger.warning("Nikto returned no output (tool may not be installed or target timed out).")
        return [], "ERROR - no output"
    findings = parse_nikto(raw)
    logger.info("Nikto (%s):    %d findings extracted.", target, len(findings))
    return findings, f"OK - {len(findings)} vulnerability findings"


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    print(BANNER)

    if args.mock:
        print("  [!] MOCK MODE - no real scans will be performed.\n")

    # Resolve the wordlist once up-front so we can log it clearly
    wordlist = resolve_wordlist(args.wordlist or _DEFAULT_WORDLIST)

    logger.info("Target    : %s", args.target)
    logger.info("Output dir: %s", args.output_dir)
    logger.info("Wordlist  : %s", wordlist)
    logger.info("Platform  : %s", platform.system())
    logger.info("Mock mode : %s", args.mock)

    all_findings: list = []
    tool_status: dict[str, str] = {}

    # ── Nmap ──────────────────────────────────────────────────────────────────
    if args.skip_nmap:
        tool_status["nmap"] = "SKIPPED (--skip-nmap)"
    else:
        findings, status = _phase_nmap(args.target, args.mock, full_scan=args.full_scan)
        all_findings.extend(findings)
        tool_status["nmap"] = status

    # ── Extract Web Targets from Nmap ─────────────────────────────────────────
    web_targets = []
    nmap_run = not args.skip_nmap
    if nmap_run:
        for f in all_findings:
            if f.source == "nmap":
                svc = f.extra.get("service", "")
                if "http" in svc or svc in ["https", "http-proxy"]:
                    port = f.extra.get("port")
                    if svc == "https" or "ssl" in svc:
                        web_targets.append(f"https://{args.target}:{port}")
                    else:
                        web_targets.append(f"http://{args.target}:{port}")
        # Deduplicate
        web_targets = list(dict.fromkeys(web_targets))
    else:
        web_targets = [f"http://{args.target}"]

    if nmap_run and not web_targets:
        logger.info("No web ports discovered by Nmap. Skipping web scanners.")

    # ── Gobuster ──────────────────────────────────────────────────────────────
    if args.skip_gobuster:
        tool_status["gobuster"] = "SKIPPED (--skip-gobuster)"
    elif nmap_run and not web_targets:
        tool_status["gobuster"] = "SKIPPED (no web ports open)"
    else:
        status_list = []
        for wt in web_targets:
            findings, status = _phase_gobuster(wt, wordlist, args.mock)
            all_findings.extend(findings)
            status_list.append(status)
        tool_status["gobuster"] = " | ".join(status_list) if status_list else "SKIPPED"

    # ── Nikto ─────────────────────────────────────────────────────────────────
    if args.skip_nikto:
        tool_status["nikto"] = "SKIPPED (--skip-nikto)"
    elif nmap_run and not web_targets:
        tool_status["nikto"] = "SKIPPED (no web ports open)"
    else:
        status_list = []
        for wt in web_targets:
            findings, status = _phase_nikto(wt, args.mock)
            all_findings.extend(findings)
            status_list.append(status)
        tool_status["nikto"] = " | ".join(status_list) if status_list else "SKIPPED"

    # ── Report ────────────────────────────────────────────────────────────────
    _section("Generating HTML Report")

    if not all_findings:
        logger.warning("No findings collected. The report will be empty.")

    try:
        report_path = generate_report(
            target=args.target,
            findings=all_findings,
            tool_status=tool_status,
            output_dir=args.output_dir,
        )
    except Exception as exc:
        logger.error("Failed to generate report: %s", exc, exc_info=True)
        return 1

    # ── Summary ───────────────────────────────────────────────────────────────
    sev_counts = {s: sum(1 for f in all_findings if f.severity == s) for s in SEVERITY_ORDER}
    sep = "=" * 70

    print(f"\n{sep}")
    print("  SCAN COMPLETE")
    print(sep)
    print(f"  Target        : {args.target}")
    print(f"  Total findings: {len(all_findings)}")
    for sev in SEVERITY_ORDER:
        count = sev_counts.get(sev, 0)
        if count:
            print(f"    {sev:<10}: {count}")
    print(f"\n  Report saved  : {os.path.abspath(report_path)}")
    print(sep + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
