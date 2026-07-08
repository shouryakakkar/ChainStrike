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
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _section(title: str) -> None:
    """Print a visible phase separator line."""
    sep = "-" * 70
    print(f"\n{sep}")
    print(f"  {title}")
    print(f"{sep}\n")
    sys.stdout.flush()


def _fmt_duration(seconds: float) -> str:
    """Format a duration in seconds as a human-readable string."""
    m, s = divmod(int(seconds), 60)
    if m:
        return f"{m}m {s:02d}s"
    return f"{s:.1f}s"


def _phase_done(phase_name: str, start: float, finding_count: int) -> None:
    """Print a coloured completion line with duration and finding count."""
    elapsed = time.time() - start
    print(
        f"\n  ✔  {phase_name} completed in {_fmt_duration(elapsed)}"
        f"  —  {finding_count} finding(s)\n",
        flush=True,
    )


# ─── Phase runners ────────────────────────────────────────────────────────────

def _phase_nmap(target: str, mock: bool, full_scan: bool = False) -> tuple[list, str, float]:
    _section("Phase 1 | Nmap  (port scan + service detection)")
    t0 = time.time()
    raw = run_nmap(target, mock=mock, full_scan=full_scan)
    if not raw:
        logger.warning("Nmap returned no output.")
        return [], "ERROR - no output", time.time() - t0
    findings = parse_nmap(raw)
    elapsed = time.time() - t0
    _phase_done("Nmap", t0, len(findings))
    return findings, f"OK - {len(findings)} port findings ({_fmt_duration(elapsed)})", elapsed


def _phase_gobuster(target: str, wordlist: str, mock: bool) -> tuple[list, str, float]:
    _section(f"Gobuster  →  {target}")
    t0 = time.time()
    raw = run_gobuster(target, wordlist, mock=mock)
    elapsed = time.time() - t0
    if not raw:
        if not mock:
            logger.warning("Gobuster returned no output (target may have no web service or timed out).")
        return [], f"ERROR - no output ({_fmt_duration(elapsed)})", elapsed
    findings = parse_gobuster(raw)
    _phase_done(f"Gobuster ({target})", t0, len(findings))
    return findings, f"OK - {len(findings)} path findings ({_fmt_duration(elapsed)})", elapsed


def _phase_nikto(target: str, mock: bool) -> tuple[list, str, float]:
    _section(f"Nikto  →  {target}")
    t0 = time.time()
    raw = run_nikto(target, mock=mock)
    elapsed = time.time() - t0
    if not raw:
        if not mock:
            logger.warning("Nikto returned no output (target may have no web service or timed out).")
        return [], f"ERROR - no output ({_fmt_duration(elapsed)})", elapsed
    findings = parse_nikto(raw)
    _phase_done(f"Nikto ({target})", t0, len(findings))
    return findings, f"OK - {len(findings)} vulnerability findings ({_fmt_duration(elapsed)})", elapsed


def _scan_web_target(
    wt: str, wordlist: str, mock: bool,
    run_gobuster_flag: bool, run_nikto_flag: bool
) -> tuple[list, str, str, float, float]:
    """Scan a single web target with Gobuster then Nikto. Returns findings and timings."""
    g_findings, g_status, g_elapsed = [], "SKIPPED", 0.0
    n_findings, n_status, n_elapsed = [], "SKIPPED", 0.0

    if run_gobuster_flag:
        g_findings, g_status, g_elapsed = _phase_gobuster(wt, wordlist, mock)
    if run_nikto_flag:
        n_findings, n_status, n_elapsed = _phase_nikto(wt, mock)

    return g_findings + n_findings, g_status, n_status, g_elapsed, n_elapsed


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    print(BANNER)
    scan_start = time.time()

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
    phase_times: dict[str, float] = {}

    # ── Nmap ──────────────────────────────────────────────────────────────────
    if args.skip_nmap:
        tool_status["nmap"] = "SKIPPED (--skip-nmap)"
    else:
        findings, status, elapsed = _phase_nmap(args.target, args.mock, full_scan=args.full_scan)
        all_findings.extend(findings)
        tool_status["nmap"] = status
        phase_times["nmap"] = elapsed

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
        web_targets = list(dict.fromkeys(web_targets))  # deduplicate, preserve order
    else:
        web_targets = [f"http://{args.target}"]

    run_gb  = not args.skip_gobuster
    run_nkt = not args.skip_nikto

    if nmap_run and not web_targets:
        logger.info("No web ports discovered by Nmap — skipping Gobuster and Nikto.")
        tool_status["gobuster"] = "SKIPPED (no web ports open)"
        tool_status["nikto"]    = "SKIPPED (no web ports open)"

    elif web_targets and (run_gb or run_nkt):
        if len(web_targets) > 1:
            _section(
                f"Phase 2 & 3 | Web Scanners  "
                f"({len(web_targets)} targets — running in parallel)"
            )
            logger.info("Web targets: %s", ", ".join(web_targets))
        else:
            _section(f"Phase 2 & 3 | Web Scanners  →  {web_targets[0]}")

        # ── Run web targets in parallel ────────────────────────────────────
        max_workers = min(len(web_targets), 3)  # cap at 3 parallel scans
        gb_statuses, nkt_statuses = [], []
        total_gb_elapsed = total_nkt_elapsed = 0.0

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    _scan_web_target, wt, wordlist, args.mock, run_gb, run_nkt
                ): wt
                for wt in web_targets
            }
            for future in as_completed(futures):
                wt = futures[future]
                try:
                    findings, g_status, n_status, g_t, n_t = future.result()
                    all_findings.extend(findings)
                    gb_statuses.append(g_status)
                    nkt_statuses.append(n_status)
                    total_gb_elapsed  += g_t
                    total_nkt_elapsed += n_t
                except Exception as exc:
                    logger.error("Web scan of %s failed: %s", wt, exc)

        tool_status["gobuster"] = " | ".join(gb_statuses)  if run_gb  else "SKIPPED (--skip-gobuster)"
        tool_status["nikto"]    = " | ".join(nkt_statuses) if run_nkt else "SKIPPED (--skip-nikto)"
        if run_gb:
            phase_times["gobuster"] = total_gb_elapsed
        if run_nkt:
            phase_times["nikto"] = total_nkt_elapsed

    else:
        if args.skip_gobuster:
            tool_status["gobuster"] = "SKIPPED (--skip-gobuster)"
        if args.skip_nikto:
            tool_status["nikto"] = "SKIPPED (--skip-nikto)"

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
    total_elapsed = time.time() - scan_start
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

    print()
    print("  Phase timing:")
    for phase, label in [("nmap", "Nmap"), ("gobuster", "Gobuster"), ("nikto", "Nikto")]:
        if phase in phase_times:
            print(f"    {label:<12}: {_fmt_duration(phase_times[phase])}")
        else:
            status = tool_status.get(phase, "?")
            print(f"    {label:<12}: {status}")
    print(f"  ─────────────────────────────")
    print(f"  Total time    : {_fmt_duration(total_elapsed)}")
    print()
    print(f"  Report saved  : {os.path.abspath(report_path)}")
    print(sep + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
