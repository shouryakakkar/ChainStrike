#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ChainStrike Tool Setup
======================
Downloads Gobuster, Nikto, and (on Windows) Strawberry Perl Portable into
  chainstrike/tools/
so the full tool chain works immediately after cloning — no system
package manager or admin rights required.

Usage:
    python setup_tools.py                  # Install everything
    python setup_tools.py --gobuster-only
    python setup_tools.py --nikto-only
    python setup_tools.py --perl-only
    python setup_tools.py --check          # Just report status
    python setup_tools.py --force          # Re-download even if present
"""

import argparse
import json
import os
import platform
import shutil
import stat
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

# ─── Paths ────────────────────────────────────────────────────────────────────

_ROOT     = Path(__file__).parent
TOOLS_DIR = _ROOT / "chainstrike" / "tools"
TOOLS_BIN = TOOLS_DIR / "bin"
NIKTO_DIR = TOOLS_DIR / "nikto"
PERL_DIR  = TOOLS_DIR / "perl"          # Strawberry Perl extracted here

# ─── Platform detection ───────────────────────────────────────────────────────

_OS   = platform.system().lower()       # windows / linux / darwin
_ARCH = platform.machine().lower()      # x86_64 / amd64 / arm64 / aarch64

# Normalise arch → Gobuster asset naming (v3.7+: Windows_x86_64, Linux_x86_64 …)
if _ARCH in ("x86_64", "amd64"):
    _GOBUSTER_ARCH = "x86_64"
elif _ARCH in ("aarch64", "arm64"):
    _GOBUSTER_ARCH = "arm64"
elif _ARCH in ("i386", "i686", "x86"):
    _GOBUSTER_ARCH = "i386"
else:
    _GOBUSTER_ARCH = "x86_64"

# Strawberry Perl portable — Windows only, 64-bit
_STRAWBERRY_ARCH = "64bit"   # only 64-bit portable is offered as .zip


# ─── Utilities ────────────────────────────────────────────────────────────────

def _print(msg: str, level: str = "info") -> None:
    icons = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[x]"}
    print(f"  {icons.get(level,'[*]')} {msg}", flush=True)


def _download(url: str, dest: Path, label: str) -> bool:
    """Download *url* to *dest* with a progress bar."""
    _print(f"Downloading {label} ...")
    _print(f"  -> {url}", "info")
    try:
        def _hook(count, block, total):
            if total > 0:
                pct = min(100, count * block * 100 // total)
                bar = "#" * (pct // 4)
                mb_done  = count * block / 1_048_576
                mb_total = total / 1_048_576
                print(
                    f"\r     [{bar:<25}] {pct:3d}%  "
                    f"({mb_done:.1f} / {mb_total:.1f} MB)",
                    end="", flush=True
                )

        urllib.request.urlretrieve(url, dest, reporthook=_hook)
        print()
        return True
    except Exception as exc:
        print()
        _print(f"Download failed: {exc}", "err")
        return False


def _make_executable(path: Path) -> None:
    if _OS != "windows":
        path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _github_latest_release(repo: str) -> dict:
    """Return the full latest-release JSON from GitHub API (or {})."""
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(url, headers={"User-Agent": "ChainStrike-Setup"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except Exception:
        return {}


# ─── Gobuster ────────────────────────────────────────────────────────────────

def _gobuster_asset(tag: str) -> tuple[str, str]:
    os_name = {"windows": "Windows", "darwin": "Darwin"}.get(_OS, "Linux")
    ext     = "zip" if _OS == "windows" else "tar.gz"
    binary  = "gobuster.exe" if _OS == "windows" else "gobuster"
    return f"gobuster_{os_name}_{_GOBUSTER_ARCH}.{ext}", binary


def install_gobuster(force: bool = False) -> bool:
    TOOLS_BIN.mkdir(parents=True, exist_ok=True)
    bin_name = "gobuster.exe" if _OS == "windows" else "gobuster"
    dest_bin = TOOLS_BIN / bin_name

    if dest_bin.exists() and not force:
        _print(f"Gobuster already present: {dest_bin}", "ok")
        return True

    print("\n--- Installing Gobuster ---")
    release = _github_latest_release("OJ/gobuster")
    tag     = release.get("tag_name", "v3.6.0")
    if not tag:
        tag = "v3.6.0"
        _print(f"GitHub API unavailable; falling back to {tag}", "warn")

    asset, binary = _gobuster_asset(tag)
    url = f"https://github.com/OJ/gobuster/releases/download/{tag}/{asset}"

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        archive  = tmp_path / asset

        if not _download(url, archive, f"Gobuster {tag}"):
            return False

        try:
            if asset.endswith(".zip"):
                with zipfile.ZipFile(archive) as zf:
                    zf.extractall(tmp_path)
            else:
                with tarfile.open(archive, "r:gz") as tf:
                    tf.extractall(tmp_path)

            candidates = list(tmp_path.rglob(binary))
            if not candidates:
                _print(f"'{binary}' not found in archive.", "err")
                return False

            shutil.copy2(candidates[0], dest_bin)
            _make_executable(dest_bin)
            _print(f"Gobuster installed: {dest_bin}", "ok")
            return True

        except Exception as exc:
            _print(f"Extraction failed: {exc}", "err")
            return False


# ─── Nikto ───────────────────────────────────────────────────────────────────

NIKTO_ZIP_URL = "https://github.com/sullo/nikto/archive/refs/heads/master.zip"


def install_nikto(force: bool = False) -> bool:
    dest_script = NIKTO_DIR / "nikto.pl"

    if dest_script.exists() and not force:
        _print(f"Nikto already present: {dest_script}", "ok")
        return True

    print("\n--- Installing Nikto ---")
    NIKTO_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        archive  = tmp_path / "nikto.zip"

        if not _download(NIKTO_ZIP_URL, archive, "Nikto (master branch)"):
            return False

        try:
            with zipfile.ZipFile(archive) as zf:
                members = [m for m in zf.namelist() if "/program/" in m]
                if not members:
                    _print("Could not locate Nikto program files in archive.", "err")
                    return False
                zf.extractall(tmp_path, members=members)

            hits = list(tmp_path.rglob("nikto.pl"))
            if not hits:
                _print("nikto.pl not found after extraction.", "err")
                return False

            src_dir = hits[0].parent
            if NIKTO_DIR.exists():
                shutil.rmtree(NIKTO_DIR)
            shutil.copytree(src_dir, NIKTO_DIR)
            _make_executable(NIKTO_DIR / "nikto.pl")
            _print(f"Nikto installed: {NIKTO_DIR / 'nikto.pl'}", "ok")
            return True

        except Exception as exc:
            _print(f"Installation failed: {exc}", "err")
            return False


# ─── Strawberry Perl (Windows) ───────────────────────────────────────────────

def _bundled_perl_exe() -> Path:
    """Return the path to the bundled perl.exe (may not exist yet)."""
    return PERL_DIR / "perl" / "bin" / "perl.exe"


def install_perl(force: bool = False) -> bool:
    """
    Check for Perl (system PATH or previously bundled) and advise if missing.
    Strawberry Perl download is removed to avoid resource/antivirus exhaustion.
    """
    # 1. Check system PATH first
    perl = shutil.which("perl")
    if perl:
        _print(f"Perl already available on PATH: {perl}", "ok")
        return True

    # 2. Check previously bundled perl
    if _OS == "windows":
        dest_exe = _bundled_perl_exe()
        if dest_exe.exists():
            _print(f"Strawberry Perl already present: {dest_exe}", "ok")
            return True

    # 3. If missing, advise how to install it
    if _OS == "windows":
        _print(
            "Perl not found on PATH or bundled tools.\n"
            "  To run Nikto on Windows, please install Strawberry Perl:\n"
            "    - Via winget:     winget install StrawberryPerl\n"
            "    - Via Chocolatey: choco install strawberryperl\n"
            "    - Via Scoop:      scoop install perl\n"
            "    - Or manually:    Download and run the installer from https://strawberryperl.com/\n"
            "  *Note: Restart your terminal/IDE after installation for the changes to take effect.*",
            "warn"
        )
    else:
        _print(
            "Perl not found on PATH.\n"
            "  Linux : sudo apt install perl\n"
            "  macOS : brew install perl",
            "warn"
        )
    return False


# ─── Status check ────────────────────────────────────────────────────────────

def check_tools() -> None:
    print("\n=== ChainStrike Tool Status ===\n")

    bundled_perl = _bundled_perl_exe()
    perl_path = (
        shutil.which("perl")
        or (str(bundled_perl) if bundled_perl.exists() else None)
    )

    checks = {
        "nmap"    : shutil.which("nmap"),
        "gobuster": (
            shutil.which("gobuster")
            or next((str(p) for p in [TOOLS_BIN/"gobuster.exe", TOOLS_BIN/"gobuster"] if p.exists()), None)
        ),
        "nikto"   : (
            shutil.which("nikto")
            or (str(NIKTO_DIR / "nikto.pl") if (NIKTO_DIR / "nikto.pl").exists() else None)
        ),
        "perl"    : perl_path,
        "python"  : sys.executable,
    }

    for tool, path in checks.items():
        icon   = "[+]" if path else "[!]"
        status = f"OK  -- {path}" if path else "NOT FOUND"
        print(f"  {icon} {tool:<12}: {status}")

    ws = _ROOT / "chainstrike" / "tools" / "web_scanner.py"
    print(f"  [+] {'py-scanner':<12}: {'OK  -- bundled (' + str(ws) + ')' if ws.exists() else 'MISSING'}")

    # Nikto readiness summary
    print()
    nikto_ready = bool(checks["nikto"] and checks["perl"])
    if nikto_ready:
        _print("Nikto + Perl are both present -- full Nikto scans enabled!", "ok")
    else:
        _print(
            "Nikto or Perl is missing -- ChainStrike will use the built-in Python scanner.\n"
            "  To enable real Nikto: python setup_tools.py --nikto-only --perl-only",
            "warn"
        )
    print()


# ─── CLI ─────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Download Gobuster + Nikto + Strawberry Perl Portable into "
            "chainstrike/tools/ for zero-install operation."
        ),
    )
    p.add_argument("--gobuster-only", action="store_true", help="Install only Gobuster.")
    p.add_argument("--nikto-only",    action="store_true", help="Install only Nikto.")
    p.add_argument("--perl-only",     action="store_true", help="Install only Strawberry Perl (Windows).")
    p.add_argument("--force",  action="store_true", help="Re-download even if already installed.")
    p.add_argument("--check",  action="store_true", help="Only report status; do not install.")
    return p


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    print(r"""
  ____  _           _         ____  _        _ _
 / ___|| |__   __ _(_)_ __  / ___|| |_ _ __(_) | _____
| |    | '_ \ / _` | | '_ \ \___ \| __| '__| | |/ / _ \
| |___ | | | | (_| | | | | | ___) | |_| |  | |   <  __/
 \____||_| |_|\__,_|_|_| |_||____/ \__|_|  |_|_|\_\___|

  Tool Setup Script  |  v1.0.0
""")

    if args.check:
        check_tools()
        return 0

    # Determine which tools to install
    only_flags = args.gobuster_only or args.nikto_only or args.perl_only
    do_gobuster = (not only_flags) or args.gobuster_only
    do_nikto    = (not only_flags) or args.nikto_only
    do_perl     = (not only_flags) or args.perl_only

    ok = True
    if do_gobuster:
        ok = install_gobuster(force=args.force) and ok
    if do_nikto:
        ok = install_nikto(force=args.force) and ok
    if do_perl:
        ok = install_perl(force=args.force) and ok

    check_tools()

    if ok:
        _print("Setup complete!  Run: python main.py --target <IP>", "ok")
    else:
        _print(
            "Some downloads failed. ChainStrike will use available tools and\n"
            "  fall back to the built-in Python scanner for web checks.",
            "warn"
        )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
