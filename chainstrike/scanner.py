"""
Scanner module: runs Nmap, Gobuster, and Nikto as subprocesses.

Tool resolution priority (for each tool):
  1. Bundled binary / script in  chainstrike/tools/bin/  or  chainstrike/tools/nikto/
  2. System PATH
  3. Fallback: Python web scanner (for Nikto only — zero dependencies)

Windows-safe: uses threaded stdout+stderr draining and CREATE_NO_WINDOW.
"""

import os
import platform
import shutil
import subprocess
import sys
import threading
import logging

from chainstrike.mock_data import NMAP_MOCK_OUTPUT, GOBUSTER_MOCK_OUTPUT, NIKTO_MOCK_OUTPUT

logger = logging.getLogger(__name__)

IS_WINDOWS = platform.system() == "Windows"

# ─── Bundled tool paths ───────────────────────────────────────────────────────

_TOOLS_DIR  = os.path.join(os.path.dirname(__file__), "tools")
_BIN_DIR    = os.path.join(_TOOLS_DIR, "bin")
_NIKTO_DIR  = os.path.join(_TOOLS_DIR, "nikto")
_PERL_DIR   = os.path.join(_TOOLS_DIR, "perl")   # Strawberry Perl Portable

# Bundled perl.exe inside Strawberry Perl Portable
_BUNDLED_PERL_EXE = os.path.join(_PERL_DIR, "perl", "bin", "perl.exe")

_BUNDLED_GOBUSTER = os.path.join(
    _BIN_DIR, "gobuster.exe" if IS_WINDOWS else "gobuster"
)
_BUNDLED_NIKTO_PL = os.path.join(_NIKTO_DIR, "nikto.pl")

# Path to the bundled wordlist shipped with this package
_BUNDLED_WORDLIST = os.path.join(
    os.path.dirname(__file__), "wordlists", "common.txt"
)


# ─── Tool resolution ──────────────────────────────────────────────────────────

def _find_tool(*names: str) -> str | None:
    """
    Search bundled bin dir first, then PATH.
    On Windows also checks <name>.exe automatically.
    """
    # Check bundled dir first
    for name in names:
        for candidate in (name, name + ".exe"):
            path = os.path.join(_BIN_DIR, candidate)
            if os.path.isfile(path) and os.access(path, os.X_OK if not IS_WINDOWS else os.F_OK):
                return path

    # Then system PATH
    for name in names:
        found = shutil.which(name)
        if found:
            return found
        if IS_WINDOWS:
            found = shutil.which(name + ".exe")
            if found:
                return found
    return None


def _find_perl() -> str | None:
    """
    Return the path to a working perl executable.
    Checks (in order):
      1. Bundled Strawberry Perl Portable  (chainstrike/tools/perl/)
      2. System PATH
    """
    if IS_WINDOWS and os.path.isfile(_BUNDLED_PERL_EXE):
        return _BUNDLED_PERL_EXE
    return shutil.which("perl")


def _perl_env(perl_exe: str) -> dict:
    """
    Build a subprocess environment suitable for running Strawberry Perl Portable.
    When using the bundled perl.exe, we prepend its bin directory to PATH and
    set PERL5LIB so Nikto can find its modules regardless of system state.
    For system Perl the current environment is returned unchanged.
    """
    env = os.environ.copy()
    if perl_exe != _BUNDLED_PERL_EXE:
        return env

    perl_root = os.path.join(_PERL_DIR, "perl")
    perl_bin  = os.path.join(perl_root, "bin")
    perl_lib  = os.path.join(perl_root, "lib")
    perl_site  = os.path.join(perl_root, "site", "lib")
    c_bin     = os.path.join(_PERL_DIR, "c", "bin")

    env["PATH"] = os.pathsep.join(
        [perl_bin, c_bin, env.get("PATH", "")]
    )
    env["PERL5LIB"] = os.pathsep.join([perl_lib, perl_site])
    env["PERL_LOCAL_LIB_ROOT"] = perl_lib
    return env


def resolve_wordlist(user_supplied: str) -> str:
    """
    Return the best available wordlist path:
      1. User-supplied (if it exists)
      2. System dirb wordlist (Linux / Kali)
      3. Bundled wordlist (always available)
    """
    if os.path.isfile(user_supplied):
        return user_supplied

    system_wl = "/usr/share/wordlists/dirb/common.txt"
    if os.path.isfile(system_wl):
        logger.info("Using system wordlist: %s", system_wl)
        return system_wl

    logger.info("Using bundled wordlist: %s", _BUNDLED_WORDLIST)
    return _BUNDLED_WORDLIST


# ─── Subprocess helper ────────────────────────────────────────────────────────

def _stream_reader(stream, chunks: list) -> None:
    """Thread target: drain a stream line-by-line."""
    try:
        for line in stream:
            chunks.append(line)
            sys.stdout.write(line)
            sys.stdout.flush()
    except Exception:
        pass


def _run(cmd: list[str], timeout: int = 3600, env: dict | None = None) -> tuple[str, str, int]:
    """
    Run *cmd* with concurrent stdout/stderr draining.
    Returns (stdout_text, stderr_text, returncode).
    Pass *env* to override the subprocess environment (used for bundled Perl).
    """
    logger.debug("Running: %s", " ".join(str(c) for c in cmd))
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0,
        )

        out_chunks: list[str] = []
        err_chunks: list[str] = []

        t_out = threading.Thread(target=_stream_reader, args=(proc.stdout, out_chunks), daemon=True)
        t_err = threading.Thread(target=_stream_reader, args=(proc.stderr, err_chunks), daemon=True)
        t_out.start()
        t_err.start()

        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            logger.error("Command timed out: %s", " ".join(str(c) for c in cmd))
            return "", "Timeout expired", -1
        finally:
            t_out.join(timeout=5)
            t_err.join(timeout=5)

        return "".join(out_chunks), "".join(err_chunks), proc.returncode

    except FileNotFoundError:
        logger.error("Tool not found: %s", cmd[0])
        return "", f"Tool not found: {cmd[0]}", -1


# ─── Nmap ────────────────────────────────────────────────────────────────────

def run_nmap(target: str, mock: bool = False, full_scan: bool = False) -> str:
    """
    Run an Nmap port scan with service/version detection.

    By default scans the top 1000 most common ports (-T4, fast).
    Pass full_scan=True to scan all 65535 ports (-p-), which is much
    slower — especially inside Docker on Windows where raw SYN scans
    are unavailable and nmap falls back to TCP connect.
    """
    if mock:
        logger.info("[MOCK] Returning mock Nmap output.")
        print(NMAP_MOCK_OUTPUT)
        return NMAP_MOCK_OUTPUT

    tool = _find_tool("nmap")
    if not tool:
        logger.error(
            "nmap is not installed or not on PATH.\n"
            "  Windows: https://nmap.org/download.html\n"
            "  Linux  : sudo apt install nmap"
        )
        return ""

    if full_scan:
        port_args = ["-p-", "--defeat-rst-ratelimit"]
        logger.info("Nmap: full port scan (all 65535 ports) — this may take several minutes.")
    else:
        port_args = ["--top-ports", "1000"]
        logger.info("Nmap: scanning top 1000 ports (use --full-scan for all ports).")

    print("\n[*] Running Nmap...\n")
    cmd = [tool, "-sV", "-sC", "--open", "-T4", "--host-timeout", "5m"] + port_args + [target]
    stdout, stderr, code = _run(cmd)
    if code not in (0, 1):
        logger.warning("nmap exited with code %d", code)
    return stdout or stderr


# ─── Gobuster ────────────────────────────────────────────────────────────────

def run_gobuster(target: str, wordlist: str, mock: bool = False) -> str:
    """Run Gobuster directory brute force. Uses bundled binary if available."""
    if mock:
        logger.info("[MOCK] Returning mock Gobuster output.")
        print(GOBUSTER_MOCK_OUTPUT)
        return GOBUSTER_MOCK_OUTPUT

    tool = _find_tool("gobuster")
    if not tool:
        logger.error(
            "gobuster not found in bundled tools or PATH.\n"
            "  Run:     python setup_tools.py --gobuster-only\n"
            "  Windows: https://github.com/OJ/gobuster/releases\n"
            "  Linux  : sudo apt install gobuster"
        )
        return ""

    resolved = resolve_wordlist(wordlist)
    if resolved != wordlist:
        logger.info("Wordlist resolved to: %s", resolved)

    url = target if target.startswith("http") else f"http://{target}"

    print("\n[*] Running Gobuster...\n")
    stdout, stderr, code = _run([
        tool, "dir",
        "-u", url,
        "-w", resolved,
        "-t", "20",
        "--no-error",
        "-q",
    ])
    if code not in (0, 1):
        logger.warning("gobuster exited with code %d", code)
    return stdout


# ─── Nikto ───────────────────────────────────────────────────────────────────

def _find_nikto() -> tuple[str | None, str | None]:
    """
    Return (tool_path, perl_path) for the best available Nikto installation.

    Search order:
      1. Bundled nikto.pl  +  bundled Strawberry Perl (chainstrike/tools/perl/)
      2. Bundled nikto.pl  +  system Perl
      3. System 'nikto' binary (pre-compiled, no Perl needed)
      4. System 'nikto.pl' + any available Perl
    Returns (None, None) if nothing usable is found.
    """
    perl = _find_perl()

    # 1 & 2: Bundled nikto.pl
    if os.path.isfile(_BUNDLED_NIKTO_PL):
        if perl:
            return _BUNDLED_NIKTO_PL, perl
        else:
            logger.warning(
                "Bundled nikto.pl found but no Perl interpreter is available.\n"
                "  Run:  python setup_tools.py --perl-only\n"
                "  Falling back to built-in Python scanner."
            )
            return None, None

    # 3: System nikto binary (Linux packages ship a wrapper script)
    sys_nikto = shutil.which("nikto")
    if sys_nikto:
        return sys_nikto, None

    # 4: System nikto.pl
    sys_nikto_pl = shutil.which("nikto.pl")
    if sys_nikto_pl and perl:
        return sys_nikto_pl, perl

    return None, None


def run_nikto(target: str, mock: bool = False) -> str:
    """
    Run Nikto (or the Python fallback web scanner) against the target.

    Priority:
      1. Bundled nikto.pl (downloaded by setup_tools.py) + Perl
      2. System nikto binary
      3. System nikto.pl + Perl
      4. Built-in Python web scanner (zero dependencies, always available)
    """
    if mock:
        logger.info("[MOCK] Returning mock Nikto output.")
        print(NIKTO_MOCK_OUTPUT)
        return NIKTO_MOCK_OUTPUT

    tool, perl = _find_nikto()

    if tool:
        print("\n[*] Running Nikto...\n")

        if tool.endswith(".pl"):
            # Build environment for Strawberry Perl Portable if needed
            env = _perl_env(perl)
            cmd = [perl, tool, "-h", target]
        else:
            env = None
            cmd = [tool, "-h", target]

        stdout, stderr, code = _run(cmd, env=env)
        if code not in (0, 1):
            logger.warning("nikto exited with code %d", code)
        return stdout or stderr

    # ── Python fallback ───────────────────────────────────────────────────────
    logger.info(
        "Nikto not available. Using built-in Python web scanner instead.\n"
        "  Tip: run  python setup_tools.py --nikto-only  to download Nikto."
    )
    print("\n[*] Running built-in Python web scanner (Nikto fallback)...\n")

    try:
        from chainstrike.tools.web_scanner import run_python_web_scan
        output = run_python_web_scan(target)
        print(output)
        return output
    except Exception as exc:
        logger.error("Python web scanner failed: %s", exc)
        return ""
