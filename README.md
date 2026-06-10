# ⛓ ChainStrike

> **Automated Recon & Vulnerability Assessment CLI**  
> Chain `nmap → gobuster → nikto`, parse every finding, map it to OWASP Top 10 + MITRE ATT&CK, and produce a premium dark-themed HTML report in one command.

---

## Features

| Feature | Details |
|---|---|
| **Tool chain** | Nmap (full port scan) → Gobuster (dir brute-force) → Nikto (web vulns) |
| **Auto-mapping** | Each finding mapped to OWASP Top 10 category & MITRE ATT&CK TTP |
| **CVE detection** | CVE IDs extracted from Nikto output and highlighted in the report |
| **Severity rating** | Critical / High / Medium / Low / Info |
| **HTML report** | Dark-themed, filterable, self-contained — no server needed |
| **Smart Targeting** | Automatically extracts non-standard web ports from Nmap and routes web scanners, skipping them entirely if no web ports are open |
| **Pie chart** | Matplotlib severity distribution chart embedded as base64 PNG |
| **Mock mode** | `--mock` flag uses static sample data (no real tools needed) |
| **Skip flags** | `--skip-nmap`, `--skip-gobuster`, `--skip-nikto` |

---

## Requirements

### Python
- Python 3.10+

### Python packages
```bash
pip install -r requirements.txt
```

> That's it for Python dependencies. **All external tools are bundled automatically.**

### External tools
ChainStrike uses a **4-level resolution chain** to find each scanner:

| Priority | Where | Set up by |
|---|---|---|
| 1 | `chainstrike/tools/bin/` | `python setup_tools.py` |
| 2 | System PATH | Your OS package manager / manual install |
| 3 | Perl + `nikto.pl` (Nikto only) | `python setup_tools.py` (Nikto only, Perl check) |
| 4 | **Built-in Python scanner** | Always available, zero deps |

Nmap still needs to be installed separately (it requires low-level socket access
that cannot be replicated in pure Python):

| Tool | Linux / Kali | Windows |
|---|---|---|
| `nmap` | `sudo apt install nmap` | [nmap.org/download.html](https://nmap.org/download.html) |
| `gobuster` | auto-downloaded | auto-downloaded |
| `nikto` | auto-downloaded | auto-downloaded (needs Perl) |

> **Nikto on Windows**: Requires [Strawberry Perl](https://strawberryperl.com/) installed on system PATH (run `winget install StrawberryPerl`).
> Without Perl, ChainStrike automatically falls back to the built-in Python scanner.

---

## Installation

```bash
# 1. Clone
git clone https://github.com/yourname/chainstrike.git
cd chainstrike

# 2. Install Python dependency (matplotlib for charts)
pip install -r requirements.txt

# 3. Download Gobuster + Nikto (one-time, ~5 MB total)
python setup_tools.py
```

That's it. You can now run scans immediately.

> **No internet after setup?** Everything still works:
> - Gobuster binary is stored in `chainstrike/tools/bin/`
> - Nikto is stored in `chainstrike/tools/nikto/`
> - The Python web scanner runs with zero dependencies

### Setup options
```bash
python setup_tools.py                  # Download Gobuster + Nikto (checks for Perl)
python setup_tools.py --gobuster-only  # Gobuster only  (~5 MB)
python setup_tools.py --nikto-only     # Nikto only     (~2 MB)
python setup_tools.py --perl-only      # Check if Perl is installed and available
python setup_tools.py --check          # Check what's installed
python setup_tools.py --force          # Re-download even if present
```

> **Disk space**: Gobuster ~15 MB • Nikto ~5 MB
> 
> On **Linux/macOS** Perl is almost always pre-installed. Run `perl --version` to confirm.

---

## Usage

### Basic scan
```bash
python main.py --target 192.168.1.100
```

### Custom output directory
```bash
python main.py --target example.com --output-dir ./my-reports
```

### Custom wordlist
```bash
python main.py --target 10.0.0.5 --wordlist /opt/wordlists/big.txt
```

### Mock mode (no real tools required — great for testing)
```bash
python main.py --target demo --mock
```

### Skip specific phases
```bash
python main.py --target 10.0.0.1 --skip-gobuster --skip-nikto
```

### Verbose / debug logging
```bash
python main.py --target 192.168.1.1 --verbose
```

### Full option reference
```
usage: chainstrike [-h] --target TARGET [--output-dir DIR] [--wordlist PATH]
                   [--mock] [--skip-nmap] [--skip-gobuster] [--skip-nikto]
                   [--verbose]

options:
  -h, --help            show this help message and exit
  --target, -t          Target IP address or domain
  --output-dir, -o DIR  Output directory for the HTML report (default: ./reports)
  --wordlist, -w PATH   Gobuster wordlist path
  --mock                Use static mock data instead of real scans
  --skip-nmap           Skip the Nmap phase
  --skip-gobuster       Skip the Gobuster phase
  --skip-nikto          Skip the Nikto phase
  --verbose, -v         Enable debug logging
```

---

## Sample Output (Mock Run)

```
  ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
 ...

  ⚠  MOCK MODE – no real scans will be performed.

──────────────────────────────────────────────────────────────────────
  Phase 1/3 – Nmap  (full port scan + service detection)
──────────────────────────────────────────────────────────────────────

... (nmap output streams here) ...

──────────────────────────────────────────────────────────────────────
  Phase 2/3 – Gobuster  (directory brute-force)
──────────────────────────────────────────────────────────────────────

... (gobuster output streams here) ...

──────────────────────────────────────────────────────────────────────
  Phase 3/3 – Nikto  (web vulnerability scan)
──────────────────────────────────────────────────────────────────────

... (nikto output streams here) ...

══════════════════════════════════════════════════════════════════════
  SCAN COMPLETE
══════════════════════════════════════════════════════════════════════
  Target       : demo
  Total findings: 41
    Critical   : 4
    High       : 12
    Medium     : 15
    Low        : 6
    Info       : 4

  Report saved  : C:\Users\shour\ChainStrike\reports\report_demo_20240115_101500.html
══════════════════════════════════════════════════════════════════════
```

### HTML Report Screenshot

![ChainStrike HTML Report](docs/screenshot_placeholder.png)

> *Run `python main.py --target demo --mock` to generate a live report and open it in your browser.*

---

## Project Structure

```
ChainStrike/
├── main.py                  # CLI entry point (argparse, orchestration)
├── requirements.txt         # Python dependencies
├── README.md
└── chainstrike/
    ├── __init__.py
    ├── scanner.py           # Runs nmap / gobuster / nikto as subprocesses
    ├── parser.py            # Extracts & classifies findings
    ├── reporter.py          # Builds HTML report with embedded chart
    └── mock_data.py         # Static sample outputs for --mock mode
```

---

## How Mapping Works

### Severity
| Source | Logic |
|---|---|
| Nmap | Based on service type (e.g. MongoDB = High, SSH = Info) + version fingerprinting |
| Gobuster | Based on path sensitivity (`.env` = Critical, `/admin` = Medium) |
| Nikto | Based on keyword matching (path traversal = Critical, missing header = Low) |

### OWASP Top 10 (2021)
Each finding is mapped to the most relevant OWASP category, e.g.:
- Open database ports → **A05 Security Misconfiguration**
- `.env` file exposed → **A02 Cryptographic Failures**
- CVE path traversal  → **A01 Broken Access Control**

### MITRE ATT&CK TTPs
| TTP | Name | Used for |
|---|---|---|
| T1046 | Network Service Discovery | Open ports |
| T1083 | File and Directory Discovery | Gobuster paths |
| T1190 | Exploit Public-Facing Application | CVE / RCE findings |
| T1539 | Steal Web Session Cookie | Cookie flags |
| T1557 | Adversary-in-the-Middle | TRACE method |
| T1592 | Gather Victim Host Information | Server version leaks |

---

## Legal Disclaimer

> **ChainStrike is intended for authorised security testing only.**  
> Running this tool against systems you do not own or have explicit written permission to test is illegal. The authors accept no liability for misuse.

---

## License

MIT
