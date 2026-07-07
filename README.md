# ⛓ ChainStrike

> **Automated Recon & Vulnerability Assessment CLI**  
> Chain `nmap → gobuster → nikto`, parse every finding, map it to OWASP Top 10 + MITRE ATT&CK, and produce a premium dark-themed HTML report — in one command.

---

## Features

| Feature | Details |
|---|---|
| **Tool chain** | Nmap (full port scan) → Gobuster (dir brute-force) → Nikto (web vulns) |
| **Smart Targeting** | Extracts non-standard web ports from Nmap results and routes web scanners to the correct port — skips them entirely if no web ports are open |
| **Auto-mapping** | Each finding mapped to OWASP Top 10 category & MITRE ATT&CK TTP |
| **CVE detection** | CVE IDs extracted from Nikto output and highlighted in the report |
| **Severity rating** | Critical / High / Medium / Low / Info |
| **HTML report** | Dark-themed, filterable, self-contained — no server needed |
| **Pie chart** | Severity distribution chart embedded as base64 PNG |
| **Mock mode** | `--mock` flag uses static sample data (no real tools needed) |
| **Skip flags** | `--skip-nmap`, `--skip-gobuster`, `--skip-nikto` |
| **Zero dependency install** | Docker image ships with all tools pre-installed |

---

## Quick Start (Recommended — Docker)

**No Perl, no Gobuster, no Nikto installation needed.** Everything is baked into the Docker image.

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/) installed and running

### 1. Pull & run (one-liner)

```bash
# Clone the repo
git clone https://github.com/shouryakakkar/ChainStrike.git
cd ChainStrike

# Build the image (one-time, ~5 min)
docker build -t chainstrike .

# Run a scan (Linux / macOS)
docker run --rm --network host -v $(pwd)/reports:/app/reports chainstrike --target 192.168.1.100
```

> **Windows (PowerShell)** — use `${PWD}` in quotes and drop `--network host` (not supported on Docker Desktop for Windows):
> ```powershell
> docker run --rm -v "${PWD}\reports:/app/reports" chainstrike --target 192.168.1.100
> ```

> **Note on `--network host`:** On Linux this gives nmap raw socket access for the most accurate scans. On Windows/macOS Docker runs inside a Linux VM so `--network host` is not available — scans still work but go through the VM's NAT interface.

### 2. Using Docker Compose (easier, recommended on Windows)

```bash
# Build
docker compose build

# Run a scan
docker compose run --rm chainstrike --target 192.168.1.100

# Mock mode (no real tools required)
docker compose run --rm chainstrike --target demo --mock
```

> Docker Compose handles volume path differences between Windows and Linux automatically — no manual path quoting needed.

---

## Native Installation (No Docker)

If you prefer to run without Docker, all tools must be installed manually.

### Requirements

| Tool | Linux / Kali | Windows |
|---|---|---|
| Python 3.10+ | pre-installed | [python.org](https://www.python.org/downloads/) |
| `nmap` | `sudo apt install nmap` | [nmap.org](https://nmap.org/download.html) |
| `gobuster` | `sudo apt install gobuster` | auto-downloaded by `setup_tools.py` |
| `nikto` | `sudo apt install nikto` | auto-downloaded (needs Perl) |
| Perl (Windows only) | pre-installed | `winget install StrawberryPerl.StrawberryPerl` |

```bash
# Clone
git clone https://github.com/shouryakakkar/ChainStrike.git
cd ChainStrike

# Install Python dependencies
pip install -r requirements.txt

# Download Gobuster + Nikto (skipped if already installed system-wide)
python setup_tools.py
```

### Setup options

```bash
python setup_tools.py                  # Download Gobuster + Nikto
python setup_tools.py --gobuster-only  # Gobuster only
python setup_tools.py --nikto-only     # Nikto only
python setup_tools.py --check          # Check what's installed
python setup_tools.py --force          # Re-download even if present
```

> **Nikto on Windows**: Requires [Strawberry Perl](https://strawberryperl.com/).  
> Without Perl, ChainStrike automatically falls back to the built-in Python scanner.

---

## Usage

All flags work identically whether you use Docker or native.

### Basic scan
```bash
# Docker
docker run --rm --network host -v $(pwd)/reports:/app/reports chainstrike --target 192.168.1.100

# Native
python main.py --target 192.168.1.100
```

### Custom output directory (native only)
```bash
python main.py --target example.com --output-dir ./my-reports
```

### Custom wordlist
```bash
# Docker
docker run --rm --network host \
  -v $(pwd)/reports:/app/reports \
  -v /path/to/wordlists:/wordlists \
  chainstrike --target 10.0.0.5 --wordlist /wordlists/big.txt

# Native
python main.py --target 10.0.0.5 --wordlist /opt/wordlists/big.txt
```

### Mock mode (no real tools — great for testing the report)
```bash
docker compose run --rm chainstrike --target demo --mock
```

### Skip specific phases
```bash
docker compose run --rm chainstrike --target 10.0.0.1 --skip-gobuster --skip-nikto
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

## Project Structure

```
ChainStrike/
├── Dockerfile               # Kali-based image with all tools pre-installed
├── docker-compose.yml       # Convenience wrapper for Docker runs
├── entrypoint.sh            # Docker entrypoint
├── main.py                  # CLI entry point (argparse, orchestration)
├── setup_tools.py           # Native install helper (downloads gobuster/nikto)
├── requirements.txt         # Python dependencies
└── chainstrike/
    ├── scanner.py           # Runs nmap / gobuster / nikto as subprocesses
    ├── parser.py            # Extracts & classifies findings
    ├── reporter.py          # Builds HTML report with embedded chart
    ├── mock_data.py         # Static sample outputs for --mock mode
    ├── wordlists/           # Bundled wordlist (fallback)
    └── tools/               # Downloaded binaries (native mode only)
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
