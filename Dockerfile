# ─────────────────────────────────────────────────────────────────────────────
#  ChainStrike – Docker image
#  Base: kalilinux/kali-rolling (ships nmap, gobuster, nikto, perl out of the box)
#  Build: docker build -t chainstrike .
#  Run:   docker run --rm --network host -v $(pwd)/reports:/app/reports chainstrike --target 192.168.1.1
# ─────────────────────────────────────────────────────────────────────────────

FROM kalilinux/kali-rolling:latest

LABEL maintainer="shouryakakkar" \
      description="ChainStrike – Automated Recon & Vulnerability Assessment" \
      version="1.0.0"

# ── 1. System packages ────────────────────────────────────────────────────────
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        nmap \
        gobuster \
        nikto \
        perl \
        python3 \
        python3-pip \
        python3-matplotlib \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── 2. Python dependencies ────────────────────────────────────────────────────
WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# ── 3. Application source ─────────────────────────────────────────────────────
COPY . .

# ── 4. Reports output directory (bind-mounted at runtime) ─────────────────────
RUN mkdir -p /app/reports

# ── 5. Entrypoint ─────────────────────────────────────────────────────────────
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
