"""
Report generator: produces a self-contained HTML report with an embedded
matplotlib severity pie chart.
"""

import base64
import io
import logging
import os
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_COLORS = {
    "Critical": "#ef4444",
    "High":     "#f97316",
    "Medium":   "#eab308",
    "Low":      "#3b82f6",
    "Info":     "#6b7280",
}

# ─── Chart ────────────────────────────────────────────────────────────────────

def _build_pie_chart(counts: dict[str, int]) -> str:
    """
    Build a matplotlib pie chart and return it as a base64-encoded PNG string.
    Falls back to an empty string if matplotlib is unavailable.
    """
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        logger.warning("matplotlib not found; skipping pie chart.")
        return ""

    labels, sizes, colors = [], [], []
    for sev in SEVERITY_ORDER:
        count = counts.get(sev, 0)
        if count:
            labels.append(f"{sev} ({count})")
            sizes.append(count)
            colors.append(SEVERITY_COLORS[sev])

    if not sizes:
        return ""

    fig, ax = plt.subplots(figsize=(6, 6), facecolor="#0f172a")
    wedges, texts, autotexts = ax.pie(
        sizes,
        labels=labels,
        colors=colors,
        autopct="%1.1f%%",
        startangle=140,
        pctdistance=0.75,
        wedgeprops=dict(linewidth=2, edgecolor="#1e293b"),
    )
    for text in texts:
        text.set_color("#e2e8f0")
        text.set_fontsize(11)
    for autotext in autotexts:
        autotext.set_color("#ffffff")
        autotext.set_fontweight("bold")
        autotext.set_fontsize(10)

    ax.set_facecolor("#0f172a")
    ax.set_title("Findings by Severity", color="#e2e8f0", fontsize=14, pad=16)

    buf = io.BytesIO()
    plt.savefig(buf, format="png", bbox_inches="tight", facecolor="#0f172a")
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("utf-8")


# ─── HTML helpers ─────────────────────────────────────────────────────────────

def _severity_badge(sev: str) -> str:
    color = SEVERITY_COLORS.get(sev, "#6b7280")
    return f'<span class="badge" style="background:{color}">{sev}</span>'


def _source_badge(src: str) -> str:
    colors = {"nmap": "#7c3aed", "gobuster": "#0891b2", "nikto": "#dc2626"}
    c = colors.get(src.lower(), "#475569")
    return f'<span class="badge" style="background:{c}">{src.upper()}</span>'


def _finding_card(f, idx: int) -> str:
    cve_html = (
        f'<div class="meta-row"><span class="meta-label">CVE</span>'
        f'<span class="cve-tag">{f.cve}</span></div>'
        if f.cve else ""
    )
    return f"""
    <div class="card" id="finding-{idx}">
      <div class="card-header">
        <div class="card-title">{f.title}</div>
        <div class="card-badges">
          {_severity_badge(f.severity)}
          {_source_badge(f.source)}
        </div>
      </div>
      <p class="card-desc">{f.description}</p>
      <div class="meta-grid">
        <div class="meta-row">
          <span class="meta-label">MITRE ATT&amp;CK</span>
          <span class="meta-value">
            <a href="https://attack.mitre.org/techniques/{f.mitre_ttp}/" target="_blank"
               class="ttp-link">{f.mitre_ttp} – {f.mitre_ttp_name}</a>
          </span>
        </div>
        <div class="meta-row">
          <span class="meta-label">OWASP</span>
          <span class="meta-value">{f.owasp}</span>
        </div>
        {cve_html}
      </div>
      <details class="details-block">
        <summary>▶ Reproduction Steps</summary>
        <pre class="code-block">{f.reproduction}</pre>
      </details>
      <details class="details-block">
        <summary>▶ Remediation</summary>
        <p class="remediation-text">{f.remediation}</p>
      </details>
    </div>
"""


# ─── Full HTML template ───────────────────────────────────────────────────────

def _build_html(
    target: str,
    scan_date: str,
    findings,
    counts: dict[str, int],
    chart_b64: str,
    tool_status: dict[str, str],
) -> str:
    total = sum(counts.values())
    chart_section = ""
    if chart_b64:
        chart_section = f"""
        <div class="chart-wrapper">
          <img src="data:image/png;base64,{chart_b64}" alt="Severity Distribution Pie Chart"
               class="chart-img" />
        </div>"""

    summary_cards = "".join(
        f"""<div class="stat-card" style="border-color:{SEVERITY_COLORS[s]}">
              <div class="stat-num" style="color:{SEVERITY_COLORS[s]}">{counts.get(s,0)}</div>
              <div class="stat-label">{s}</div>
            </div>"""
        for s in SEVERITY_ORDER
    )

    tool_rows = "".join(
        f'<tr><td class="tool-name">{t}</td>'
        f'<td class="{("status-ok" if "OK" in s else "status-err")}">{s}</td></tr>'
        for t, s in tool_status.items()
    )

    finding_cards = "".join(
        _finding_card(f, i) for i, f in enumerate(findings, 1)
    )

    # Filter controls JS
    severities_js = str(SEVERITY_ORDER)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ChainStrike Report – {target}</title>
  <meta name="description" content="ChainStrike automated security scan report for {target}" />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
  <style>
    :root {{
      --bg:        #0f172a;
      --surface:   #1e293b;
      --surface2:  #263348;
      --border:    #334155;
      --text:      #e2e8f0;
      --muted:     #94a3b8;
      --accent:    #6366f1;
      --accent2:   #818cf8;
      --radius:    12px;
    }}
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Inter', sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
    }}

    /* ── Top bar ── */
    .topbar {{
      background: linear-gradient(135deg, #1e1b4b 0%, #0f172a 60%);
      border-bottom: 1px solid var(--border);
      padding: 1.25rem 2.5rem;
      display: flex;
      align-items: center;
      gap: 1rem;
    }}
    .topbar-logo {{
      font-size: 1.5rem;
      font-weight: 700;
      background: linear-gradient(90deg, #6366f1, #a78bfa, #38bdf8);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      letter-spacing: -0.5px;
    }}
    .topbar-sub {{
      color: var(--muted);
      font-size: 0.875rem;
    }}
    .topbar-right {{ margin-left: auto; color: var(--muted); font-size: 0.8rem; }}

    /* ── Layout ── */
    main {{ max-width: 1280px; margin: 0 auto; padding: 2.5rem 1.5rem 4rem; }}

    /* ── Section headings ── */
    .section-title {{
      font-size: 1.25rem;
      font-weight: 700;
      color: var(--text);
      margin-bottom: 1.25rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}
    .section-title::before {{
      content: '';
      display: inline-block;
      width: 4px;
      height: 1.25em;
      background: linear-gradient(180deg, #6366f1, #38bdf8);
      border-radius: 2px;
    }}
    .divider {{ border: none; border-top: 1px solid var(--border); margin: 2.5rem 0; }}

    /* ── Executive summary ── */
    .exec-grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1.5rem;
      margin-bottom: 2rem;
    }}
    @media (max-width: 768px) {{ .exec-grid {{ grid-template-columns: 1fr; }} }}

    .info-box {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1.5rem;
    }}
    .info-box h3 {{ font-size: 0.875rem; color: var(--muted); text-transform: uppercase;
                    letter-spacing: 0.05em; margin-bottom: 0.75rem; }}
    .info-row {{ display: flex; justify-content: space-between; align-items: center;
                  padding: 0.4rem 0; border-bottom: 1px solid var(--border); font-size: 0.9rem; }}
    .info-row:last-child {{ border: none; }}
    .info-val {{ color: var(--accent2); font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; }}

    /* Stat cards */
    .stats-row {{
      display: flex;
      gap: 1rem;
      flex-wrap: wrap;
      margin-bottom: 2rem;
    }}
    .stat-card {{
      flex: 1;
      min-width: 100px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-top-width: 3px;
      border-radius: var(--radius);
      padding: 1.25rem;
      text-align: center;
      transition: transform 0.2s, box-shadow 0.2s;
    }}
    .stat-card:hover {{ transform: translateY(-2px); box-shadow: 0 8px 24px rgba(0,0,0,0.4); }}
    .stat-num {{ font-size: 2rem; font-weight: 700; line-height: 1; }}
    .stat-label {{ font-size: 0.75rem; color: var(--muted); margin-top: 0.4rem;
                   text-transform: uppercase; letter-spacing: 0.05em; }}

    /* Chart */
    .chart-wrapper {{
      display: flex;
      justify-content: center;
      margin-bottom: 2rem;
    }}
    .chart-img {{ max-width: 380px; width: 100%; border-radius: var(--radius); }}

    /* Tool status table */
    .tool-table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
    .tool-table th, .tool-table td {{ padding: 0.6rem 0.9rem; text-align: left;
                                       border-bottom: 1px solid var(--border); }}
    .tool-table th {{ color: var(--muted); font-weight: 500; }}
    .tool-name {{ font-family: 'JetBrains Mono', monospace; }}
    .status-ok  {{ color: #4ade80; }}
    .status-err {{ color: #f87171; }}

    /* ── Filter bar ── */
    .filter-bar {{
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
      margin-bottom: 1.5rem;
    }}
    .filter-btn {{
      padding: 0.35rem 0.9rem;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: var(--surface);
      color: var(--muted);
      cursor: pointer;
      font-size: 0.8rem;
      font-family: 'Inter', sans-serif;
      transition: all 0.2s;
    }}
    .filter-btn:hover, .filter-btn.active {{
      background: var(--accent);
      border-color: var(--accent);
      color: #fff;
    }}

    /* ── Finding cards ── */
    .card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1.5rem;
      margin-bottom: 1rem;
      transition: box-shadow 0.2s, transform 0.2s;
      animation: slideIn 0.3s ease forwards;
    }}
    @keyframes slideIn {{
      from {{ opacity: 0; transform: translateY(8px); }}
      to   {{ opacity: 1; transform: translateY(0); }}
    }}
    .card:hover {{ box-shadow: 0 8px 32px rgba(0,0,0,0.5); transform: translateY(-1px); }}

    .card-header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 1rem;
      margin-bottom: 0.75rem;
    }}
    .card-title {{ font-weight: 600; font-size: 1rem; color: var(--text); }}
    .card-badges {{ display: flex; gap: 0.4rem; flex-shrink: 0; flex-wrap: wrap; }}

    .badge {{
      display: inline-block;
      padding: 0.2rem 0.6rem;
      border-radius: 999px;
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: #fff;
    }}

    .card-desc {{ color: var(--muted); font-size: 0.875rem; margin-bottom: 1rem; line-height: 1.6; }}

    .meta-grid {{ display: flex; flex-direction: column; gap: 0.4rem; margin-bottom: 1rem; }}
    .meta-row {{ display: flex; align-items: baseline; gap: 0.5rem; font-size: 0.82rem; flex-wrap: wrap; }}
    .meta-label {{ color: var(--muted); font-weight: 500; min-width: 110px; flex-shrink: 0; }}
    .meta-value {{ color: var(--text); }}
    .cve-tag {{
      font-family: 'JetBrains Mono', monospace;
      background: rgba(239,68,68,0.15);
      border: 1px solid rgba(239,68,68,0.3);
      color: #fca5a5;
      padding: 0.1rem 0.5rem;
      border-radius: 4px;
      font-size: 0.78rem;
    }}
    .ttp-link {{
      color: var(--accent2);
      text-decoration: none;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
    }}
    .ttp-link:hover {{ text-decoration: underline; }}

    /* Details blocks */
    .details-block {{
      border-top: 1px solid var(--border);
      padding-top: 0.75rem;
      margin-top: 0.5rem;
    }}
    .details-block summary {{
      cursor: pointer;
      color: var(--muted);
      font-size: 0.82rem;
      font-weight: 500;
      user-select: none;
      transition: color 0.2s;
    }}
    .details-block summary:hover {{ color: var(--accent2); }}
    .details-block[open] summary {{ color: var(--accent2); margin-bottom: 0.6rem; }}
    .code-block {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
      background: var(--surface2);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.75rem 1rem;
      overflow-x: auto;
      color: #a5f3fc;
    }}
    .remediation-text {{
      font-size: 0.875rem;
      color: var(--text);
      line-height: 1.65;
    }}

    /* ── Footer ── */
    footer {{
      text-align: center;
      color: var(--muted);
      font-size: 0.75rem;
      padding: 1.5rem;
      border-top: 1px solid var(--border);
    }}
  </style>
</head>
<body>

  <header class="topbar">
    <div class="topbar-logo">⛓ ChainStrike</div>
    <div class="topbar-sub">Automated Recon &amp; Vulnerability Report</div>
    <div class="topbar-right">Generated {scan_date}</div>
  </header>

  <main>

    <!-- ── Executive Summary ─────────────────────────── -->
    <section aria-labelledby="exec-title">
      <h2 class="section-title" id="exec-title">Executive Summary</h2>

      <div class="exec-grid">
        <div class="info-box">
          <h3>Scan Information</h3>
          <div class="info-row"><span>Target</span>       <span class="info-val">{target}</span></div>
          <div class="info-row"><span>Scan Date</span>    <span class="info-val">{scan_date}</span></div>
          <div class="info-row"><span>Total Findings</span><span class="info-val">{total}</span></div>
          <div class="info-row"><span>Tool Chain</span>   <span class="info-val">Nmap → Gobuster → Nikto</span></div>
        </div>
        <div class="info-box">
          <h3>Tool Execution Status</h3>
          <table class="tool-table">
            <thead><tr><th>Tool</th><th>Status</th></tr></thead>
            <tbody>{tool_rows}</tbody>
          </table>
        </div>
      </div>

      <div class="stats-row">{summary_cards}</div>

      {chart_section}
    </section>

    <hr class="divider" />

    <!-- ── Technical Findings ────────────────────────── -->
    <section aria-labelledby="findings-title">
      <h2 class="section-title" id="findings-title">Technical Findings</h2>

      <div class="filter-bar" id="filter-bar">
        <button class="filter-btn active" data-filter="all" onclick="filterFindings('all',this)">All ({total})</button>
        {"".join(
            f'<button class="filter-btn" data-filter="{s}" onclick="filterFindings(\'{s}\',this)">'
            f'{s} ({counts.get(s,0)})</button>'
            for s in SEVERITY_ORDER if counts.get(s,0)
        )}
      </div>

      <div id="findings-container">
        {finding_cards}
      </div>
    </section>

  </main>

  <footer>
    ChainStrike v1.0 • Report generated {scan_date} • Target: {target}
  </footer>

  <script>
    function filterFindings(severity, btn) {{
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      document.querySelectorAll('.card').forEach(card => {{
        if (severity === 'all') {{
          card.style.display = '';
        }} else {{
          const badge = card.querySelector('.badge');
          if (badge && badge.textContent.trim().toLowerCase() === severity.toLowerCase()) {{
            card.style.display = '';
          }} else {{
            card.style.display = 'none';
          }}
        }}
      }});
    }}
  </script>

</body>
</html>
"""


# ─── Public entry point ───────────────────────────────────────────────────────

def generate_report(
    target: str,
    findings,
    tool_status: dict[str, str],
    output_dir: str = ".",
) -> str:
    """
    Build and save the HTML report. Returns the path to the saved file.
    """
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    safe_target = target.replace("/", "_").replace(":", "_").replace(".", "_")
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename    = f"report_{safe_target}_{timestamp}.html"
    filepath    = os.path.join(output_dir, filename)

    # Count by severity
    counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    # Sort findings: Critical first
    severity_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    sorted_findings = sorted(findings, key=lambda f: severity_rank.get(f.severity, 99))

    chart_b64 = _build_pie_chart(counts)
    html = _build_html(target, scan_date, sorted_findings, counts, chart_b64, tool_status)

    os.makedirs(output_dir, exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write(html)

    logger.info("Report saved: %s", filepath)
    return filepath
