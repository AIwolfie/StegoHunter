"""Forensic HTML Report Generator for StegoHunter batch triage and analysis."""

from __future__ import annotations

import html
import json
import os
from typing import Any


def generate_html_report(
    results: list[dict],
    output_path: str,
    title: str = "StegoHunter Forensic Triage Report",
) -> str:
    """Compile analysis findings into a standalone, offline, interactive HTML report."""
    total = len(results)
    clean_count = sum(1 for r in results if r.get("verdict") == "CLEAN")
    suspicious_count = sum(1 for r in results if r.get("verdict") == "SUSPICIOUS")
    hidden_count = sum(1 for r in results if r.get("verdict") == "HIDDEN DATA LIKELY")
    unsupported_count = total - (clean_count + suspicious_count + hidden_count)

    items_html = []
    for idx, item in enumerate(results):
        v = item.get("verdict", "UNKNOWN")
        v_class = "badge-clean" if v == "CLEAN" else "badge-hidden" if v == "HIDDEN DATA LIKELY" else "badge-suspicious"

        file_path = html.escape(str(item.get("file", "unknown")))
        basename = html.escape(os.path.basename(file_path))
        file_type = html.escape(str(item.get("type", "unknown")))

        # Extract findings breakdown
        findings = item.get("findings", [])
        findings_rows = []
        for f in findings:
            mod = html.escape(str(f.get("module", "")))
            is_susp = f.get("suspicious", False)
            if not is_susp and mod == "appended":
                is_susp = f.get("appended", False)

            status_badge = '<span class="status-chip chip-susp">SUSPICIOUS</span>' if is_susp else '<span class="status-chip chip-clean">CLEAN</span>'

            # Gather notes / reasons
            reasons = f.get("reasons", [])
            details_list = f.get("details", [])
            lines = []
            if isinstance(reasons, list):
                for r in reasons:
                    lines.append(f"• {html.escape(str(r))}")
            if isinstance(details_list, list):
                for d in details_list:
                    lines.append(f"• {html.escape(str(d))}")

            desc = "<br>".join(lines) if lines else html.escape(f.get("note", "No anomalies observed"))

            findings_rows.append(f"""
            <tr>
              <td><strong>{mod.upper()}</strong></td>
              <td>{status_badge}</td>
              <td class="text-dim">{desc}</td>
            </tr>
            """)

        table_body = "".join(findings_rows) if findings_rows else "<tr><td colspan='3' class='text-dim'>No module details</td></tr>"

        card_html = f"""
        <div class="evidence-card" data-verdict="{v}">
          <div class="card-header" onclick="toggleDetails('details-{idx}')">
            <div class="card-title-col">
              <span class="file-name">{basename}</span>
              <span class="file-path">{file_path}</span>
            </div>
            <div class="card-meta-col">
              <span class="type-pill">{file_type}</span>
              <span class="badge {v_class}">{v}</span>
            </div>
          </div>
          <div id="details-{idx}" class="card-body">
            <table class="findings-table">
              <thead>
                <tr>
                  <th style="width: 120px;">Module</th>
                  <th style="width: 120px;">Status</th>
                  <th>Evidence & Findings</th>
                </tr>
              </thead>
              <tbody>
                {table_body}
              </tbody>
            </table>
          </div>
        </div>
        """
        items_html.append(card_html)

    cards_joined = "\n".join(items_html)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{html.escape(title)}</title>
  <style>
    :root {{
      --bg: #090d16;
      --card-bg: #111827;
      --card-border: #1f2937;
      --text: #f3f4f6;
      --text-dim: #9ca3af;
      --accent: #38bdf8;
      --green: #22c55e;
      --yellow: #f59e0b;
      --red: #ef4444;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 32px 16px;
    }}
    .container {{
      max-width: 1100px;
      margin: 0 auto;
    }}
    header {{
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--card-border);
    }}
    .brand {{
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 8px;
    }}
    .brand h1 {{
      font-size: 24px;
      font-weight: 700;
      color: var(--text);
      letter-spacing: -0.5px;
    }}
    .tagline {{
      color: var(--text-dim);
      font-size: 14px;
    }}
    .metrics-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}
    .metric-card {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 16px;
    }}
    .metric-val {{
      font-size: 28px;
      font-weight: 700;
      line-height: 1.2;
    }}
    .metric-lbl {{
      color: var(--text-dim);
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-top: 4px;
    }}
    .controls-bar {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      justify-content: space-between;
      margin-bottom: 20px;
    }}
    .filter-group {{
      display: flex;
      gap: 8px;
    }}
    .btn-filter {{
      background: #1f2937;
      border: 1px solid #374151;
      color: var(--text);
      padding: 6px 14px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 13px;
      font-weight: 500;
      transition: all 0.2s;
    }}
    .btn-filter.active, .btn-filter:hover {{
      background: var(--accent);
      color: #000;
      border-color: var(--accent);
    }}
    .search-input {{
      background: #1f2937;
      border: 1px solid #374151;
      color: var(--text);
      padding: 6px 14px;
      border-radius: 6px;
      font-size: 13px;
      min-width: 260px;
    }}
    .search-input:focus {{
      outline: none;
      border-color: var(--accent);
    }}
    .evidence-card {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      margin-bottom: 12px;
      overflow: hidden;
    }}
    .card-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 14px 18px;
      cursor: pointer;
      user-select: none;
      background: rgba(255, 255, 255, 0.02);
    }}
    .card-header:hover {{
      background: rgba(255, 255, 255, 0.04);
    }}
    .card-title-col {{
      display: flex;
      flex-direction: column;
    }}
    .file-name {{
      font-weight: 600;
      font-size: 15px;
    }}
    .file-path {{
      font-size: 12px;
      color: var(--text-dim);
      font-family: monospace;
      margin-top: 2px;
    }}
    .card-meta-col {{
      display: flex;
      align-items: center;
      gap: 10px;
    }}
    .type-pill {{
      font-size: 11px;
      padding: 2px 8px;
      border-radius: 4px;
      background: #374151;
      color: #e5e7eb;
      text-transform: uppercase;
    }}
    .badge {{
      font-size: 12px;
      font-weight: 600;
      padding: 4px 10px;
      border-radius: 4px;
      letter-spacing: 0.3px;
    }}
    .badge-clean {{ background: rgba(34, 197, 94, 0.15); color: var(--green); border: 1px solid rgba(34, 197, 94, 0.3); }}
    .badge-suspicious {{ background: rgba(245, 158, 11, 0.15); color: var(--yellow); border: 1px solid rgba(245, 158, 11, 0.3); }}
    .badge-hidden {{ background: rgba(239, 68, 68, 0.15); color: var(--red); border: 1px solid rgba(239, 68, 68, 0.3); }}
    .card-body {{
      padding: 16px 18px;
      border-top: 1px solid var(--card-border);
    }}
    .findings-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }}
    .findings-table th {{
      text-align: left;
      padding: 8px;
      border-bottom: 1px solid #2d3748;
      color: var(--text-dim);
      font-weight: 600;
    }}
    .findings-table td {{
      padding: 10px 8px;
      border-bottom: 1px solid #1f2937;
      vertical-align: top;
    }}
    .status-chip {{
      font-size: 11px;
      font-weight: 600;
      padding: 2px 6px;
      border-radius: 4px;
    }}
    .chip-clean {{ background: rgba(34, 197, 94, 0.15); color: var(--green); }}
    .chip-susp {{ background: rgba(239, 68, 68, 0.15); color: var(--red); }}
    .text-dim {{ color: #cbd5e1; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <h1>StegoHunter Forensic Triage Report</h1>
      </div>
      <p class="tagline">Automated Steganalysis & Artifact Triaging Dashboard</p>
    </header>

    <div class="metrics-grid">
      <div class="metric-card">
        <div class="metric-val">{total}</div>
        <div class="metric-lbl">Total Files Analyzed</div>
      </div>
      <div class="metric-card">
        <div class="metric-val" style="color: var(--red);">{hidden_count}</div>
        <div class="metric-lbl">Hidden Data Likely</div>
      </div>
      <div class="metric-card">
        <div class="metric-val" style="color: var(--yellow);">{suspicious_count}</div>
        <div class="metric-lbl">Suspicious Files</div>
      </div>
      <div class="metric-card">
        <div class="metric-val" style="color: var(--green);">{clean_count}</div>
        <div class="metric-lbl">Clean Baseline Files</div>
      </div>
    </div>

    <div class="controls-bar">
      <div class="filter-group">
        <button class="btn-filter active" onclick="setFilter('ALL', this)">All ({total})</button>
        <button class="btn-filter" onclick="setFilter('HIDDEN DATA LIKELY', this)">Hidden Payloads ({hidden_count})</button>
        <button class="btn-filter" onclick="setFilter('SUSPICIOUS', this)">Suspicious ({suspicious_count})</button>
        <button class="btn-filter" onclick="setFilter('CLEAN', this)">Clean ({clean_count})</button>
      </div>
      <input type="text" id="searchInput" class="search-input" placeholder="Search filename or path..." oninput="handleSearch()">
    </div>

    <div id="evidenceList">
      {cards_joined}
    </div>
  </div>

  <script>
    let currentFilter = 'ALL';

    function toggleDetails(id) {{
      const el = document.getElementById(id);
      if (el) {{
        el.style.display = (el.style.display === 'none') ? 'block' : 'none';
      }}
    }}

    function setFilter(verdict, btn) {{
      currentFilter = verdict;
      document.querySelectorAll('.btn-filter').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      applyFilters();
    }}

    function handleSearch() {{
      applyFilters();
    }}

    function applyFilters() {{
      const query = document.getElementById('searchInput').value.toLowerCase();
      const cards = document.querySelectorAll('.evidence-card');

      cards.forEach(card => {{
        const cardVerdict = card.getAttribute('data-verdict');
        const text = card.innerText.toLowerCase();

        const matchesVerdict = (currentFilter === 'ALL') || (cardVerdict === currentFilter);
        const matchesQuery = query === '' || text.includes(query);

        card.style.display = (matchesVerdict && matchesQuery) ? 'block' : 'none';
      }});
    }}
  </script>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return output_path
