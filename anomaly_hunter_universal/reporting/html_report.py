"""
reporting/html_report.py  -  Anomaly Hunter v3
================================================
Generates a self-contained HTML investigation report.

Sections:
  1. Executive Banner  (score, severity, patient zero)
  2. Statistics Grid   (event counts, alert counts)
  3. Correlated Incidents Table
  4. Kill Chain Timeline  (visual stage flow)
  5. MITRE Coverage Table
  6. Investigation Queue  (top alerts)
  7. IOC Summary Table
  8. Beaconing Summary
  9. Process Tree
 10. Attack Chain

No external JS/CSS dependencies — fully offline renderable.
"""

import html
import logging
from datetime import datetime
from pathlib import Path

import pandas as pd

log = logging.getLogger("AnomalyHunter.HTMLReport")

# ── Severity colour map ───────────────────────────────────────────────────────
SEV_COLOUR = {
    "CRITICAL":      "#c0392b",
    "HIGH":          "#e67e22",
    "MEDIUM":        "#f1c40f",
    "LOW":           "#27ae60",
    "INFO":          "#2980b9",
    "FP-SUPPRESSED": "#7f8c8d",
}

TACTIC_COLOUR = {
    "TA0001": "#8e44ad",
    "TA0002": "#c0392b",
    "TA0003": "#e67e22",
    "TA0005": "#e74c3c",
    "TA0007": "#2980b9",
    "TA0011": "#16a085",
    "TA0004": "#8e44ad",
}


def _esc(value) -> str:
    return html.escape(str(value))


def _sev_badge(severity: str) -> str:
    colour = SEV_COLOUR.get(str(severity), "#7f8c8d")
    return (
        f'<span style="background:{colour};color:#fff;padding:2px 8px;'
        f'border-radius:4px;font-size:0.78em;font-weight:700;">'
        f'{_esc(severity)}</span>'
    )


def _score_bar(score) -> str:
    try:
        s = int(float(score))
    except Exception:
        s = 0
    colour = "#c0392b" if s >= 80 else "#e67e22" if s >= 60 else "#f1c40f" if s >= 40 else "#27ae60"
    return (
        f'<div style="display:inline-flex;align-items:center;gap:6px;">'
        f'<div style="width:80px;background:#eee;border-radius:4px;height:8px;">'
        f'<div style="width:{s}%;background:{colour};border-radius:4px;height:8px;"></div></div>'
        f'<span style="font-size:0.85em;font-weight:700;">{s}</span></div>'
    )


def _df_to_html_table(df: pd.DataFrame, max_rows: int = 200,
                      highlight_col: str = "", sev_col: str = "") -> str:
    if df is None or df.empty:
        return '<p style="color:#888;font-style:italic;">No data available.</p>'

    df = df.head(max_rows).fillna("")
    cols = df.columns.tolist()

    header = "".join(
        f'<th style="background:#2c3e50;color:#ecf0f1;padding:8px 12px;'
        f'text-align:left;font-size:0.82em;white-space:nowrap;">'
        f'{_esc(c)}</th>' for c in cols
    )

    rows_html = []
    for i, (_, row) in enumerate(df.iterrows()):
        bg = "#f9f9f9" if i % 2 == 0 else "#ffffff"

        # Highlight row if severity column present
        if sev_col and sev_col in row:
            sev = str(row[sev_col])
            if sev == "CRITICAL":   bg = "#fdecea"
            elif sev == "HIGH":     bg = "#fef6e4"
            elif sev == "MEDIUM":   bg = "#fffde4"

        cells = []
        for col in cols:
            val = row[col]
            cell_str = _esc(str(val))

            # Special renderers
            if col in ("Severity", "Alert Severity", "Sigma Level", "Incident Severity"):
                cell_str = _sev_badge(str(val))
            elif col in ("Risk Score", "Chain Risk Score", "Incident Score",
                         "Beacon Score", "Alert Score", "Max Risk Score"):
                cell_str = _score_bar(val)
            elif col in ("MITRE Technique",) and str(val).startswith("T"):
                tid = _esc(str(val))
                cell_str = (
                    f'<a href="https://attack.mitre.org/techniques/{tid.replace(".","/")}" '
                    f'target="_blank" style="color:#2980b9;text-decoration:none;">'
                    f'{tid}</a>'
                )
            elif col in ("Process", "Full Child Path", "Root Process") and "\\" in str(val):
                parts = str(val).split("\\")
                basename = _esc(parts[-1])
                fullpath = _esc(str(val))
                cell_str = f'<span title="{fullpath}" style="font-weight:600;">{basename}</span>'
            elif col == "TI Verdict":
                colour_map = {"Malicious": "#c0392b", "Suspicious": "#e67e22",
                              "Recon": "#8e44ad", "Clean": "#27ae60", "Unknown": "#95a5a6"}
                c = colour_map.get(str(val), "#555")
                cell_str = f'<span style="color:{c};font-weight:700;">{_esc(str(val))}</span>'

            cells.append(
                f'<td style="padding:6px 10px;border-bottom:1px solid #eee;'
                f'font-size:0.82em;max-width:320px;overflow:hidden;'
                f'text-overflow:ellipsis;white-space:nowrap;">{cell_str}</td>'
            )
        rows_html.append(
            f'<tr style="background:{bg};">{"".join(cells)}</tr>'
        )

    return (
        f'<div style="overflow-x:auto;">'
        f'<table style="border-collapse:collapse;width:100%;font-family:monospace;">'
        f'<thead><tr>{header}</tr></thead>'
        f'<tbody>{"".join(rows_html)}</tbody>'
        f'</table></div>'
    )


def _section(title: str, content: str, colour: str = "#2c3e50") -> str:
    return f"""
    <div style="margin:24px 0;background:#fff;border-radius:8px;
                box-shadow:0 2px 8px rgba(0,0,0,0.08);overflow:hidden;">
      <div style="background:{colour};color:#fff;padding:12px 20px;
                  font-size:1.05em;font-weight:700;">{_esc(title)}</div>
      <div style="padding:20px;">{content}</div>
    </div>"""


def _kill_chain_visual(kill_chain_df: pd.DataFrame) -> str:
    if kill_chain_df is None or kill_chain_df.empty:
        return "<p style='color:#888;font-style:italic;'>No kill chain data.</p>"

    stage_colours = {
        "1": "#8e44ad", "2": "#e74c3c", "3": "#e67e22",
        "4": "#c0392b", "5": "#2980b9", "6": "#16a085",
    }

    seen_stages = []
    for stage in kill_chain_df["Stage"].unique():
        num = str(stage).split("–")[0].strip().replace("Stage ", "")
        colour = stage_colours.get(num, "#555")
        seen_stages.append((stage, colour))

    flow_html = '<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:20px;">'
    for stage, colour in seen_stages:
        label = str(stage).split("–")[-1].strip() if "–" in str(stage) else str(stage)
        flow_html += (
            f'<div style="background:{colour};color:#fff;padding:8px 14px;'
            f'border-radius:20px;font-size:0.8em;font-weight:600;">'
            f'{_esc(label)}</div>'
            f'<div style="color:#ccc;font-size:1.2em;align-self:center;">›</div>'
        )
    flow_html += "</div>"

    table_html = _df_to_html_table(
        kill_chain_df[["Stage", "MITRE Tactic", "Timestamp", "Process", "Detail", "Risk Score"]],
        sev_col=""
    )
    return flow_html + table_html


def _stats_grid(stats: dict) -> str:
    cards = []
    colours = ["#2980b9","#c0392b","#e67e22","#27ae60","#8e44ad","#16a085","#e74c3c","#f39c12"]
    for i, (k, v) in enumerate(stats.items()):
        c = colours[i % len(colours)]
        cards.append(
            f'<div style="background:{c};color:#fff;border-radius:8px;padding:16px 20px;'
            f'min-width:160px;flex:1;">'
            f'<div style="font-size:1.8em;font-weight:800;">{_esc(str(v))}</div>'
            f'<div style="font-size:0.78em;opacity:0.9;margin-top:4px;">{_esc(k)}</div>'
            f'</div>'
        )
    return (
        '<div style="display:flex;flex-wrap:wrap;gap:12px;">'
        + "".join(cards) + "</div>"
    )


def _mitre_heatmap(mitre_df: pd.DataFrame) -> str:
    if mitre_df is None or mitre_df.empty:
        return "<p style='color:#888;'>No MITRE coverage data.</p>"

    cells = []
    for _, row in mitre_df.iterrows():
        tid   = _esc(str(row.get("Tactic ID", "")))
        tname = _esc(str(row.get("Tactic Name", "")))
        count = row.get("Alert Count", 0)
        tech  = _esc(str(row.get("Top Technique", "")))
        # Intensity based on alert count
        intensity = min(int(count) * 15 + 40, 220)
        bg = f"rgb({intensity},60,60)"
        cells.append(
            f'<div style="background:{bg};color:#fff;border-radius:6px;padding:10px 14px;'
            f'min-width:140px;flex:1;">'
            f'<div style="font-size:0.72em;opacity:0.85;">{tid}</div>'
            f'<div style="font-weight:700;font-size:0.9em;">{tname}</div>'
            f'<div style="font-size:0.75em;margin-top:4px;">{count} alerts | {tech}</div>'
            f'</div>'
        )
    return '<div style="display:flex;flex-wrap:wrap;gap:10px;">' + "".join(cells) + "</div>"


def _patient_zero_card(pz: dict) -> str:
    if not pz:
        return "<p style='color:#888;'>Patient zero not identified.</p>"
    sev_c = SEV_COLOUR.get(pz.get("Severity",""), "#555")
    return f"""
    <div style="display:flex;gap:20px;flex-wrap:wrap;">
      <div style="background:#2c3e50;color:#ecf0f1;border-radius:8px;
                  padding:16px 24px;flex:2;min-width:280px;">
        <div style="font-size:0.75em;opacity:0.7;margin-bottom:4px;">PATIENT ZERO — INITIAL DROPPER</div>
        <div style="font-size:1.3em;font-weight:800;color:#e74c3c;">{_esc(pz.get("Process Name","?"))}</div>
        <div style="font-size:0.78em;opacity:0.8;margin-top:2px;">{_esc(pz.get("Process",""))}</div>
        <div style="margin-top:12px;font-size:0.82em;">
          <span style="opacity:0.7;">Parent: </span>{_esc(pz.get("Parent Name","?"))}<br>
          <span style="opacity:0.7;">First seen: </span>{_esc(pz.get("First Seen",""))}<br>
          <span style="opacity:0.7;">Raw events: </span>{_esc(str(pz.get("Raw Events",0)))}
        </div>
      </div>
      <div style="background:{sev_c};color:#fff;border-radius:8px;
                  padding:16px 24px;flex:1;min-width:140px;text-align:center;">
        <div style="font-size:0.75em;opacity:0.8;">RISK SCORE</div>
        <div style="font-size:2.8em;font-weight:900;">{pz.get("Risk Score",0)}</div>
        <div style="font-size:0.8em;font-weight:700;">{_esc(pz.get("Severity",""))}</div>
      </div>
    </div>
    <div style="margin-top:12px;background:#fdf2f8;border-left:4px solid #c0392b;
                padding:10px 16px;border-radius:4px;font-size:0.82em;color:#555;">
      <strong>Detection:</strong> {_esc(pz.get("Detection",""))}<br>
      <strong>Reason:</strong> {_esc(str(pz.get("Reason",""))[:200])}
    </div>"""


def generate_html_report(investigation: dict, output_path: str) -> str:
    """
    Generate the full HTML investigation report.
    Returns the output file path.
    """
    stats         = investigation.get("stats", {})
    patient_zero  = investigation.get("patient_zero", {})
    sev_counts    = investigation.get("severity_counts", {})
    c2_ips        = investigation.get("c2_ips", [])
    persist_iocs  = investigation.get("persistence_indicators", [])
    mitre_cov     = investigation.get("mitre_coverage", pd.DataFrame())
    affected_procs= investigation.get("affected_processes", pd.DataFrame())
    queue_df      = investigation.get("queue_df", pd.DataFrame())
    incidents_df  = investigation.get("incidents_df", pd.DataFrame())
    kill_chain_df = investigation.get("kill_chain_df", pd.DataFrame())
    ioc_df        = investigation.get("ioc_df", pd.DataFrame())
    timeline_df   = investigation.get("timeline_df", pd.DataFrame())
    tree_df       = investigation.get("tree_df", pd.DataFrame())
    beacon_df     = investigation.get("beacon_df", pd.DataFrame())
    chain_df      = investigation.get("alerts_df", pd.DataFrame())   # reuse alerts for chain

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    overall_sev  = "CRITICAL" if sev_counts.get("CRITICAL",0) else \
                   "HIGH"     if sev_counts.get("HIGH",0)     else \
                   "MEDIUM"   if sev_counts.get("MEDIUM",0)   else "LOW"
    banner_colour = SEV_COLOUR.get(overall_sev, "#2c3e50")

    # ── IOC callout bar ───────────────────────────────────────────────
    ioc_bar = ""
    if c2_ips:
        ioc_bar += (
            '<div style="background:#fdecea;border:1px solid #e74c3c;border-radius:6px;'
            'padding:10px 16px;margin:12px 0;font-size:0.83em;">'
            f'<strong style="color:#c0392b;">⚠ C2 IPs identified:</strong> '
            + " &nbsp;|&nbsp; ".join(f'<code>{_esc(ip)}</code>' for ip in c2_ips[:8])
            + "</div>"
        )
    if persist_iocs:
        ioc_bar += (
            '<div style="background:#fff8e1;border:1px solid #f39c12;border-radius:6px;'
            'padding:10px 16px;margin:12px 0;font-size:0.83em;">'
            f'<strong style="color:#e67e22;">🔑 Persistence keys:</strong> '
            + " &nbsp;|&nbsp; ".join(f'<code>{_esc(k)}</code>' for k in persist_iocs[:4])
            + "</div>"
        )

    # ── Queue: pick best columns available ────────────────────────────
    queue_cols = [c for c in [
        "Alert ID","Timestamp","Risk Score","Severity","Process",
        "Detection Type","MITRE Technique","Analyst Verdict","Recommendation"
    ] if c in (queue_df.columns if not queue_df.empty else [])]
    queue_display = queue_df[queue_cols].head(50) if queue_cols else queue_df.head(50)

    # ── Timeline: pick best columns ────────────────────────────────────
    tl_cols = [c for c in [
        "Timeline #","Timestamp","Tactic","Process","Detection Type",
        "Risk Score","Severity","MITRE Technique"
    ] if c in (timeline_df.columns if not timeline_df.empty else [])]
    tl_display = timeline_df[tl_cols].head(80) if tl_cols else timeline_df.head(80)

    # ── Process tree ───────────────────────────────────────────────────
    tree_cols = [c for c in [
        "Depth","PID","Process Name","Parent Name","Event Count",
        "Alert Severity","Alert Score","Detection Types"
    ] if c in (tree_df.columns if not tree_df.empty else [])]
    tree_display = tree_df[tree_cols].head(80) if tree_cols else tree_df.head(80)

    # ── Build HTML ─────────────────────────────────────────────────────
    body = f"""
    <!DOCTYPE html><html lang="en"><head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Anomaly Hunter v3 — Investigation Report</title>
    <style>
      body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;
            background:#f0f2f5;margin:0;padding:0;color:#222;}}
      .container{{max-width:1400px;margin:0 auto;padding:24px;}}
      code{{background:#f4f4f4;padding:1px 5px;border-radius:3px;font-size:0.85em;}}
      a{{color:#2980b9;}}
    </style>
    </head><body>

    <!-- BANNER -->
    <div style="background:{banner_colour};color:#fff;padding:20px 32px;">
      <div style="max-width:1400px;margin:0 auto;display:flex;
                  justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;">
        <div>
          <div style="font-size:1.5em;font-weight:900;">🔍 Anomaly Hunter v3</div>
          <div style="font-size:0.88em;opacity:0.85;">Investigation Report &nbsp;·&nbsp; Generated {_esc(generated_at)}</div>
        </div>
        <div style="text-align:right;">
          <div style="font-size:0.78em;opacity:0.8;">Overall Severity</div>
          <div style="font-size:2em;font-weight:900;">{_esc(overall_sev)}</div>
        </div>
      </div>
    </div>

    <div class="container">
      {ioc_bar}

      {_section("Patient Zero — Initial Dropper", _patient_zero_card(patient_zero), "#c0392b")}

      {_section("Investigation Statistics", _stats_grid(stats), "#2c3e50")}

      {_section("MITRE ATT&CK Coverage", _mitre_heatmap(mitre_cov), "#8e44ad")}

      {_section("Correlated Incidents", _df_to_html_table(incidents_df, sev_col="Severity"), "#e67e22")}

      {_section("Kill Chain Reconstruction", _kill_chain_visual(kill_chain_df), "#c0392b")}

      {_section("Investigation Queue — Top Alerts (MEDIUM+)", _df_to_html_table(queue_display, sev_col="Severity"), "#e74c3c")}

      {_section("Threat Intelligence — IOC Summary", _df_to_html_table(ioc_df.head(100) if ioc_df is not None else pd.DataFrame(), sev_col=""), "#16a085")}

      {_section("Beaconing Analysis", _df_to_html_table(beacon_df, sev_col="") if beacon_df is not None else _section("",""), "#2980b9")}

      {_section("Attack Timeline (MITRE-staged)", _df_to_html_table(tl_display, sev_col="Severity"), "#27ae60")}

      {_section("Affected Processes", _df_to_html_table(affected_procs, sev_col="Severity"), "#8e44ad")}

      {_section("Process Tree", _df_to_html_table(tree_display, sev_col="Alert Severity"), "#2c3e50")}

      <div style="text-align:center;color:#aaa;font-size:0.78em;padding:24px 0;">
        Anomaly Hunter v3 &nbsp;·&nbsp; {_esc(generated_at)} &nbsp;·&nbsp;
        For analyst use only — handle as TLP:AMBER
      </div>
    </div>
    </body></html>"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(body)

    log.info("HTML report written: %s", output_path)
    return output_path
