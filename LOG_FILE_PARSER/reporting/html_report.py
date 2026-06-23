"""
reporting/html_report.py  -  Anomaly Hunter Pro
=================================================
Self-contained HTML investigation report with embedded charts.
No external CSS/JS dependencies — works fully offline.
"""

import html
import logging
from datetime import datetime
from pathlib import Path

import pandas as pd

from reporting.charts import build_all_charts, chart_img_tag

log = logging.getLogger("AnomalyHunter.HTMLReport")

SEV_COLOUR = {
    "CRITICAL":"#c0392b","HIGH":"#e67e22","MEDIUM":"#f1c40f",
    "LOW":"#27ae60","INFO":"#2980b9","FP-SUPPRESSED":"#7f8c8d",
}

def _e(v): return html.escape(str(v))

def _badge(sev):
    c = SEV_COLOUR.get(str(sev),"#7f8c8d")
    return (f'<span style="background:{c};color:#fff;padding:2px 8px;'
            f'border-radius:4px;font-size:.78em;font-weight:700;">{_e(sev)}</span>')

def _bar(score):
    try: s = int(float(score))
    except: s = 0
    c = "#c0392b" if s>=80 else "#e67e22" if s>=60 else "#f1c40f" if s>=40 else "#27ae60"
    return (f'<div style="display:inline-flex;align-items:center;gap:6px;">'
            f'<div style="width:80px;background:#eee;border-radius:4px;height:8px;">'
            f'<div style="width:{s}%;background:{c};border-radius:4px;height:8px;"></div></div>'
            f'<span style="font-size:.85em;font-weight:700;">{s}</span></div>')

def _df_table(df, max_rows=200, sev_col=""):
    if df is None or df.empty:
        return '<p style="color:#888;font-style:italic;">No data.</p>'
    df = df.head(max_rows).fillna("")
    cols = df.columns.tolist()
    header = "".join(
        f'<th style="background:#2c3e50;color:#ecf0f1;padding:8px 12px;'
        f'text-align:left;font-size:.82em;white-space:nowrap;">{_e(c)}</th>'
        for c in cols)
    rows_html = []
    for i,(_, row) in enumerate(df.iterrows()):
        bg = "#f9f9f9" if i%2==0 else "#fff"
        if sev_col and sev_col in row:
            s = str(row[sev_col])
            if s=="CRITICAL": bg="#fdecea"
            elif s=="HIGH":   bg="#fef6e4"
            elif s=="MEDIUM": bg="#fffde4"
        cells = []
        for col in cols:
            val = str(row[col])
            if col in ("Severity","Alert Severity","Sigma Level"):
                cell = _badge(val)
            elif col in ("Risk Score","Chain Risk Score","Incident Score","Alert Score","Beacon Score"):
                cell = _bar(val)
            elif col=="MITRE Technique" and val.startswith("T"):
                url = f'https://attack.mitre.org/techniques/{val.replace(".","/")}'
                cell = f'<a href="{url}" target="_blank" style="color:#2980b9;">{_e(val)}</a>'
            elif col in ("Process","Full Child Path") and "\\" in val:
                base = _e(val.split("\\")[-1])
                cell = f'<span title="{_e(val)}" style="font-weight:600;">{base}</span>'
            elif col=="TI Verdict":
                cm = {"Malicious":"#c0392b","Suspicious":"#e67e22","Recon":"#8e44ad","Clean":"#27ae60"}
                c2 = cm.get(val,"#555")
                cell = f'<span style="color:{c2};font-weight:700;">{_e(val)}</span>'
            else:
                cell = _e(val[:200])
            cells.append(f'<td style="padding:6px 10px;border-bottom:1px solid #eee;'
                         f'font-size:.82em;max-width:340px;overflow:hidden;'
                         f'text-overflow:ellipsis;white-space:nowrap;">{cell}</td>')
        rows_html.append(f'<tr style="background:{bg};">{"".join(cells)}</tr>')
    return (f'<div style="overflow-x:auto;">'
            f'<table style="border-collapse:collapse;width:100%;font-family:monospace;">'
            f'<thead><tr>{header}</tr></thead>'
            f'<tbody>{"".join(rows_html)}</tbody></table></div>')

def _section(title, content, colour="#2c3e50"):
    return f"""
    <div style="margin:20px 0;background:#fff;border-radius:8px;
                box-shadow:0 2px 8px rgba(0,0,0,.08);overflow:hidden;">
      <div style="background:{colour};color:#fff;padding:12px 20px;
                  font-size:1.05em;font-weight:700;">{_e(title)}</div>
      <div style="padding:20px;">{content}</div>
    </div>"""

def _stats_grid(stats):
    colours = ["#2980b9","#c0392b","#e67e22","#27ae60","#8e44ad","#16a085","#e74c3c","#f39c12"]
    cards = []
    for i,(k,v) in enumerate(stats.items()):
        c = colours[i % len(colours)]
        cards.append(
            f'<div style="background:{c};color:#fff;border-radius:8px;padding:16px 20px;'
            f'min-width:150px;flex:1;">'
            f'<div style="font-size:1.8em;font-weight:800;">{_e(str(v))}</div>'
            f'<div style="font-size:.78em;opacity:.9;margin-top:4px;">{_e(k)}</div></div>')
    return '<div style="display:flex;flex-wrap:wrap;gap:12px;">' + "".join(cards) + "</div>"

def _charts_row(charts):
    if not charts: return ""
    items = []
    chart_titles = {
        "severity_pie":    "Severity Distribution",
        "top_processes":   "Top Suspicious Processes",
        "timeline":        "Alert Timeline",
        "detection_types": "Detection Types",
        "risk_histogram":  "Risk Score Distribution",
        "mitre_tactics":   "MITRE Tactic Coverage",
    }
    for name, b64 in charts.items():
        title = chart_titles.get(name, name)
        items.append(
            f'<div style="flex:1;min-width:320px;">'
            f'<div style="font-size:.85em;font-weight:600;color:#555;'
            f'margin-bottom:6px;text-align:center;">{_e(title)}</div>'
            f'{chart_img_tag(b64, alt=title)}</div>')
    rows = []
    for i in range(0, len(items), 2):
        chunk = items[i:i+2]
        rows.append(
            '<div style="display:flex;flex-wrap:wrap;gap:16px;margin-bottom:16px;">'
            + "".join(chunk) + "</div>")
    return "".join(rows)

def _patient_zero_card(pz):
    if not pz: return "<p style='color:#888;'>Not identified.</p>"
    sc = SEV_COLOUR.get(pz.get("Severity",""), "#555")
    return f"""
    <div style="display:flex;gap:16px;flex-wrap:wrap;">
      <div style="background:#2c3e50;color:#ecf0f1;border-radius:8px;
                  padding:16px 24px;flex:2;min-width:260px;">
        <div style="font-size:.75em;opacity:.7;margin-bottom:4px;">PATIENT ZERO — INITIAL DROPPER</div>
        <div style="font-size:1.3em;font-weight:800;color:#e74c3c;">{_e(pz.get("Process Name","?"))}</div>
        <div style="font-size:.78em;opacity:.8;">{_e(pz.get("Process",""))}</div>
        <div style="margin-top:10px;font-size:.82em;">
          <b>Parent:</b> {_e(pz.get("Parent Name","?"))}<br>
          <b>First seen:</b> {_e(pz.get("First Seen",""))}<br>
          <b>Raw events:</b> {_e(str(pz.get("Raw Events",0)))}
        </div>
      </div>
      <div style="background:{sc};color:#fff;border-radius:8px;
                  padding:16px 24px;flex:1;min-width:120px;text-align:center;">
        <div style="font-size:.75em;opacity:.8;">RISK SCORE</div>
        <div style="font-size:2.8em;font-weight:900;">{pz.get("Risk Score",0)}</div>
        <div style="font-size:.8em;font-weight:700;">{_e(pz.get("Severity",""))}</div>
      </div>
    </div>
    <div style="margin-top:10px;background:#fdf2f8;border-left:4px solid #c0392b;
                padding:10px 16px;border-radius:4px;font-size:.82em;color:#555;">
      <b>Detection:</b> {_e(pz.get("Detection",""))}<br>
      <b>Reason:</b> {_e(str(pz.get("Reason",""))[:220])}
    </div>"""

def _kill_chain_flow(kill_chain_df):
    if kill_chain_df is None or kill_chain_df.empty:
        return "<p style='color:#888;'>No kill chain data.</p>"
    colours = {"1":"#8e44ad","2":"#e74c3c","3":"#e67e22","4":"#c0392b","5":"#2980b9","6":"#16a085"}
    flow = '<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px;">'
    for stage in kill_chain_df["Stage"].unique():
        num = str(stage).split("–")[0].strip()
        label = str(stage).split("–")[-1].strip() if "–" in str(stage) else str(stage)
        c = colours.get(num, "#555")
        flow += (f'<div style="background:{c};color:#fff;padding:8px 14px;'
                 f'border-radius:20px;font-size:.8em;font-weight:600;">{_e(label)}</div>'
                 f'<div style="color:#ccc;font-size:1.2em;align-self:center;">›</div>')
    flow += "</div>"
    cols = [c for c in ["Stage","MITRE Tactic","Timestamp","Process","Detail","Risk Score","Recommendation"]
            if c in kill_chain_df.columns]
    return flow + _df_table(kill_chain_df[cols])

def generate_html_report(investigation: dict, output_path: str) -> str:
    stats        = investigation.get("stats", {})
    patient_zero = investigation.get("patient_zero", {})
    sev_counts   = investigation.get("severity_counts", {})
    c2_ips       = investigation.get("c2_ips", [])
    persist_iocs = investigation.get("persistence_indicators", [])
    mitre_cov    = investigation.get("mitre_coverage", pd.DataFrame())
    queue_df     = investigation.get("queue_df", pd.DataFrame())
    incidents_df = investigation.get("incidents_df", pd.DataFrame())
    kill_chain_df= investigation.get("kill_chain_df", pd.DataFrame())
    ioc_df       = investigation.get("ioc_df", pd.DataFrame())
    timeline_df  = investigation.get("timeline_df", pd.DataFrame())
    tree_df      = investigation.get("tree_df", pd.DataFrame())
    beacon_df    = investigation.get("beacon_df", pd.DataFrame())
    alerts_df    = investigation.get("alerts_df", pd.DataFrame())

    # Generate charts
    log.info("Generating charts...")
    charts = build_all_charts(alerts_df) if not alerts_df.empty else {}

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    overall_sev  = ("CRITICAL" if sev_counts.get("CRITICAL",0) else
                    "HIGH"     if sev_counts.get("HIGH",0)     else
                    "MEDIUM"   if sev_counts.get("MEDIUM",0)   else "LOW")
    banner_col = SEV_COLOUR.get(overall_sev, "#2c3e50")

    # IOC alert bars
    ioc_bar = ""
    if c2_ips:
        ioc_bar += (f'<div style="background:#fdecea;border:1px solid #e74c3c;'
                    f'border-radius:6px;padding:10px 16px;margin:10px 0;font-size:.83em;">'
                    f'<strong style="color:#c0392b;">⚠ C2 IPs:</strong> '
                    + " &nbsp;|&nbsp; ".join(f'<code>{_e(ip)}</code>' for ip in c2_ips[:8])
                    + "</div>")
    if persist_iocs:
        ioc_bar += (f'<div style="background:#fff8e1;border:1px solid #f39c12;'
                    f'border-radius:6px;padding:10px 16px;margin:10px 0;font-size:.83em;">'
                    f'<strong style="color:#e67e22;">🔑 Persistence keys:</strong> '
                    + " &nbsp;|&nbsp; ".join(f'<code>{_e(k)}</code>' for k in persist_iocs[:4])
                    + "</div>")

    # Queue columns
    qcols = [c for c in ["Alert ID","Timestamp","Risk Score","Severity","Process",
                          "Detection Type","MITRE Technique","Analyst Verdict","Recommendation"]
             if c in (queue_df.columns if not queue_df.empty else [])]

    # Timeline columns
    tcols = [c for c in ["Timeline #","Timestamp","Tactic","Process","Detection Type",
                          "Risk Score","Severity","MITRE Technique"]
             if c in (timeline_df.columns if not timeline_df.empty else [])]

    # Tree columns
    trcols = [c for c in ["Depth","PID","Process Name","Parent Name","Event Count",
                           "Alert Severity","Alert Score","Detection Types"]
              if c in (tree_df.columns if not tree_df.empty else [])]

    html_content = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Anomaly Hunter Pro — Investigation Report</title>
<style>
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;
        background:#f0f2f5;margin:0;padding:0;color:#222;}}
  .container{{max-width:1440px;margin:0 auto;padding:24px;}}
  code{{background:#f4f4f4;padding:1px 5px;border-radius:3px;font-size:.85em;}}
  a{{color:#2980b9;}} details summary{{cursor:pointer;font-weight:600;padding:4px 0;}}
</style>
</head><body>

<div style="background:{banner_col};color:#fff;padding:18px 32px;">
  <div style="max-width:1440px;margin:0 auto;display:flex;
              justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;">
    <div>
      <div style="font-size:1.5em;font-weight:900;">🔍 Anomaly Hunter Pro</div>
      <div style="font-size:.88em;opacity:.85;">Investigation Report &nbsp;·&nbsp; {_e(generated_at)}</div>
    </div>
    <div style="text-align:right;">
      <div style="font-size:.78em;opacity:.8;">Overall Severity</div>
      <div style="font-size:2em;font-weight:900;">{_e(overall_sev)}</div>
    </div>
  </div>
</div>

<div class="container">
  {ioc_bar}

  {_section("Patient Zero — Initial Dropper", _patient_zero_card(patient_zero), "#c0392b")}

  {_section("Investigation Statistics", _stats_grid(stats), "#2c3e50")}

  {_section("Analysis Charts", _charts_row(charts), "#16213e")}

  {_section("Correlated Incidents", _df_table(incidents_df, sev_col="Severity"), "#e67e22")}

  {_section("Kill Chain Reconstruction", _kill_chain_flow(kill_chain_df), "#c0392b")}

  {_section("Investigation Queue — MEDIUM+ Alerts",
            _df_table(queue_df[qcols].head(100) if qcols else queue_df.head(100), sev_col="Severity"),
            "#e74c3c")}

  {_section("MITRE Coverage",
            _df_table(mitre_cov) if not (mitre_cov is None or (isinstance(mitre_cov, pd.DataFrame) and mitre_cov.empty)) else "<p>No MITRE data.</p>",
            "#8e44ad")}

  {_section("Threat Intelligence — IOC Summary",
            _df_table(ioc_df.head(150) if ioc_df is not None and not ioc_df.empty else pd.DataFrame()),
            "#16a085")}

  {_section("Beaconing Analysis",
            _df_table(beacon_df.head(50) if beacon_df is not None and not beacon_df.empty else pd.DataFrame()),
            "#2980b9")}

  {_section("Attack Timeline (MITRE-staged)",
            _df_table(timeline_df[tcols].head(100) if tcols else timeline_df.head(100), sev_col="Severity"),
            "#27ae60")}

  {_section("Process Tree",
            _df_table(tree_df[trcols].head(100) if trcols else tree_df.head(100), sev_col="Alert Severity"),
            "#2c3e50")}

  <div style="text-align:center;color:#aaa;font-size:.78em;padding:24px 0;">
    Anomaly Hunter Pro &nbsp;·&nbsp; {_e(generated_at)} &nbsp;·&nbsp;
    Handle as TLP:AMBER — For analyst use only
  </div>
</div>
</body></html>"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    log.info("HTML report: %s  (charts=%d)", output_path, len(charts))
    return output_path
