"""
reporting/charts.py  -  Anomaly Hunter Pro
============================================
Generates analysis charts as base64-encoded PNG strings
for embedding directly in the HTML report.

No web server or external files needed — charts are
self-contained inside the HTML file.

Charts produced:
  1. Alert severity distribution (pie)
  2. Top 10 suspicious processes (horizontal bar)
  3. Events per time window (timeline bar)
  4. Detection type breakdown (horizontal bar)
  5. Risk score distribution (histogram)
  6. MITRE tactic coverage (horizontal bar)
"""

import io
import base64
import logging
from collections import Counter

import pandas as pd
import numpy as np

log = logging.getLogger("AnomalyHunter.Charts")

try:
    import matplotlib
    matplotlib.use("Agg")          # non-interactive — no display needed
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    MATPLOTLIB_OK = True
except ImportError:
    MATPLOTLIB_OK = False
    log.warning("matplotlib not installed — charts disabled")

# ── Theme ─────────────────────────────────────────────────────────────────────
BG_DARK   = "#1a1a2e"
BG_PANEL  = "#16213e"
TEXT_COL  = "#ecf0f1"
GRID_COL  = "#2c3e50"

SEV_COLOURS = {
    "CRITICAL":     "#c0392b",
    "HIGH":         "#e67e22",
    "MEDIUM":       "#f1c40f",
    "LOW":          "#27ae60",
    "FP-SUPPRESSED":"#7f8c8d",
    "INFO":         "#2980b9",
}

PALETTE = ["#e74c3c","#e67e22","#f1c40f","#27ae60","#2980b9",
           "#8e44ad","#16a085","#d35400","#2ecc71","#3498db"]


def _fig_to_b64(fig) -> str:
    """Convert matplotlib figure to base64 PNG string."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=110, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    buf.seek(0)
    encoded = base64.b64encode(buf.read()).decode("utf-8")
    plt.close(fig)
    return encoded


def _apply_dark_theme(ax, title: str = ""):
    ax.set_facecolor(BG_PANEL)
    ax.tick_params(colors=TEXT_COL, labelsize=9)
    ax.xaxis.label.set_color(TEXT_COL)
    ax.yaxis.label.set_color(TEXT_COL)
    if title:
        ax.set_title(title, color=TEXT_COL, fontsize=11, fontweight="bold", pad=10)
    for spine in ax.spines.values():
        spine.set_edgecolor(GRID_COL)
    ax.grid(color=GRID_COL, linestyle="--", linewidth=0.5, alpha=0.5)


def chart_severity_pie(alerts_df: pd.DataFrame) -> str:
    """Pie chart of alert severity distribution."""
    if not MATPLOTLIB_OK or alerts_df.empty:
        return ""
    sev_counts = alerts_df["Severity"].value_counts()
    labels  = [s for s in ["CRITICAL","HIGH","MEDIUM","LOW","FP-SUPPRESSED","INFO"]
               if s in sev_counts.index]
    sizes   = [sev_counts.get(s, 0) for s in labels]
    colours = [SEV_COLOURS.get(s, "#555") for s in labels]
    if not any(s > 0 for s in sizes):
        return ""

    fig, ax = plt.subplots(figsize=(5, 4), facecolor=BG_DARK)
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colours,
        autopct=lambda p: f"{p:.0f}%" if p > 3 else "",
        startangle=140, pctdistance=0.8,
        textprops={"color": TEXT_COL, "fontsize": 8},
    )
    for at in autotexts:
        at.set_color("#ffffff")
        at.set_fontsize(8)
    ax.set_facecolor(BG_DARK)
    ax.set_title("Alert Severity Distribution", color=TEXT_COL,
                 fontsize=11, fontweight="bold")
    fig.patch.set_facecolor(BG_DARK)
    return _fig_to_b64(fig)


def chart_top_processes(alerts_df: pd.DataFrame, top_n: int = 10) -> str:
    """Horizontal bar chart of top suspicious processes by alert count."""
    if not MATPLOTLIB_OK or alerts_df.empty:
        return ""

    working = alerts_df[alerts_df["Severity"] != "FP-SUPPRESSED"]
    if working.empty:
        return ""

    proc_counts = (
        working["Process"]
        .apply(lambda p: str(p).replace("/","\\").split("\\")[-1].strip())
        .value_counts()
        .head(top_n)
    )
    if proc_counts.empty:
        return ""

    # Colour bars by max severity of that process
    proc_sev = {}
    for proc in proc_counts.index:
        pname = proc.lower()
        match = working[working["Process"].str.lower().str.endswith(pname)]
        top_s = match["Severity"].map(
            {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}
        ).max() if not match.empty else 1
        proc_sev[proc] = top_s

    colours = [
        SEV_COLOURS.get(
            {4:"CRITICAL",3:"HIGH",2:"MEDIUM",1:"LOW"}.get(proc_sev.get(p,1),"LOW"),
            "#27ae60"
        )
        for p in proc_counts.index
    ]

    fig, ax = plt.subplots(figsize=(7, max(3, top_n * 0.4 + 0.8)),
                           facecolor=BG_DARK)
    bars = ax.barh(proc_counts.index[::-1], proc_counts.values[::-1],
                   color=colours[::-1], edgecolor=BG_DARK, height=0.6)
    _apply_dark_theme(ax, "Top Suspicious Processes")
    ax.set_xlabel("Alert Count", color=TEXT_COL)
    for bar, val in zip(bars, proc_counts.values[::-1]):
        ax.text(val + 0.3, bar.get_y() + bar.get_height() / 2,
                str(val), va="center", color=TEXT_COL, fontsize=8)
    fig.tight_layout()
    return _fig_to_b64(fig)


def chart_events_timeline(alerts_df: pd.DataFrame) -> str:
    """Bar chart of alert count over time (by timestamp bucket)."""
    if not MATPLOTLIB_OK or alerts_df.empty:
        return ""
    if "Timestamp" not in alerts_df.columns:
        return ""

    import re
    def parse_ts(s):
        try:
            return pd.to_datetime(re.sub(r"\s*@\s*", " ", str(s)), errors="coerce")
        except Exception:
            return pd.NaT

    ts = alerts_df["Timestamp"].apply(parse_ts).dropna()
    if ts.empty:
        return ""

    ts_df = pd.DataFrame({"ts": ts, "sev": alerts_df.loc[ts.index, "Severity"]})
    ts_df = ts_df.set_index("ts").sort_index()

    # Auto-select bucket size based on time range
    duration = (ts_df.index.max() - ts_df.index.min()).total_seconds()
    if duration < 600:
        freq = "1min"
    elif duration < 7200:
        freq = "5min"
    elif duration < 86400:
        freq = "1h"
    else:
        freq = "1D"

    buckets = ts_df.resample(freq).size()
    if buckets.empty:
        return ""

    fig, ax = plt.subplots(figsize=(8, 3.5), facecolor=BG_DARK)
    ax.bar(range(len(buckets)), buckets.values, color="#2980b9",
           edgecolor=BG_DARK, width=0.8)
    _apply_dark_theme(ax, f"Alert Timeline (bucket={freq})")
    ax.set_xlabel("Time Bucket", color=TEXT_COL)
    ax.set_ylabel("Alert Count", color=TEXT_COL)

    # Label x-axis with timestamps (sparse)
    step = max(1, len(buckets) // 8)
    ax.set_xticks(range(0, len(buckets), step))
    ax.set_xticklabels(
        [str(t)[:16] for t in buckets.index[::step]],
        rotation=30, ha="right", fontsize=7, color=TEXT_COL,
    )
    fig.tight_layout()
    return _fig_to_b64(fig)


def chart_detection_types(alerts_df: pd.DataFrame, top_n: int = 12) -> str:
    """Horizontal bar of detection type counts."""
    if not MATPLOTLIB_OK or alerts_df.empty:
        return ""

    # Expand combined detection types
    all_types = []
    for dt in alerts_df["Detection Type"].dropna():
        for t in str(dt).split("|"):
            t = t.strip()
            if t:
                all_types.append(t)

    counts = Counter(all_types).most_common(top_n)
    if not counts:
        return ""

    labels = [c[0][:40] for c in counts]
    values = [c[1] for c in counts]
    colours = PALETTE[:len(labels)]

    fig, ax = plt.subplots(figsize=(7, max(3, len(labels) * 0.38 + 0.8)),
                           facecolor=BG_DARK)
    ax.barh(labels[::-1], values[::-1], color=colours[::-1],
            edgecolor=BG_DARK, height=0.6)
    _apply_dark_theme(ax, "Detection Type Breakdown")
    ax.set_xlabel("Count", color=TEXT_COL)
    for i, val in enumerate(values[::-1]):
        ax.text(val + 0.3, i, str(val), va="center", color=TEXT_COL, fontsize=8)
    fig.tight_layout()
    return _fig_to_b64(fig)


def chart_risk_histogram(alerts_df: pd.DataFrame) -> str:
    """Histogram of risk score distribution."""
    if not MATPLOTLIB_OK or alerts_df.empty:
        return ""
    if "Risk Score" not in alerts_df.columns:
        return ""

    scores = pd.to_numeric(alerts_df["Risk Score"], errors="coerce").dropna()
    if scores.empty:
        return ""

    fig, ax = plt.subplots(figsize=(6, 3.5), facecolor=BG_DARK)
    n, bins, patches = ax.hist(scores, bins=20, color="#2980b9",
                                edgecolor=BG_DARK, alpha=0.85)
    # Colour by severity band
    for patch, left in zip(patches, bins[:-1]):
        if left >= 80:   patch.set_facecolor(SEV_COLOURS["CRITICAL"])
        elif left >= 60: patch.set_facecolor(SEV_COLOURS["HIGH"])
        elif left >= 40: patch.set_facecolor(SEV_COLOURS["MEDIUM"])
        elif left >= 20: patch.set_facecolor(SEV_COLOURS["LOW"])

    _apply_dark_theme(ax, "Risk Score Distribution")
    ax.set_xlabel("Risk Score", color=TEXT_COL)
    ax.set_ylabel("Count", color=TEXT_COL)

    # Severity band labels
    for x, label, col in [(10,"LOW","#27ae60"),(30,"MEDIUM","#f1c40f"),
                           (50,"HIGH","#e67e22"),(85,"CRITICAL","#c0392b")]:
        ax.axvline(x=x, color=col, linestyle="--", alpha=0.4, linewidth=1)

    legend = [mpatches.Patch(color=SEV_COLOURS[s], label=s)
              for s in ["CRITICAL","HIGH","MEDIUM","LOW"]]
    ax.legend(handles=legend, loc="upper left", fontsize=7,
              facecolor=BG_PANEL, labelcolor=TEXT_COL)
    fig.tight_layout()
    return _fig_to_b64(fig)


def chart_mitre_tactics(alerts_df: pd.DataFrame) -> str:
    """Horizontal bar of MITRE tactic coverage."""
    if not MATPLOTLIB_OK or alerts_df.empty:
        return ""

    from ah_config.config import MITRE_TACTICS

    DETECTION_TO_TACTIC = {
        "Malware Staging": "TA0001", "EDR Rule Detection": "TA0001",
        "Download Execute": "TA0002", "PowerShell Payload": "TA0002",
        "LOLBin Abuse": "TA0002", "Rare Process": "TA0002",
        "Encoded Payload": "TA0005", "Defense Evasion": "TA0005",
        "Persistence": "TA0003", "Persistence via Cmdline": "TA0003",
        "Recon / IP Discovery": "TA0007", "DNS Anomaly": "TA0007",
        "External Communication": "TA0011", "Beaconing": "TA0011",
        "Network Outlier": "TA0011", "Process Injection": "TA0004",
        "Brute Force / Auth Failure": "TA0006",
        "ML Anomaly (Isolation Forest)": "TA0002",
        "UEBA: After-Hours Activity": "TA0003",
        "ML: DGA Domain Detected": "TA0011",
    }

    tactic_counts = Counter()
    for dt in alerts_df["Detection Type"].dropna():
        for t in str(dt).split("|"):
            t = t.strip()
            tac = DETECTION_TO_TACTIC.get(t, "")
            if tac:
                tactic_counts[tac] += 1

    if not tactic_counts:
        return ""

    ordered = sorted(tactic_counts.items(), key=lambda x: -x[1])
    labels  = [f"{tid}\n{MITRE_TACTICS.get(tid, tid)[:15]}" for tid, _ in ordered]
    values  = [v for _, v in ordered]
    colours = PALETTE[:len(labels)]

    fig, ax = plt.subplots(figsize=(7, max(3, len(labels) * 0.45 + 0.8)),
                           facecolor=BG_DARK)
    ax.barh(labels[::-1], values[::-1], color=colours[::-1],
            edgecolor=BG_DARK, height=0.6)
    _apply_dark_theme(ax, "MITRE ATT&CK Tactic Coverage")
    ax.set_xlabel("Alert Count", color=TEXT_COL)
    for i, val in enumerate(values[::-1]):
        ax.text(val + 0.2, i, str(val), va="center", color=TEXT_COL, fontsize=8)
    fig.tight_layout()
    return _fig_to_b64(fig)


# ── Master chart builder ──────────────────────────────────────────────────────

def build_all_charts(alerts_df: pd.DataFrame) -> dict:
    """
    Generate all charts and return dict of {name: base64_png_string}.
    Returns empty dict if matplotlib not available.
    """
    if not MATPLOTLIB_OK:
        log.warning("matplotlib not available — skipping chart generation")
        return {}

    charts = {}
    chart_fns = [
        ("severity_pie",     chart_severity_pie),
        ("top_processes",    chart_top_processes),
        ("timeline",         chart_events_timeline),
        ("detection_types",  chart_detection_types),
        ("risk_histogram",   chart_risk_histogram),
        ("mitre_tactics",    chart_mitre_tactics),
    ]

    for name, fn in chart_fns:
        try:
            b64 = fn(alerts_df)
            if b64:
                charts[name] = b64
                log.debug("Chart generated: %s", name)
        except Exception as e:
            log.warning("Chart '%s' failed: %s", name, e)

    log.info("Charts generated: %d/%d", len(charts), len(chart_fns))
    return charts


def chart_img_tag(b64: str, alt: str = "chart", width: str = "100%") -> str:
    """Return an HTML <img> tag with the base64-encoded chart."""
    if not b64:
        return ""
    return (
        f'<img src="data:image/png;base64,{b64}" '
        f'alt="{alt}" style="width:{width};border-radius:6px;" />'
    )
