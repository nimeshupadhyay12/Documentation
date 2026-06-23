"""
investigation/investigation_engine.py  -  Anomaly Hunter v3
=============================================================
Produces the complete investigation narrative:
  - Patient Zero identification
  - Attack summary (what happened, when, how)
  - Affected processes list
  - IOC summary
  - MITRE tactic coverage
  - Analyst recommendations per stage
"""

import logging
import pandas as pd

from config.config import MITRE_TACTICS, KNOWN_GOOD_PROCESSES

log = logging.getLogger("AnomalyHunter.InvestigationEngine")


def _norm(value: str) -> str:
    return str(value).lower().split("\\")[-1].strip()


# ── Patient Zero ──────────────────────────────────────────────────────────────

def identify_patient_zero(alerts_df: pd.DataFrame, raw_df: pd.DataFrame) -> dict:
    """
    Identify the earliest suspicious process — the likely initial dropper.
    Uses three signals:
      1. EDR Rule Detection events (explicit rule hit on process start)
      2. Malware Staging events (execution from user-writable path)
      3. Earliest timestamp among CRITICAL/HIGH alerts
    """
    if alerts_df.empty:
        return {}

    candidate = None

    # Signal 1: EDR hit on process start
    edr = alerts_df[
        alerts_df["Detection Type"].str.contains("EDR Rule", na=False)
    ].sort_values("Timestamp")
    if not edr.empty:
        candidate = edr.iloc[0]

    # Signal 2: Malware staging (fallback)
    if candidate is None:
        staging = alerts_df[
            alerts_df["Detection Type"].str.contains("Malware Staging", na=False)
        ].sort_values("Timestamp")
        if not staging.empty:
            candidate = staging.iloc[0]

    # Signal 3: Earliest critical/high alert (last resort)
    if candidate is None:
        high = alerts_df[
            alerts_df["Severity"].isin(["CRITICAL", "HIGH"])
        ].sort_values("Timestamp")
        if not high.empty:
            candidate = high.iloc[0]

    if candidate is None:
        return {}

    proc      = str(candidate.get("Process", ""))
    proc_name = proc.split("\\")[-1]
    parent    = str(candidate.get("Parent Process", ""))
    ts        = candidate.get("Timestamp", "")

    # Count how many events this process generated in the raw log
    raw_events = 0
    if not raw_df.empty and "_process" in raw_df.columns:
        raw_events = int(
            (raw_df["_process"].str.lower() == proc.lower()).sum()
        )

    return {
        "Process":       proc,
        "Process Name":  proc_name,
        "Parent":        parent,
        "Parent Name":   parent.split("\\")[-1],
        "First Seen":    ts,
        "Raw Events":    raw_events,
        "Risk Score":    int(candidate.get("Risk Score", 0)),
        "Severity":      candidate.get("Severity", ""),
        "Detection":     candidate.get("Detection Type", ""),
        "Reason":        candidate.get("Investigation Reason", ""),
    }


# ── MITRE coverage ────────────────────────────────────────────────────────────

def build_mitre_coverage(alerts_df: pd.DataFrame, timeline_df: pd.DataFrame) -> pd.DataFrame:
    """
    Returns a DataFrame showing which MITRE tactics were observed,
    with alert counts and top technique per tactic.
    """
    coverage_rows = []

    if not timeline_df.empty and "Tactic ID" in timeline_df.columns:
        for tactic_id, grp in timeline_df.groupby("Tactic ID"):
            tactic_name = MITRE_TACTICS.get(tactic_id, "Unknown")
            techniques  = grp["MITRE Technique"].replace("", pd.NA).dropna().value_counts()
            top_tech    = techniques.index[0] if not techniques.empty else ""
            top_count   = int(techniques.iloc[0]) if not techniques.empty else 0
            coverage_rows.append({
                "Tactic ID":         tactic_id,
                "Tactic Name":       tactic_name,
                "Alert Count":       len(grp),
                "Top Technique":     top_tech,
                "Top Technique Count": top_count,
                "Detection Types":   " | ".join(grp["Detection Type"].unique()[:4]),
            })

    elif not alerts_df.empty and "MITRE Technique" in alerts_df.columns:
        for tid, grp in alerts_df.groupby("MITRE Technique"):
            if not tid:
                continue
            coverage_rows.append({
                "Tactic ID":         tid,
                "Tactic Name":       tid,
                "Alert Count":       len(grp),
                "Top Technique":     tid,
                "Top Technique Count": len(grp),
                "Detection Types":   "",
            })

    if not coverage_rows:
        return pd.DataFrame()

    df = pd.DataFrame(coverage_rows)
    return df.sort_values("Alert Count", ascending=False).reset_index(drop=True)


# ── Affected assets ───────────────────────────────────────────────────────────

def build_affected_processes(alerts_df: pd.DataFrame) -> pd.DataFrame:
    """
    One row per unique suspicious process with aggregated metrics.
    """
    if alerts_df.empty:
        return pd.DataFrame()

    working = alerts_df[alerts_df["Severity"] != "FP-SUPPRESSED"]
    if working.empty:
        return pd.DataFrame()

    rows = []
    for proc, grp in working.groupby("Process"):
        pname = str(proc).split("\\")[-1]
        if _norm(proc) in KNOWN_GOOD_PROCESSES and grp["Risk Score"].max() < 30:
            continue
        rows.append({
            "Process Name":     pname,
            "Full Path":        proc,
            "Max Risk Score":   int(grp["Risk Score"].max()),
            "Alert Count":      len(grp),
            "Severity":         grp["Severity"].iloc[0],
            "Detection Types":  " | ".join(sorted(set(
                t.strip()
                for dt in grp["Detection Type"]
                for t in dt.split("|")
            ))[:5]),
            "MITRE Techniques": " | ".join(
                grp["MITRE Technique"].replace("", pd.NA).dropna().unique()[:4]
            ),
            "C2 IPs": " | ".join(
                grp["Destination IP"].replace("", pd.NA).dropna().unique()[:3]
            ),
        })

    if not rows:
        return pd.DataFrame()

    return pd.DataFrame(rows).sort_values("Max Risk Score", ascending=False).reset_index(drop=True)


# ── Full investigation report ─────────────────────────────────────────────────

def build_investigation_report(
    raw_df:        pd.DataFrame,
    alerts_df:     pd.DataFrame,
    queue_df:      pd.DataFrame,
    incidents_df:  pd.DataFrame,
    kill_chain_df: pd.DataFrame,
    timeline_df:   pd.DataFrame,
    ioc_df:        pd.DataFrame,
    tree_df:       pd.DataFrame,
    beacon_df:     pd.DataFrame,
) -> dict:
    """
    Master investigation report dictionary.
    Consumed by html_report.py and executive_report.py.
    """

    # ── Patient Zero ─────────────────────────────────────────────────
    patient_zero = identify_patient_zero(alerts_df, raw_df)

    # ── Severity breakdown ───────────────────────────────────────────
    sev_counts = {}
    if not alerts_df.empty:
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "FP-SUPPRESSED"]:
            count = int((alerts_df["Severity"] == sev).sum())
            if count:
                sev_counts[sev] = count

    # ── Detection type breakdown ─────────────────────────────────────
    det_counts = {}
    if not alerts_df.empty:
        for dt in alerts_df["Detection Type"]:
            for part in str(dt).split("|"):
                part = part.strip()
                if part:
                    det_counts[part] = det_counts.get(part, 0) + 1

    # ── Top IOCs ─────────────────────────────────────────────────────
    top_iocs = []
    if not ioc_df.empty:
        malicious = ioc_df[ioc_df.get("TI Verdict", pd.Series()) == "Malicious"] \
            if "TI Verdict" in ioc_df.columns else ioc_df
        top_iocs = malicious.head(10).to_dict("records") if not malicious.empty \
            else ioc_df.head(10).to_dict("records")

    # ── C2 IPs ───────────────────────────────────────────────────────
    c2_ips = []
    if not alerts_df.empty:
        c2_mask = alerts_df["Detection Type"].str.contains("Beaconing|External", na=False)
        c2_ips  = (
            alerts_df[c2_mask]["Destination IP"]
            .replace("", pd.NA).dropna().unique().tolist()
        )

    # ── Persistence indicators ───────────────────────────────────────
    persistence_indicators = []
    if not ioc_df.empty and "IOC Type" in ioc_df.columns:
        reg_iocs = ioc_df[ioc_df["IOC Type"] == "Registry Key"]["IOC Value"].tolist()
        persistence_indicators.extend(reg_iocs)

    # ── Beaconing summary ─────────────────────────────────────────────
    beacon_summary = []
    if beacon_df is not None and not beacon_df.empty:
        beacon_summary = beacon_df[[
            "Process", "Destination IP", "Event Count",
            "Mean Interval(s)", "CV", "Beacon Score"
        ]].head(5).to_dict("records")

    # ── MITRE coverage ────────────────────────────────────────────────
    mitre_coverage = build_mitre_coverage(alerts_df, timeline_df)

    # ── Affected processes ────────────────────────────────────────────
    affected_procs = build_affected_processes(alerts_df)

    # ── Stats ─────────────────────────────────────────────────────────
    stats = {
        "Total Events Analysed":  len(raw_df),
        "Unique Alerts":          len(alerts_df),
        "Investigation Queue":    len(queue_df),
        "Correlated Incidents":   len(incidents_df) if incidents_df is not None else 0,
        "Kill Chain Stages":      len(kill_chain_df) if kill_chain_df is not None else 0,
        "IOCs Extracted":         len(ioc_df) if ioc_df is not None else 0,
        "Beaconing Pairs":        len(beacon_df) if beacon_df is not None else 0,
        "Process Tree Nodes":     len(tree_df) if tree_df is not None else 0,
    }

    return {
        "stats":                   stats,
        "patient_zero":            patient_zero,
        "severity_counts":         sev_counts,
        "detection_counts":        det_counts,
        "c2_ips":                  c2_ips,
        "persistence_indicators":  persistence_indicators,
        "top_iocs":                top_iocs,
        "beacon_summary":          beacon_summary,
        "mitre_coverage":          mitre_coverage,
        "affected_processes":      affected_procs,
        "alerts_df":               alerts_df,
        "queue_df":                queue_df,
        "incidents_df":            incidents_df,
        "kill_chain_df":           kill_chain_df,
        "timeline_df":             timeline_df,
        "ioc_df":                  ioc_df,
        "tree_df":                 tree_df,
        "beacon_df":               beacon_df,
    }
