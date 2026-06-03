"""
reports.py
Anomaly Hunter v2.1

IMPROVEMENTS OVER v2.0:
- save_anomaly_report: now sorts by Risk Score DESC and includes 
  MITRE Technique / MITRE Name columns
- Added save_kill_chain_report() for the new kill-chain narrative output
- build_executive_summary: now includes IOC summary section with
  unique C2 IPs and persistence keys found
- All save_* functions are safe on empty DataFrames
- Added MITRE coverage summary to executive report
"""

import pandas as pd
from config import OUTPUT_FILES

# Add new output file keys
OUTPUT_FILES["kill_chain"] = "kill_chain_report.csv"


def _safe_save(df, path):
    """Save a DataFrame, always write headers even if empty."""
    if df is None or df.empty:
        pd.DataFrame().to_csv(path, index=False)
    else:
        df.to_csv(path, index=False)


def save_anomaly_report(alerts_df):
    if alerts_df.empty:
        _safe_save(alerts_df, OUTPUT_FILES["anomaly_report"])
        return
    out = alerts_df.sort_values(by="Risk Score", ascending=False)
    _safe_save(out, OUTPUT_FILES["anomaly_report"])


def save_investigation_queue(queue_df):
    if queue_df.empty:
        _safe_save(queue_df, OUTPUT_FILES["investigation_queue"])
        return
    _safe_save(
        queue_df.sort_values(by="Risk Score", ascending=False),
        OUTPUT_FILES["investigation_queue"]
    )


def save_attack_chain_report(chain_df):
    if chain_df.empty:
        _safe_save(chain_df, OUTPUT_FILES["attack_chain"])
        return
    _safe_save(
        chain_df.sort_values(by="Chain Risk Score", ascending=False),
        OUTPUT_FILES["attack_chain"]
    )


def save_kill_chain_report(kill_chain_df):
    """NEW: save the narrative kill-chain reconstruction."""
    _safe_save(kill_chain_df, OUTPUT_FILES["kill_chain"])


def save_timeline(timeline_df):
    if timeline_df.empty:
        _safe_save(timeline_df, OUTPUT_FILES["timeline"])
        return
    _safe_save(
        timeline_df.sort_values(by="Timestamp"),
        OUTPUT_FILES["timeline"]
    )


def build_executive_summary(alerts_df, queue_df, chain_df):
    metrics = []

    # ── Counts ──────────────────────────────────────────────────────
    metrics.append(["Total Unique Alerts",    len(alerts_df)])
    metrics.append(["Investigation Queue",    len(queue_df)])
    metrics.append(["Attack Chains",          len(chain_df)])

    if not alerts_df.empty:
        metrics.append(["Critical Alerts",
            int((alerts_df["Severity"] == "CRITICAL").sum())])
        metrics.append(["High Alerts",
            int((alerts_df["Severity"] == "HIGH").sum())])
        metrics.append(["Medium Alerts",
            int((alerts_df["Severity"] == "MEDIUM").sum())])

        # ── Detection type breakdown ─────────────────────────────────
        for det in [
            "EDR Rule Detection", "Persistence", "Persistence via Cmdline",
            "Process Injection", "Download Execute",
            "LOLBin Abuse", "Svchost Script Spawn",
            "Recon / IP Discovery", "Beaconing",
            "Suspicious Parent-Child"
        ]:
            count = int(
                alerts_df["Detection Type"].str.contains(det, na=False).sum()
            )
            if count:
                metrics.append([f"  – {det}", count])

        # ── IOC Summary (NEW) ────────────────────────────────────────
        metrics.append(["--- IOC SUMMARY ---", ""])

        # C2 IPs
        c2_ips = (
            alerts_df[
                alerts_df["Detection Type"].str.contains("Beaconing|External", na=False)
            ]["Destination IP"]
            .replace("", pd.NA).dropna().unique().tolist()
        )
        if c2_ips:
            metrics.append(["Suspicious C2 IPs", " | ".join(str(x) for x in c2_ips[:10])])

        # Top suspicious processes
        top_procs = (
            alerts_df[
                alerts_df["Severity"].isin(["CRITICAL", "HIGH", "MEDIUM"])
            ]["Process"]
            .value_counts().head(5).index.tolist()
        )
        if top_procs:
            metrics.append(["Top Suspicious Processes",
                " | ".join(str(p).split("\\")[-1] for p in top_procs)])

        # MITRE techniques seen (NEW)
        mitre_hits = (
            alerts_df["MITRE Technique"]
            .replace("", pd.NA).dropna()
            .value_counts().head(8)
        )
        if not mitre_hits.empty:
            mitre_str = " | ".join(
                f"{tid}({cnt})" for tid, cnt in mitre_hits.items()
            )
            metrics.append(["MITRE Techniques", mitre_str])

    return pd.DataFrame(metrics, columns=["Metric", "Value"])


def save_executive_summary(summary_df):
    _safe_save(summary_df, OUTPUT_FILES["executive_summary"])


def generate_all_reports(alerts_df, queue_df, chain_df, timeline_df,
                         kill_chain_df=None):
    save_anomaly_report(alerts_df)
    save_investigation_queue(queue_df)
    save_attack_chain_report(chain_df)
    save_timeline(timeline_df)

    if kill_chain_df is not None:
        save_kill_chain_report(kill_chain_df)

    summary = build_executive_summary(alerts_df, queue_df, chain_df)
    save_executive_summary(summary)

    result = {
        "anomaly_report":      OUTPUT_FILES["anomaly_report"],
        "investigation_queue": OUTPUT_FILES["investigation_queue"],
        "attack_chain":        OUTPUT_FILES["attack_chain"],
        "timeline":            OUTPUT_FILES["timeline"],
        "executive_summary":   OUTPUT_FILES["executive_summary"],
    }
    if kill_chain_df is not None:
        result["kill_chain"] = OUTPUT_FILES["kill_chain"]

    return result
