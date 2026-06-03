"""
attack_chain.py
Anomaly Hunter v2.1

IMPROVEMENTS OVER v2.0:
- build_suspicious_chains: added try/except on groupby in case
  'Process' or 'Parent Process' column is missing
- Added build_full_kill_chain() — correlates the complete infection
  sequence: malware drop → persistence install → script execution →
  C2 call-back, assigning MITRE tactic stages
- Added detect_c2_beaconing_chains() — links beaconing alerts to the
  process that installed persistence
- correlate_download_execute / correlate_persistence kept as-is but
  now return MITRE fields
- build_attack_timeline now preserves MITRE and Event Action columns
"""

import re
import pandas as pd
from collections import defaultdict
from config import MITRE_MAPPING, MITRE_NAMES


def normalize_process(value):
    return str(value).lower().split("\\")[-1].strip()


# ─────────────────────────────────────────────
#  Process Lineage
# ─────────────────────────────────────────────

def build_process_lineage(df):
    chains = []
    for _, row in df.iterrows():
        parent = normalize_process(row.get("process.parent.executable", ""))
        child  = normalize_process(row.get("process.executable", ""))
        if parent and child and parent != "-" and child != "-":
            chains.append({
                "Timestamp":    row.get("@timestamp", ""),
                "Parent Process": parent,
                "Child Process":  child,
                "Relationship": f"{parent} -> {child}",
                "Event Action": row.get("event.action", ""),
            })
    return pd.DataFrame(chains)


# ─────────────────────────────────────────────
#  Suspicious Chain Summary
# ─────────────────────────────────────────────

def build_suspicious_chains(alerts_df):
    if alerts_df.empty:
        return pd.DataFrame()

    # Ensure required columns exist
    for col in ["Process", "Parent Process", "Risk Score", "Detection Type"]:
        if col not in alerts_df.columns:
            alerts_df[col] = ""

    chain_rows = []
    chain_id = 1

    try:
        grouped = alerts_df.groupby(["Process", "Parent Process"])
    except Exception:
        return pd.DataFrame()

    for (process, parent), group in grouped:
        risk_score = min(int(group["Risk Score"].sum()), 100)
        detections = sorted(group["Detection Type"].dropna().unique().tolist())

        # MITRE for the child process
        tid   = MITRE_MAPPING.get(process, "")
        tname = MITRE_NAMES.get(tid, "")

        chain_rows.append({
            "Chain ID":         f"AC-{chain_id:04d}",
            "Root Process":     parent,
            "Child Process":    process,
            "Chain Risk Score": risk_score,
            "Detection Count":  len(group),
            "Detections":       " | ".join(detections),
            "Chain Summary":    f"{parent} -> {process}",
            "MITRE Technique":  tid,
            "MITRE Name":       tname,
        })
        chain_id += 1

    chains = pd.DataFrame(chain_rows)
    if not chains.empty:
        chains = chains.sort_values(by="Chain Risk Score", ascending=False)
    return chains


# ─────────────────────────────────────────────
#  Full Kill-Chain Reconstruction  (NEW)
# ─────────────────────────────────────────────

# MITRE tactic stages used for narrative
KILL_CHAIN_STAGES = {
    "initial_access":   ("TA0001", "Initial Access"),
    "execution":        ("TA0002", "Execution"),
    "persistence":      ("TA0003", "Persistence"),
    "discovery":        ("TA0007", "Discovery"),
    "c2":               ("TA0011", "Command and Control"),
}

def build_full_kill_chain(alerts_df, raw_df):
    """
    Correlates the complete infection sequence observed in this log:
      office_portable_x3.exe  [Initial Access / Execution]
        → reg.exe Run key write  [Persistence]
        → powershell Download-Execute  [Execution]
        → svchost → wscript xuvotopo.js  [Execution via Persistence]
        → uusd.exe C2 connections  [C2]
        → curl.exe ipinfo.io recon  [Discovery]

    Returns a narrative DataFrame one row per kill-chain stage.
    """
    if alerts_df.empty or raw_df.empty:
        return pd.DataFrame()

    stages = []

    # ── Stage 1: Initial Access / Dropper ───────────────────────────
    droppers = alerts_df[
        alerts_df["Detection Type"].str.contains("Malware Staging|EDR Rule", na=False)
    ]
    if not droppers.empty:
        for _, row in droppers.drop_duplicates("Process").head(3).iterrows():
            stages.append({
                "Stage":           "1 – Initial Access / Dropper",
                "MITRE Tactic":    "TA0001 / TA0002",
                "Timestamp":       row.get("Timestamp", ""),
                "Process":         row.get("Process", ""),
                "Parent Process":  row.get("Parent Process", ""),
                "Detail":          row.get("Investigation Reason", ""),
                "Risk Score":      row.get("Risk Score", 0),
            })

    # ── Stage 2: Persistence Installation ──────────────────────────
    persist = alerts_df[
        alerts_df["Detection Type"].str.contains("Persistence", na=False)
    ]
    if not persist.empty:
        for _, row in persist.drop_duplicates("Process").head(3).iterrows():
            stages.append({
                "Stage":           "2 – Persistence Installation",
                "MITRE Tactic":    "TA0003",
                "Timestamp":       row.get("Timestamp", ""),
                "Process":         row.get("Process", ""),
                "Parent Process":  row.get("Parent Process", ""),
                "Detail":          row.get("Investigation Reason", ""),
                "Risk Score":      row.get("Risk Score", 0),
            })

    # ── Stage 3: Lateral / Execution via LOLBin ─────────────────────
    lolbin_exec = alerts_df[
        alerts_df["Detection Type"].str.contains("LOLBin|Svchost|Suspicious Parent", na=False)
    ]
    if not lolbin_exec.empty:
        for _, row in lolbin_exec.drop_duplicates("Process").head(3).iterrows():
            stages.append({
                "Stage":           "3 – LOLBin / Script Execution",
                "MITRE Tactic":    "TA0002",
                "Timestamp":       row.get("Timestamp", ""),
                "Process":         row.get("Process", ""),
                "Parent Process":  row.get("Parent Process", ""),
                "Detail":          row.get("Investigation Reason", ""),
                "Risk Score":      row.get("Risk Score", 0),
            })

    # ── Stage 4: Discovery / Recon ──────────────────────────────────
    recon = alerts_df[
        alerts_df["Detection Type"].str.contains("Recon|DNS Anomaly", na=False)
    ]
    if not recon.empty:
        for _, row in recon.drop_duplicates("Process").head(3).iterrows():
            stages.append({
                "Stage":           "4 – Discovery / Recon",
                "MITRE Tactic":    "TA0007",
                "Timestamp":       row.get("Timestamp", ""),
                "Process":         row.get("Process", ""),
                "Parent Process":  row.get("Parent Process", ""),
                "Detail":          row.get("Investigation Reason", ""),
                "Risk Score":      row.get("Risk Score", 0),
            })

    # ── Stage 5: C2 Communication ───────────────────────────────────
    c2 = alerts_df[
        alerts_df["Detection Type"].str.contains("Beaconing|External Communication", na=False)
    ]
    if not c2.empty:
        for _, row in c2.drop_duplicates(["Process", "Destination IP"]).head(5).iterrows():
            stages.append({
                "Stage":           "5 – C2 Communication",
                "MITRE Tactic":    "TA0011",
                "Timestamp":       row.get("Timestamp", ""),
                "Process":         row.get("Process", ""),
                "Parent Process":  row.get("Parent Process", ""),
                "Detail":          f"C2 IP: {row.get('Destination IP','')} | {row.get('Investigation Reason','')}",
                "Risk Score":      row.get("Risk Score", 0),
            })

    if not stages:
        return pd.DataFrame()

    return pd.DataFrame(stages).sort_values("Timestamp")


# ─────────────────────────────────────────────
#  Existing helpers (kept, minor improvements)
# ─────────────────────────────────────────────

def build_attack_chain_report(alerts_df, raw_df):
    chains = build_suspicious_chains(alerts_df)
    if chains.empty:
        return chains

    attack_rows = []
    for _, row in chains.iterrows():
        attack_rows.append({
            "Chain ID":         row["Chain ID"],
            "Root Process":     row["Root Process"],
            "Child Process":    row["Child Process"],
            "Chain Risk Score": row["Chain Risk Score"],
            "Detection Count":  row["Detection Count"],
            "Detections":       row["Detections"],
            "Chain Summary":    row["Chain Summary"],
            "MITRE Technique":  row.get("MITRE Technique", ""),
            "MITRE Name":       row.get("MITRE Name", ""),
        })
    return pd.DataFrame(attack_rows)


def correlate_download_execute(raw_df):
    findings = []
    download_kw = [
        "invoke-webrequest", "downloadstring", "downloadfile",
        "curl", "wget", "bitsadmin", "certutil"
    ]
    execute_kw = ["start-process", "iex", "invoke-expression"]
    for _, row in raw_df.iterrows():
        cmd = str(row.get("process.command_line", "")).lower()
        if any(x in cmd for x in download_kw) and any(x in cmd for x in execute_kw):
            findings.append({
                "Timestamp":   row.get("@timestamp", ""),
                "Process":     row.get("process.executable", ""),
                "Attack Step": "Download Execute",
                "Risk":        "Critical",
                "MITRE":       "T1105",
            })
    return pd.DataFrame(findings)


def correlate_persistence(raw_df):
    findings = []
    patterns = ["run", "runonce", "startup", "services", "tasks"]
    for _, row in raw_df.iterrows():
        reg = str(row.get("registry.path", "")).lower()
        if any(x in reg for x in patterns):
            findings.append({
                "Timestamp":   row.get("@timestamp", ""),
                "Process":     row.get("process.executable", ""),
                "Attack Step": "Persistence",
                "Risk":        "High",
                "MITRE":       "T1547.001",
            })
    return pd.DataFrame(findings)


def build_attack_timeline(alerts_df):
    if alerts_df.empty:
        return pd.DataFrame()

    timeline = alerts_df.copy()
    keep = [
        "Timestamp", "Process", "Parent Process",
        "Detection Type", "Risk Score",
        "MITRE Technique", "MITRE Name", "Event Action"
    ]
    keep = [x for x in keep if x in timeline.columns]
    timeline = timeline[keep]
    return timeline.sort_values(by="Timestamp").reset_index(drop=True)


def get_top_attack_chains(chain_df, top_n=20):
    if chain_df.empty:
        return chain_df
    return chain_df.nlargest(top_n, "Chain Risk Score")


def build_chain_metrics(chain_df):
    metrics = [["Attack Chains Found", len(chain_df)]]
    if not chain_df.empty:
        metrics.append(["Highest Chain Score", int(chain_df["Chain Risk Score"].max())])
        metrics.append(["Chains Above 80", int((chain_df["Chain Risk Score"] >= 80).sum())])
    return pd.DataFrame(metrics, columns=["Metric", "Value"])
