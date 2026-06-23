"""
correlation/attack_chain.py  -  Anomaly Hunter v3
===================================================
Attack chain reconstruction:
  - Suspicious process chain summary (parent → child groupings)
  - Full kill-chain narrative (5-stage: Access→Persist→Execute→Recon→C2)
  - Attack timeline (chronological alert sequence with MITRE tags)
"""

import re
import logging
import pandas as pd

from ah_config.config import MITRE_MAPPING, MITRE_NAMES

log = logging.getLogger("AnomalyHunter.AttackChain")


def _norm(value: str) -> str:
    return str(value).lower().split("\\")[-1].strip()


# ── Process chain summary ─────────────────────────────────────────────────────

def build_suspicious_chains(alerts_df: pd.DataFrame) -> pd.DataFrame:
    if alerts_df.empty:
        return pd.DataFrame()

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
        risk  = min(int(group["Risk Score"].sum()), 100)
        dets  = sorted(group["Detection Type"].dropna().unique().tolist())
        pname = _norm(process)
        tid   = MITRE_MAPPING.get(pname, "")
        tname = MITRE_NAMES.get(tid, "")

        chain_rows.append({
            "Chain ID":         f"AC-{chain_id:04d}",
            "Root Process":     _norm(parent),
            "Child Process":    pname,
            "Full Child Path":  process,
            "Chain Risk Score": risk,
            "Detection Count":  len(group),
            "Detections":       " | ".join(dets),
            "Chain Summary":    f"{_norm(parent)} → {pname}",
            "MITRE Technique":  tid,
            "MITRE Name":       tname,
        })
        chain_id += 1

    if not chain_rows:
        return pd.DataFrame()
    chains = pd.DataFrame(chain_rows)
    return chains.sort_values("Chain Risk Score", ascending=False).reset_index(drop=True)


def build_attack_chain_report(alerts_df: pd.DataFrame, raw_df: pd.DataFrame) -> pd.DataFrame:
    return build_suspicious_chains(alerts_df)


# ── Full kill-chain narrative ─────────────────────────────────────────────────

def build_full_kill_chain(alerts_df: pd.DataFrame, raw_df: pd.DataFrame) -> pd.DataFrame:
    """
    5-stage kill-chain reconstruction aligned to MITRE ATT&CK tactics.
    Returns one row per stage entry found.
    """
    if alerts_df.empty:
        return pd.DataFrame()

    stages = []

    # Stage 1 – Initial Access / Dropper
    mask = alerts_df["Detection Type"].str.contains("Malware Staging|EDR Rule", na=False)
    for _, r in alerts_df[mask].drop_duplicates("Process").head(3).iterrows():
        stages.append({
            "Stage":          "1 – Initial Access / Dropper",
            "MITRE Tactic":   "TA0001 / TA0002",
            "Timestamp":      r.get("Timestamp", ""),
            "Process":        r.get("Process", ""),
            "Parent Process": r.get("Parent Process", ""),
            "Detail":         r.get("Investigation Reason", ""),
            "Risk Score":     r.get("Risk Score", 0),
            "Recommendation": "Collect dropper; hash and sandbox immediately",
        })

    # Stage 2 – Defense Evasion (Defender exclusion)
    mask = alerts_df["Detection Type"].str.contains("Defense Evasion", na=False)
    for _, r in alerts_df[mask].drop_duplicates("Process").head(2).iterrows():
        stages.append({
            "Stage":          "2 – Defense Evasion",
            "MITRE Tactic":   "TA0005",
            "Timestamp":      r.get("Timestamp", ""),
            "Process":        r.get("Process", ""),
            "Parent Process": r.get("Parent Process", ""),
            "Detail":         r.get("Investigation Reason", ""),
            "Risk Score":     r.get("Risk Score", 0),
            "Recommendation": "Re-enable Defender; review ExclusionPath list",
        })

    # Stage 3 – Persistence
    mask = alerts_df["Detection Type"].str.contains("Persistence", na=False)
    for _, r in alerts_df[mask].drop_duplicates("Process").head(3).iterrows():
        stages.append({
            "Stage":          "3 – Persistence Installation",
            "MITRE Tactic":   "TA0003",
            "Timestamp":      r.get("Timestamp", ""),
            "Process":        r.get("Process", ""),
            "Parent Process": r.get("Parent Process", ""),
            "Detail":         r.get("Investigation Reason", ""),
            "Risk Score":     r.get("Risk Score", 0),
            "Recommendation": "Enumerate and remove persistence keys/scheduled tasks created by this process",
        })

    # Stage 4 – Execution via LOLBin
    mask = alerts_df["Detection Type"].str.contains("LOLBin|Svchost|Suspicious Parent", na=False)
    for _, r in alerts_df[mask].drop_duplicates("Process").head(3).iterrows():
        stages.append({
            "Stage":          "4 – Execution via LOLBin",
            "MITRE Tactic":   "TA0002",
            "Timestamp":      r.get("Timestamp", ""),
            "Process":        r.get("Process", ""),
            "Parent Process": r.get("Parent Process", ""),
            "Detail":         r.get("Investigation Reason", ""),
            "Risk Score":     r.get("Risk Score", 0),
            "Recommendation": "Terminate spawned interpreter/payload processes; collect artefacts",
        })

    # Stage 5 – Discovery / Recon
    mask = alerts_df["Detection Type"].str.contains("Recon|DNS Anomaly", na=False)
    for _, r in alerts_df[mask].drop_duplicates("Process").head(2).iterrows():
        stages.append({
            "Stage":          "5 – Discovery / Recon",
            "MITRE Tactic":   "TA0007",
            "Timestamp":      r.get("Timestamp", ""),
            "Process":        r.get("Process", ""),
            "Parent Process": r.get("Parent Process", ""),
            "Detail":         r.get("Investigation Reason", ""),
            "Risk Score":     r.get("Risk Score", 0),
            "Recommendation": "Block recon domains at DNS; collect curl artefacts",
        })

    # Stage 6 – C2
    mask = alerts_df["Detection Type"].str.contains("Beaconing|External Communication", na=False)
    for _, r in alerts_df[mask].drop_duplicates(["Process","Destination IP"]).head(5).iterrows():
        stages.append({
            "Stage":          "6 – C2 Communication",
            "MITRE Tactic":   "TA0011",
            "Timestamp":      r.get("Timestamp", ""),
            "Process":        r.get("Process", ""),
            "Parent Process": r.get("Parent Process", ""),
            "Detail":         f"C2 IP: {r.get('Destination IP','')} | {r.get('Investigation Reason','')}",
            "Risk Score":     r.get("Risk Score", 0),
            "Recommendation": "Block C2 IPs at firewall; full packet capture; isolate host",
        })

    if not stages:
        return pd.DataFrame()

    df = pd.DataFrame(stages)
    return df.sort_values("Timestamp").reset_index(drop=True)


# ── Timeline ──────────────────────────────────────────────────────────────────

def build_attack_timeline(alerts_df: pd.DataFrame) -> pd.DataFrame:
    if alerts_df.empty:
        return pd.DataFrame()

    keep = [
        "Timestamp", "Alert ID", "Process", "Parent Process",
        "Detection Type", "Risk Score", "Severity",
        "MITRE Technique", "MITRE Name", "Event Action",
        "Destination IP", "Registry Path",
    ]
    keep = [c for c in keep if c in alerts_df.columns]
    return alerts_df[keep].sort_values("Timestamp").reset_index(drop=True)
