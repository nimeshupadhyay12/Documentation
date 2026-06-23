"""
investigation/timeline_engine.py  -  Anomaly Hunter v3
========================================================
Produces a MITRE-tactic-staged timeline from the alerts DataFrame.

Instead of a flat timestamp sort, each event is tagged to a
MITRE tactic stage, allowing an analyst to read the attack
narrative in kill-chain order.

Output columns:
  Timeline Index | Tactic Stage | Timestamp | Process | Detection Type
  Risk Score | Severity | MITRE Technique | MITRE Name | Detail
"""

import re
import logging
import pandas as pd

from config.config import MITRE_TACTICS

log = logging.getLogger("AnomalyHunter.TimelineEngine")


# ── Tactic inference ──────────────────────────────────────────────────────────

# Map detection types to MITRE tactic IDs
DETECTION_TO_TACTIC = {
    "Malware Staging":          "TA0001",
    "EDR Rule Detection":       "TA0001",
    "Download Execute":         "TA0002",
    "PowerShell Payload":       "TA0002",
    "LOLBin Abuse":             "TA0002",
    "Encoded Payload":          "TA0005",
    "Defense Evasion":          "TA0005",
    "Sigma Match":              "TA0002",
    "Rare Process":             "TA0002",
    "Rare Parent-Child":        "TA0002",
    "Suspicious Parent-Child":  "TA0002",
    "Svchost Script Spawn":     "TA0002",
    "Persistence":              "TA0003",
    "Persistence via Cmdline":  "TA0003",
    "Recon / IP Discovery":     "TA0007",
    "DNS Anomaly":              "TA0007",
    "Network Outlier":          "TA0011",
    "External Communication":   "TA0011",
    "Beaconing":                "TA0011",
    "Process Injection":        "TA0004",
}

TACTIC_ORDER = [
    "TA0001", "TA0002", "TA0005", "TA0003",
    "TA0007", "TA0004", "TA0008", "TA0009",
    "TA0010", "TA0011",
]


def _infer_tactic(detection_type: str, mitre_technique: str) -> tuple:
    """Returns (tactic_id, tactic_name) for a given detection row."""
    primary = detection_type.split("|")[0].strip()
    tactic_id = DETECTION_TO_TACTIC.get(primary, "")

    # Fallback: infer from MITRE technique prefix
    if not tactic_id and mitre_technique:
        tid = str(mitre_technique)
        if tid.startswith("T1547"):   tactic_id = "TA0003"
        elif tid.startswith("T1059"): tactic_id = "TA0002"
        elif tid.startswith("T1218"): tactic_id = "TA0002"
        elif tid.startswith("T1105"): tactic_id = "TA0002"
        elif tid.startswith("T1055"): tactic_id = "TA0004"
        elif tid.startswith("T1071"): tactic_id = "TA0011"
        elif tid.startswith("T1016"): tactic_id = "TA0007"
        elif tid.startswith("T1562"): tactic_id = "TA0005"

    tactic_name = MITRE_TACTICS.get(tactic_id, "Unknown")
    return tactic_id or "TA0000", tactic_name or "Unknown"


def _tactic_sort_key(tactic_id: str) -> int:
    try:
        return TACTIC_ORDER.index(tactic_id)
    except ValueError:
        return 99


# ── Timeline builder ──────────────────────────────────────────────────────────

def build_staged_timeline(alerts_df: pd.DataFrame) -> pd.DataFrame:
    """
    Build the MITRE-staged timeline from enriched alerts.
    Returns a DataFrame sorted by (tactic_order, timestamp).
    """
    if alerts_df.empty:
        return pd.DataFrame()

    working = alerts_df[alerts_df["Severity"] != "FP-SUPPRESSED"].copy()
    if working.empty:
        return pd.DataFrame()

    rows = []
    for _, r in working.iterrows():
        tactic_id, tactic_name = _infer_tactic(
            r.get("Detection Type", ""),
            r.get("MITRE Technique", ""),
        )
        rows.append({
            "Timestamp":        r.get("Timestamp", ""),
            "Alert ID":         r.get("Alert ID", ""),
            "Tactic ID":        tactic_id,
            "Tactic":           tactic_name,
            "Tactic Order":     _tactic_sort_key(tactic_id),
            "Process":          r.get("Process", ""),
            "Parent Process":   r.get("Parent Process", ""),
            "Detection Type":   r.get("Detection Type", ""),
            "Risk Score":       r.get("Risk Score", 0),
            "Severity":         r.get("Severity", ""),
            "MITRE Technique":  r.get("MITRE Technique", ""),
            "MITRE Name":       r.get("MITRE Name", ""),
            "Destination IP":   r.get("Destination IP", ""),
            "Registry Path":    r.get("Registry Path", ""),
            "Detail":           r.get("Investigation Reason", ""),
        })

    df = pd.DataFrame(rows)
    df = df.sort_values(["Tactic Order", "Timestamp"]).reset_index(drop=True)
    df.insert(0, "Timeline #", range(1, len(df) + 1))
    return df


def render_timeline_text(timeline_df: pd.DataFrame) -> str:
    """Human-readable terminal timeline grouped by tactic stage."""
    if timeline_df.empty:
        return "(no timeline data)"

    lines = ["", "ATTACK TIMELINE", "=" * 80]
    current_tactic = None

    for _, row in timeline_df.iterrows():
        tactic = f"[{row['Tactic ID']}] {row['Tactic']}"
        if tactic != current_tactic:
            current_tactic = tactic
            lines.append(f"\n  ▶ {tactic}")
            lines.append("  " + "-" * 60)

        ts    = str(row["Timestamp"])
        proc  = str(row["Process"]).split("\\")[-1]
        det   = str(row["Detection Type"])[:60]
        score = row["Risk Score"]
        sev   = row["Severity"]
        lines.append(f"    {ts}  [{sev:<8}] {proc:<25}  {det}  (score={score})")

    lines.append("\n" + "=" * 80)
    return "\n".join(lines)
