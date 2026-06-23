"""
correlation/risk_engine.py  -  Anomaly Hunter v3
==================================================
Risk scoring engine.

Responsibilities:
  1. Aggregate raw detector hits: same (Timestamp + Process) → one row
  2. Score aggregation with MAX_RISK_SCORE cap
  3. Apply allowlist / FP suppression BEFORE severity assignment
  4. Enrich every alert with Severity, Confidence, Analyst Verdict,
     Recommendation, and MITRE fields
  5. Build the investigation queue (MEDIUM and above)
"""

import re
import hashlib
import logging

import pandas as pd

from config.config import (
    MAX_RISK_SCORE, THRESHOLDS, KNOWN_GOOD_PROCESSES,
    MITRE_MAPPING, MITRE_NAMES, is_allowlisted,
)

log = logging.getLogger("AnomalyHunter.RiskEngine")


# ── Helpers ───────────────────────────────────────────────────────────────────

def calculate_severity(score: int) -> str:
    if score >= THRESHOLDS["CRITICAL"]: return "CRITICAL"
    if score >= THRESHOLDS["HIGH"]:     return "HIGH"
    if score >= THRESHOLDS["MEDIUM"]:   return "MEDIUM"
    if score >= THRESHOLDS["LOW"]:      return "LOW"
    return "INFO"


def calculate_confidence(score: int, detection_type: str) -> str:
    high_conf = {
        "Process Injection", "Download Execute", "Persistence",
        "Encoded Payload", "EDR Rule Detection", "Svchost Script Spawn",
        "Persistence via Cmdline", "Suspicious Parent-Child",
        "Defense Evasion", "Sigma Match",
    }
    primary = detection_type.split(" | ")[0].strip()
    if primary in high_conf:
        return "HIGH"
    if score >= THRESHOLDS["MEDIUM"]:
        return "MEDIUM"
    return "LOW"


def fp_assessment(process: str, score: int, allowlisted: bool) -> str:
    if allowlisted:
        return "Allowlisted / FP Suppressed"
    pname = str(process).lower().split("\\")[-1]
    if pname in KNOWN_GOOD_PROCESSES and score <= 30:
        return "Likely False Positive"
    if score >= THRESHOLDS["CRITICAL"]:
        return "Highly Suspicious"
    if score >= THRESHOLDS["HIGH"]:
        return "Suspicious"
    return "Needs Review"


def analyst_verdict(score: int) -> str:
    if score >= THRESHOLDS["CRITICAL"]: return "Escalate Immediately"
    if score >= THRESHOLDS["HIGH"]:     return "Investigate"
    if score >= THRESHOLDS["MEDIUM"]:   return "Review"
    return "Monitor"


RECOMMENDATIONS = {
    "Process Injection":        "Check memory / target process; consider full memory dump",
    "Download Execute":         "Isolate host; retrieve and sandbox the downloaded payload",
    "Persistence":              "Enumerate autoruns (Autoruns for Windows); remove malicious entry",
    "Persistence via Cmdline":  "Remove persistence key/entry found in detection; terminate spawned processes",
    "LOLBin Abuse":             "Review full command line and parent process chain",
    "PowerShell Payload":       "Export PowerShell ScriptBlock logs; decode commands",
    "Encoded Payload":          "Decode Base64 payload; send to sandbox",
    "Malware Staging":          "Collect file artefacts; hash and submit to VT",
    "External Communication":   "Block destination IP at perimeter; review netflow",
    "DNS Anomaly":              "Query domain reputation; sinkhole if confirmed malicious",
    "Network Outlier":          "Review process network history; identify C2 pattern",
    "EDR Rule Detection":       "Triage immediately — native EDR rule fired on this event",
    "Svchost Script Spawn":     "Inspect scheduled task body; delete malicious task entry",
    "Recon / IP Discovery":     "Host performing pre-C2 IP recon — isolate and image",
    "Beaconing":                "Block C2 IP; isolate host; collect full packet capture",
    "Suspicious Parent-Child":  "Trace macro/script origin; check email/browser downloads",
    "Defense Evasion":          "Re-enable Defender; check ExclusionPath list; reboot",
    "Sigma Match":              "Review matching Sigma rule for context-specific guidance",
}


def get_recommendation(detection_type: str) -> str:
    primary = detection_type.split(" | ")[0].strip()
    return RECOMMENDATIONS.get(primary, "Manual analyst review required")


def make_alert_id(timestamp: str, process: str, detection_type: str) -> str:
    key = f"{timestamp}{process}{detection_type[:30]}"
    return "AH-" + hashlib.md5(key.encode()).hexdigest()[:8].upper()


# ── Score aggregation ─────────────────────────────────────────────────────────

def aggregate_alerts(alerts_df: pd.DataFrame) -> pd.DataFrame:
    """
    Merge all detection hits for the same (Timestamp, Process) into one row.
    Sums risk scores (capped), merges detection type labels.
    """
    if alerts_df.empty:
        return alerts_df

    def first_nonempty(series):
        vals = series.replace("", pd.NA).dropna()
        return vals.iloc[0] if not vals.empty else ""

    aggregated = []
    for (ts, proc), group in alerts_df.groupby(["Timestamp", "Process"], sort=False):
        total_score  = min(int(group["Risk Score"].sum()), MAX_RISK_SCORE)
        det_types    = sorted(group["Detection Type"].dropna().unique().tolist())
        combined_det = " | ".join(det_types)
        reasons      = group["Investigation Reason"].dropna().unique().tolist()
        combined_rsn = " ; ".join(str(r) for r in reasons[:4])

        aggregated.append({
            "Timestamp":            ts,
            "Process":              proc,
            "Parent Process":       first_nonempty(group["Parent Process"]),
            "Command Line":         first_nonempty(group["Command Line"]),
            "Detection Type":       combined_det,
            "Risk Score":           total_score,
            "Investigation Reason": combined_rsn,
            "Source IP":            first_nonempty(group["Source IP"]),
            "Destination IP":       first_nonempty(group["Destination IP"]),
            "Registry Path":        first_nonempty(group["Registry Path"]),
            "File Path":            first_nonempty(group["File Path"]),
            "DNS Query":            first_nonempty(group["DNS Query"]),
            "Event Action":         first_nonempty(group["Event Action"]),
            "PID":                  first_nonempty(group["PID"]),
            "MITRE Technique":      first_nonempty(group["MITRE Technique"]),
            "MITRE Name":           first_nonempty(group["MITRE Name"]),
        })

    return pd.DataFrame(aggregated)


# ── MITRE enrichment ──────────────────────────────────────────────────────────

def _get_mitre_id(row: pd.Series) -> str:
    if row.get("MITRE Technique", ""):
        return row["MITRE Technique"]
    pname = str(row.get("Process", "")).lower().split("\\")[-1]
    return MITRE_MAPPING.get(pname, "")


def _get_mitre_name(row: pd.Series) -> str:
    if row.get("MITRE Name", ""):
        return row["MITRE Name"]
    tid = _get_mitre_id(row)
    return MITRE_NAMES.get(tid, "")


# ── Main enrichment pipeline ──────────────────────────────────────────────────

def enrich_alerts(alerts_df: pd.DataFrame) -> pd.DataFrame:
    """
    Full enrichment pipeline:
      1. Aggregate duplicate hits
      2. Apply allowlist / FP suppression
      3. Assign severity, confidence, verdict, recommendation
      4. Add unique Alert ID
    """
    if alerts_df.empty:
        return alerts_df

    df = aggregate_alerts(alerts_df)
    log.info("After aggregation: %d unique alert events", len(df))

    # Numeric score
    df["Risk Score"] = (
        pd.to_numeric(df["Risk Score"], errors="coerce")
        .fillna(0).clip(0, MAX_RISK_SCORE).astype(int)
    )

    # Allowlist check
    df["Allowlisted"] = df.apply(
        lambda r: is_allowlisted(r.get("Investigation Reason",""), r.get("Process","")),
        axis=1
    )
    suppressed = df["Allowlisted"].sum()
    if suppressed:
        log.info("FP suppression: %d events allowlisted", suppressed)

    # Do NOT remove allowlisted rows — keep them visible but mark them
    df["Severity"]   = df.apply(
        lambda r: "FP-SUPPRESSED" if r["Allowlisted"] else calculate_severity(r["Risk Score"]),
        axis=1
    )
    df["Confidence"] = df.apply(
        lambda r: calculate_confidence(r["Risk Score"], r["Detection Type"]), axis=1
    )
    df["FP Assessment"] = df.apply(
        lambda r: fp_assessment(r["Process"], r["Risk Score"], r["Allowlisted"]), axis=1
    )
    df["Analyst Verdict"]  = df["Risk Score"].apply(analyst_verdict)
    df["Recommendation"]   = df["Detection Type"].apply(get_recommendation)
    df["MITRE Technique"]  = df.apply(_get_mitre_id, axis=1)
    df["MITRE Name"]       = df.apply(_get_mitre_name, axis=1)
    df["Alert ID"]         = df.apply(
        lambda r: make_alert_id(r["Timestamp"], r["Process"], r["Detection Type"]), axis=1
    )

    return df.sort_values(by="Risk Score", ascending=False).reset_index(drop=True)


def get_investigation_queue(alerts_df: pd.DataFrame) -> pd.DataFrame:
    """Return alerts at MEDIUM severity or above, excluding FP-suppressed."""
    if alerts_df.empty:
        return alerts_df
    return alerts_df[
        alerts_df["Severity"].isin(["MEDIUM", "HIGH", "CRITICAL"])
    ].copy().reset_index(drop=True)
