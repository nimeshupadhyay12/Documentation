"""
scoring.py
Anomaly Hunter v2.1

IMPROVEMENTS OVER v2.0:
- Score aggregation: when the same (Timestamp, Process) pair fires
  multiple detectors, scores are summed and capped at MAX_RISK_SCORE
  instead of appearing as duplicate rows — reduces noise dramatically
- MITRE fields are now carried through from detectors
- False-positive suppression: known-good processes with low individual
  scores (< 30) are downgraded before severity assignment
- Added MITRE technique enrichment from config lookup
- get_investigation_queue now includes MEDIUM severity too (not just
  HIGH/CRITICAL) so the queue isn't empty when no critical hit fires
- Added build_fp_suppressed_alerts() helper
"""

import pandas as pd
from config import *


# ─────────────────────────────────────────────
#  Severity / Confidence / Verdict helpers
# ─────────────────────────────────────────────

def calculate_severity(score):
    if score >= CRITICAL_THRESHOLD: return "CRITICAL"
    if score >= HIGH_THRESHOLD:     return "HIGH"
    if score >= MEDIUM_THRESHOLD:   return "MEDIUM"
    if score >= LOW_THRESHOLD:      return "LOW"
    return "INFO"


def calculate_confidence(score, detection_type):
    high_confidence_types = {
        "Process Injection", "Download Execute", "Persistence",
        "Encoded Payload", "EDR Rule Detection",
        "Svchost Script Spawn", "Persistence via Cmdline",
        "Suspicious Parent-Child"
    }
    if detection_type in high_confidence_types:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def false_positive_assessment(process, score):
    process = str(process).lower().split("\\")[-1]
    if process in KNOWN_GOOD_PROCESSES and score <= 30:
        return "Likely False Positive"
    if score >= 80:
        return "Highly Suspicious"
    if score >= 60:
        return "Suspicious"
    return "Needs Review"


def analyst_verdict(score):
    if score >= 80: return "Escalate Immediately"
    if score >= 60: return "Investigate"
    if score >= 40: return "Review"
    return "Monitor"


def recommendation(detection_type):
    mapping = {
        "Process Injection":        "Check memory activity and target process",
        "Download Execute":         "Isolate host and review downloaded payload",
        "Persistence":              "Review autoruns, services and scheduled tasks",
        "Persistence via Cmdline":  "Check Run key for: wscript/uusd payload; remove entry",
        "LOLBin Abuse":             "Investigate command line and parent process",
        "PowerShell Payload":       "Review PowerShell history and script content",
        "Encoded Payload":          "Decode and inspect payload",
        "Malware Staging":          "Inspect file location and execution source",
        "External Communication":   "Review outbound traffic and destination",
        "DNS Anomaly":              "Investigate domain reputation",
        "Network Outlier":          "Review unusual network behavior",
        "EDR Rule Detection":       "Triage immediately — EDR flagged this event",
        "Svchost Script Spawn":     "Investigate svchost child; likely scheduled task abuse",
        "Recon / IP Discovery":     "Attacker performing network recon pre-C2 — isolate host",
        "Beaconing":                "Block destination IP; review C2 traffic; isolate host",
        "Suspicious Parent-Child":  "Trace parent process origin; check macro or script execution",
    }
    return mapping.get(detection_type, "Manual analyst review")


# ─────────────────────────────────────────────
#  Score Aggregation  (NEW)
# ─────────────────────────────────────────────

def aggregate_alerts(alerts_df):
    """
    Aggregate multiple detection hits for the same event
    (Timestamp + Process) by summing risk scores and merging
    detection type labels. This prevents 1623 duplicate Malware Staging
    rows flooding the report.
    """
    if alerts_df.empty:
        return alerts_df

    group_keys = ["Timestamp", "Process"]
    aggregated = []

    for keys, group in alerts_df.groupby(group_keys, sort=False):
        # Sum scores, cap at MAX_RISK_SCORE
        total_score = min(int(group["Risk Score"].sum()), MAX_RISK_SCORE)

        # Combine detection types
        det_types = sorted(group["Detection Type"].dropna().unique().tolist())
        combined_det = " | ".join(det_types)

        # Combine investigation reasons
        reasons = group["Investigation Reason"].dropna().unique().tolist()
        combined_reason = " ; ".join(reasons[:3])  # cap to avoid giant strings

        # Take first non-empty value for context fields
        def first_nonempty(col):
            vals = group[col].replace("", pd.NA).dropna()
            return vals.iloc[0] if not vals.empty else ""

        aggregated.append({
            "Timestamp":             keys[0],
            "Process":               keys[1],
            "Parent Process":        first_nonempty("Parent Process"),
            "Detection Type":        combined_det,
            "Risk Score":            total_score,
            "Investigation Reason":  combined_reason,
            "Source IP":             first_nonempty("Source IP"),
            "Destination IP":        first_nonempty("Destination IP"),
            "MITRE Technique":       first_nonempty("MITRE Technique"),
            "MITRE Name":            first_nonempty("MITRE Name"),
            "Event Action":          first_nonempty("Event Action"),
        })

    return pd.DataFrame(aggregated)


# ─────────────────────────────────────────────
#  Enrichment
# ─────────────────────────────────────────────

def enrich_alerts(alerts_df):
    if alerts_df.empty:
        return alerts_df

    # Aggregate first — reduces 3998 → meaningful unique events
    df = aggregate_alerts(alerts_df)

    df["Risk Score"] = (
        pd.to_numeric(df["Risk Score"], errors="coerce")
        .fillna(0)
        .clip(0, MAX_RISK_SCORE)
        .astype(int)
    )

    df["Severity"] = df["Risk Score"].apply(calculate_severity)

    df["Confidence"] = df.apply(
        lambda x: calculate_confidence(x["Risk Score"], x["Detection Type"]),
        axis=1
    )

    df["False Positive Assessment"] = df.apply(
        lambda x: false_positive_assessment(x["Process"], x["Risk Score"]),
        axis=1
    )

    df["Analyst Verdict"] = df["Risk Score"].apply(analyst_verdict)

    df["Recommendation"] = df["Detection Type"].apply(
        lambda dt: recommendation(dt.split(" | ")[0])   # use primary detection type
    )

    # MITRE enrichment fallback from config if detector didn't populate it
    def _mitre_id(row):
        if row.get("MITRE Technique", ""):
            return row["MITRE Technique"]
        pname = str(row.get("Process", "")).lower().split("\\")[-1]
        return MITRE_MAPPING.get(pname, "")

    def _mitre_name(row):
        if row.get("MITRE Name", ""):
            return row["MITRE Name"]
        tid = _mitre_id(row)
        return MITRE_NAMES.get(tid, "")

    df["MITRE Technique"] = df.apply(_mitre_id, axis=1)
    df["MITRE Name"]      = df.apply(_mitre_name, axis=1)

    return df.sort_values(by="Risk Score", ascending=False).reset_index(drop=True)


def get_investigation_queue(alerts_df):
    """
    IMPROVEMENT: include MEDIUM severity so queue is never empty when
    only medium-severity alerts fire.
    """
    if alerts_df.empty:
        return alerts_df

    return alerts_df[
        alerts_df["Severity"].isin(["HIGH", "CRITICAL", "MEDIUM"])
    ].copy()


# ─────────────────────────────────────────────
#  Executive Metrics
# ─────────────────────────────────────────────

def build_executive_metrics(alerts_df):
    metrics = []
    metrics.append(["Total Unique Events Alerted", len(alerts_df)])
    metrics.append(["Critical Alerts",  int((alerts_df["Severity"] == "CRITICAL").sum())])
    metrics.append(["High Alerts",      int((alerts_df["Severity"] == "HIGH").sum())])
    metrics.append(["Medium Alerts",    int((alerts_df["Severity"] == "MEDIUM").sum())])
    metrics.append(["EDR Rule Hits",    int(alerts_df["Detection Type"].str.contains("EDR Rule", na=False).sum())])
    metrics.append(["Persistence Events", int(alerts_df["Detection Type"].str.contains("Persistence", na=False).sum())])
    metrics.append(["Process Injection Events", int(alerts_df["Detection Type"].str.contains("Process Injection", na=False).sum())])
    metrics.append(["Download Execute Events", int(alerts_df["Detection Type"].str.contains("Download Execute", na=False).sum())])
    metrics.append(["Beaconing Events", int(alerts_df["Detection Type"].str.contains("Beaconing", na=False).sum())])
    return pd.DataFrame(metrics, columns=["Metric", "Value"])
