"""
correlation/correlation_engine.py  -  Anomaly Hunter v3
=========================================================
Multi-alert correlation engine.

Instead of showing 8 individual detection rows for one malware session,
this engine groups related alerts into named Incidents with:
  - Incident ID
  - Incident Type (e.g. Malware Infection, Ransomware Prep, Credential Theft)
  - Combined Risk Score
  - Full MITRE tactic coverage
  - Root cause process
  - IOC summary

Correlation rules (pure Python, no external library):
  Rule = set of detection types that together indicate an incident.
  All specified types must be present for the incident to fire.
"""

import logging
import hashlib
from dataclasses import dataclass, field
from typing import Optional

import pandas as pd

log = logging.getLogger("AnomalyHunter.CorrelationEngine")


# ── Correlation rule definitions ──────────────────────────────────────────────

@dataclass
class CorrelationRule:
    id:           str
    name:         str
    description:  str
    required_any: list      # alert must contain at least one of these det-types
    required_all: list      # alert must contain ALL of these det-types (AND)
    severity:     str       = "HIGH"
    mitre_tactics: list     = field(default_factory=list)
    min_alerts:   int       = 1


CORRELATION_RULES = [
    CorrelationRule(
        id="INC-001",
        name="Malware Infection Chain",
        description=(
            "Full malware lifecycle: dropper execution → persistence "
            "installation → script execution → C2 communication."
        ),
        required_any=["Malware Staging", "EDR Rule Detection"],
        required_all=["Persistence", "Beaconing"],
        severity="CRITICAL",
        mitre_tactics=["TA0001","TA0002","TA0003","TA0011"],
        min_alerts=3,
    ),
    CorrelationRule(
        id="INC-002",
        name="Defense Evasion + Persistence",
        description=(
            "Attacker disabling security tools (Defender exclusion) "
            "immediately followed by persistence installation."
        ),
        required_any=["Defense Evasion"],
        required_all=["Persistence"],
        severity="CRITICAL",
        mitre_tactics=["TA0005","TA0003"],
        min_alerts=2,
    ),
    CorrelationRule(
        id="INC-003",
        name="Download-and-Execute Dropper",
        description=(
            "PowerShell or LOLBin downloading a payload and immediately executing it."
        ),
        required_any=["Download Execute", "PowerShell Payload"],
        required_all=["LOLBin Abuse"],
        severity="HIGH",
        mitre_tactics=["TA0002","TA0105"],
        min_alerts=2,
    ),
    CorrelationRule(
        id="INC-004",
        name="Recon + C2 Callback",
        description=(
            "Host performing IP geolocation recon immediately before "
            "establishing a C2 channel — classic pre-callback behaviour."
        ),
        required_any=["Recon / IP Discovery"],
        required_all=["Beaconing"],
        severity="CRITICAL",
        mitre_tactics=["TA0007","TA0011"],
        min_alerts=2,
    ),
    CorrelationRule(
        id="INC-005",
        name="Scheduled Task / Script Persistence Abuse",
        description=(
            "Scheduled task or Run key set up to launch a script interpreter "
            "from a user-writable path — living-off-the-land persistence."
        ),
        required_any=["Svchost Script Spawn", "Suspicious Parent-Child"],
        required_all=["Persistence"],
        severity="HIGH",
        mitre_tactics=["TA0003","TA0002"],
        min_alerts=2,
    ),
    CorrelationRule(
        id="INC-006",
        name="LOLBin Execution Chain",
        description=(
            "Multiple LOLBins used in sequence — typical fileless attack pattern."
        ),
        required_any=["LOLBin Abuse"],
        required_all=["Rare Parent-Child"],
        severity="MEDIUM",
        mitre_tactics=["TA0002"],
        min_alerts=2,
    ),
    CorrelationRule(
        id="INC-007",
        name="Sigma Rule Critical Cluster",
        description=(
            "Multiple Sigma rules fired on the same session — high-confidence threat."
        ),
        required_any=["Sigma Match"],
        required_all=[],
        severity="HIGH",
        mitre_tactics=["TA0002"],
        min_alerts=3,
    ),
]


def _incident_id(rule_id: str, process: str) -> str:
    key = f"{rule_id}{process}"
    return f"{rule_id}-{hashlib.md5(key.encode()).hexdigest()[:6].upper()}"


def _score_incident(matched_alerts: pd.DataFrame) -> int:
    import numpy as np
    scores = matched_alerts["Risk Score"].tolist()
    if not scores:
        return 0
    base = max(scores)
    bonus = int(sum(scores[1:]) * 0.3)
    return min(base + bonus, 100)


def _get_detection_type_set(alerts_df: pd.DataFrame) -> set:
    all_types = set()
    for dt in alerts_df["Detection Type"].dropna():
        for part in dt.split("|"):
            all_types.add(part.strip())
    return all_types


def correlate_alerts(alerts_df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply correlation rules to the enriched alerts DataFrame.
    Returns an Incidents DataFrame — one row per correlated incident.
    """
    if alerts_df.empty:
        return pd.DataFrame()

    # Work on non-FP-suppressed alerts
    working = alerts_df[alerts_df["Severity"] != "FP-SUPPRESSED"].copy()
    if working.empty:
        return pd.DataFrame()

    incidents = []

    for rule in CORRELATION_RULES:
        det_types = _get_detection_type_set(working)

        # required_any: at least one must be present
        any_match = any(req in det_types for req in rule.required_any) if rule.required_any else True
        # required_all: every one must be present
        all_match = all(req in det_types for req in rule.required_all) if rule.required_all else True

        if not (any_match and all_match):
            continue

        # Collect matching alert rows
        matched_rows = []
        for _, row in working.iterrows():
            row_types = {t.strip() for t in row["Detection Type"].split("|")}
            if (any(r in row_types for r in rule.required_any) if rule.required_any else True) or \
               (all(r in row_types for r in rule.required_all) if rule.required_all else True):
                matched_rows.append(row)

        matched_df = pd.DataFrame(matched_rows)
        if len(matched_df) < rule.min_alerts:
            continue

        # Root cause = highest-scoring process
        root_proc = matched_df.sort_values("Risk Score", ascending=False).iloc[0]["Process"]
        incident_score = _score_incident(matched_df)

        # Collect IOCs
        c2_ips = matched_df["Destination IP"].replace("", pd.NA).dropna().unique().tolist()
        processes = matched_df["Process"].apply(lambda p: str(p).split("\\")[-1]).unique().tolist()
        det_list  = sorted({t.strip() for dt in matched_df["Detection Type"] for t in dt.split("|")})
        mitre_str = " | ".join(rule.mitre_tactics)

        incidents.append({
            "Incident ID":      _incident_id(rule.id, root_proc),
            "Rule ID":          rule.id,
            "Incident Type":    rule.name,
            "Description":      rule.description,
            "Severity":         rule.severity,
            "Incident Score":   incident_score,
            "Alert Count":      len(matched_df),
            "Root Process":     root_proc,
            "Involved Processes": " | ".join(processes[:6]),
            "Detections":       " | ".join(det_list),
            "MITRE Tactics":    mitre_str,
            "C2 IPs":           " | ".join(str(ip) for ip in c2_ips[:5]) if c2_ips else "",
            "First Seen":       matched_df["Timestamp"].min(),
            "Last Seen":        matched_df["Timestamp"].max(),
            "Analyst Action":   "Escalate Immediately" if rule.severity == "CRITICAL" else "Investigate",
        })

    if not incidents:
        log.info("Correlation engine: no incidents matched")
        return pd.DataFrame()

    result = pd.DataFrame(incidents)
    result = result.sort_values("Incident Score", ascending=False).reset_index(drop=True)
    log.info("Correlation engine: %d incidents generated", len(result))
    return result
