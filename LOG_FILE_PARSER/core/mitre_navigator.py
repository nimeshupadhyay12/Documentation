"""
core/mitre_navigator.py  -  Anomaly Hunter Pro
================================================
Generates a MITRE ATT&CK Navigator layer JSON file.

Output can be imported directly at:
  https://mitre-attack.github.io/attack-navigator/

Shows:
  - Which techniques were detected (coloured by alert count)
  - Which techniques have detection coverage (from detector registry)
  - Technique-level comments with alert details
"""

import json
import logging
from pathlib import Path
from collections import defaultdict

import pandas as pd

from ah_config.config import MITRE_MAPPING, MITRE_NAMES

log = logging.getLogger("AnomalyHunter.MITRENavigator")

# Technique → Tactic mapping (needed for Navigator layer)
TECHNIQUE_TACTICS = {
    "T1059.001": "execution",
    "T1059.003": "execution",
    "T1059.005": "execution",
    "T1218.011": "defense-evasion",
    "T1218.010": "defense-evasion",
    "T1218.005": "defense-evasion",
    "T1218.004": "defense-evasion",
    "T1218":     "defense-evasion",
    "T1105":     "command-and-control",
    "T1127.001": "defense-evasion",
    "T1053.005": "persistence",
    "T1047":     "execution",
    "T1547.001": "persistence",
    "T1016":     "discovery",
    "T1027":     "defense-evasion",
    "T1055":     "privilege-escalation",
    "T1071":     "command-and-control",
    "T1562.001": "defense-evasion",
    "T1036":     "defense-evasion",
    "T1110":     "credential-access",
    "T1595":     "reconnaissance",
    "T1204":     "execution",
    "T1078":     "defense-evasion",
    "T1568":     "command-and-control",
    "T1003.001": "credential-access",
    "T1069":     "discovery",
    "T1490":     "impact",
    "T1190":     "initial-access",
    "T1083":     "discovery",
}

# All techniques the tool CAN detect (coverage map)
DETECTION_COVERAGE = set(MITRE_MAPPING.values()) | {
    "T1110", "T1595", "T1204", "T1078", "T1568",
    "T1003.001", "T1069", "T1490", "T1190", "T1083",
}

COLOUR_SCALE = [
    (0,   "#ffffff"),   # no alerts
    (1,   "#ffeeee"),   # 1 alert
    (3,   "#ffcccc"),   # 3+ alerts
    (10,  "#ff9999"),   # 10+ alerts
    (30,  "#ff6666"),   # 30+ alerts
    (100, "#cc0000"),   # 100+ alerts
]


def _pick_colour(count: int) -> str:
    colour = "#ffffff"
    for threshold, col in COLOUR_SCALE:
        if count >= threshold:
            colour = col
    return colour


def build_navigator_layer(alerts_df: pd.DataFrame,
                           output_path: str = "") -> dict:
    """
    Build a MITRE ATT&CK Navigator layer from alerts.

    Args:
        alerts_df:   Enriched alerts DataFrame
        output_path: If provided, write JSON to this path

    Returns:
        Layer dict (also saved to output_path if provided)
    """
    # Count alerts per technique
    tech_counts   = defaultdict(int)
    tech_comments = defaultdict(list)
    tech_severity = defaultdict(str)

    if not alerts_df.empty and "MITRE Technique" in alerts_df.columns:
        for _, row in alerts_df.iterrows():
            tid = str(row.get("MITRE Technique", "")).strip()
            if not tid or tid == "nan":
                continue
            sev   = str(row.get("Severity", ""))
            proc  = str(row.get("Process", "")).split("\\")[-1]
            det   = str(row.get("Detection Type", ""))[:40]
            score = int(row.get("Risk Score", 0))

            tech_counts[tid] += 1
            if len(tech_comments[tid]) < 3:
                tech_comments[tid].append(f"[{sev}] {proc} — {det} (score={score})")
            if sev == "CRITICAL" or (sev == "HIGH" and tech_severity[tid] != "CRITICAL"):
                tech_severity[tid] = sev

    # Build technique entries
    techniques = []

    # 1. Detected techniques (from alerts)
    for tid, count in tech_counts.items():
        comment  = "\n".join(tech_comments.get(tid, []))
        tname    = MITRE_NAMES.get(tid, tid)
        techniques.append({
            "techniqueID": tid,
            "tactic":      TECHNIQUE_TACTICS.get(tid, ""),
            "score":       count,
            "color":       _pick_colour(count),
            "comment":     f"{tname}: {count} alert(s)\n{comment}",
            "enabled":     True,
            "metadata":    [
                {"name": "Alert Count", "value": str(count)},
                {"name": "Severity",    "value": tech_severity.get(tid, "")},
            ],
            "links":       [],
            "showSubtechniques": True,
        })

    # 2. Coverage-only techniques (detected = 0, but we have a rule for them)
    detected_set = set(tech_counts.keys())
    for tid in DETECTION_COVERAGE - detected_set:
        tname = MITRE_NAMES.get(tid, tid)
        techniques.append({
            "techniqueID": tid,
            "tactic":      TECHNIQUE_TACTICS.get(tid, ""),
            "score":       0,
            "color":       "#e8f5e9",   # light green = coverage but no alerts
            "comment":     f"{tname}: Detection rule exists, 0 alerts this run",
            "enabled":     True,
            "metadata":    [{"name": "Coverage", "value": "Detector exists"}],
            "links":       [],
            "showSubtechniques": False,
        })

    layer = {
        "name":        "Anomaly Hunter Pro — Detection Results",
        "versions":    {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain":      "enterprise-attack",
        "description": (
            f"Techniques detected by Anomaly Hunter Pro. "
            f"{len(tech_counts)} techniques triggered, "
            f"{len(DETECTION_COVERAGE)} techniques have coverage."
        ),
        "filters":     {"platforms": ["Windows","Linux","macOS","Cloud"]},
        "sorting":     3,   # sort by score descending
        "layout": {
            "layout":          "side",
            "aggregateFunction": "sum",
            "showID":          True,
            "showName":        True,
            "showAggregateScores": True,
            "countUnscored":   False,
        },
        "hideDisabled": False,
        "techniques":  techniques,
        "gradient": {
            "colors":   ["#ffffff", "#ff6666"],
            "minValue": 0,
            "maxValue": max(tech_counts.values()) if tech_counts else 10,
        },
        "legendItems": [
            {"label": "CRITICAL alerts",   "color": "#cc0000"},
            {"label": "HIGH alerts",       "color": "#ff6666"},
            {"label": "MEDIUM alerts",     "color": "#ff9999"},
            {"label": "Coverage (0 hits)", "color": "#e8f5e9"},
            {"label": "No coverage",       "color": "#ffffff"},
        ],
        "metadata":    [],
        "links":       [],
        "showTacticRowBackground":     True,
        "tacticRowBackground":         "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }

    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(layer, f, indent=2)
        log.info("MITRE Navigator layer written: %s  (%d techniques)",
                 output_path, len(techniques))

    return layer
