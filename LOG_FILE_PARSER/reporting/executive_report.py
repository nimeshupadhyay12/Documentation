"""
reporting/executive_report.py  -  Anomaly Hunter v3
=====================================================
Generates the executive summary:
  - One-page CSV with top-level metrics, top threats, top IOCs
  - Plain-text version for terminal output / email body
  - JSON report (machine-readable, for SIEM ingestion)
"""

import json
import logging
from datetime import datetime
from pathlib import Path

import pandas as pd

from ah_config.config import OUTPUT_FILES

log = logging.getLogger("AnomalyHunter.ExecutiveReport")


def _safe(val) -> str:
    return str(val) if val is not None else ""


def build_executive_csv(investigation: dict, output_dir: str) -> str:
    """Build and save the executive summary CSV. Returns file path."""
    stats         = investigation.get("stats", {})
    sev_counts    = investigation.get("severity_counts", {})
    det_counts    = investigation.get("detection_counts", {})
    c2_ips        = investigation.get("c2_ips", [])
    persist_iocs  = investigation.get("persistence_indicators", [])
    patient_zero  = investigation.get("patient_zero", {})
    incidents_df  = investigation.get("incidents_df", pd.DataFrame())
    ioc_df        = investigation.get("ioc_df", pd.DataFrame())
    alerts_df     = investigation.get("alerts_df", pd.DataFrame())

    rows = []
    rows.append(["Generated",             datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
    rows.append(["Anomaly Hunter Version", "3.0"])
    rows.append(["", ""])

    rows.append(["=== OVERVIEW ===", ""])
    for k, v in stats.items():
        rows.append([k, _safe(v)])
    rows.append(["", ""])

    rows.append(["=== SEVERITY BREAKDOWN ===", ""])
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "FP-SUPPRESSED"]:
        if sev in sev_counts:
            rows.append([f"  {sev}", sev_counts[sev]])
    rows.append(["", ""])

    rows.append(["=== PATIENT ZERO ===", ""])
    if patient_zero:
        for k, v in patient_zero.items():
            rows.append([f"  {k}", _safe(v)])
    rows.append(["", ""])

    rows.append(["=== TOP DETECTION TYPES ===", ""])
    for det, count in sorted(det_counts.items(), key=lambda x: -x[1])[:10]:
        rows.append([f"  {det}", count])
    rows.append(["", ""])

    rows.append(["=== IOC HIGHLIGHTS ===", ""])
    if c2_ips:
        rows.append(["  Suspected C2 IPs", " | ".join(_safe(ip) for ip in c2_ips[:8])])
    if persist_iocs:
        rows.append(["  Persistence Keys", " | ".join(_safe(p) for p in persist_iocs[:4])])
    rows.append(["", ""])

    rows.append(["=== TOP CORRELATED INCIDENTS ===", ""])
    if incidents_df is not None and not incidents_df.empty:
        for _, inc in incidents_df.head(5).iterrows():
            rows.append([
                f"  {inc.get('Incident ID','')} — {inc.get('Incident Type','')}",
                f"Score={inc.get('Incident Score',0)}  Severity={inc.get('Severity','')}"
            ])
    rows.append(["", ""])

    rows.append(["=== TOP MITRE TECHNIQUES ===", ""])
    if not alerts_df.empty and "MITRE Technique" in alerts_df.columns:
        tech_counts = (
            alerts_df["MITRE Technique"].replace("", pd.NA).dropna()
            .value_counts().head(8)
        )
        for tid, cnt in tech_counts.items():
            rows.append([f"  {tid}", cnt])
    rows.append(["", ""])

    rows.append(["=== TOP SUSPICIOUS PROCESSES ===", ""])
    if not alerts_df.empty and "Process" in alerts_df.columns:
        working = alerts_df[alerts_df["Severity"] != "FP-SUPPRESSED"]
        top_procs = working["Process"].value_counts().head(8)
        for proc, cnt in top_procs.items():
            pname = str(proc).split("\\")[-1]
            rows.append([f"  {pname}", cnt])
    rows.append(["", ""])

    rows.append(["=== THREAT INTEL SUMMARY ===", ""])
    if ioc_df is not None and not ioc_df.empty and "TI Verdict" in ioc_df.columns:
        verdict_counts = ioc_df["TI Verdict"].value_counts()
        for verdict, count in verdict_counts.items():
            rows.append([f"  {verdict}", count])
    rows.append(["", ""])

    rows.append(["=== ANALYST RECOMMENDATIONS ===", ""])
    # Build dynamic recommendations from actual findings
    recommendations = [
        "1. IMMEDIATE: Isolate any host with CRITICAL or HIGH severity alerts",
        "2. IMMEDIATE: Block all identified C2 / suspicious external IPs at perimeter",
        "3. HIGH:      Review and remove any persistence keys/tasks identified in alerts",
        "4. HIGH:      Collect and sandbox all malicious IOC files identified",
        "5. HIGH:      Check for defense evasion: review AV/EDR exclusion lists",
        "6. MEDIUM:    Submit all IOC file hashes to VirusTotal for attribution",
        "7. MEDIUM:    Block suspicious domains identified in DNS Anomaly alerts",
        "8. MEDIUM:    Image and forensically preserve all affected endpoints",
    ]
    # Append dynamic findings
    if c2_ips:
        recommendations.append(f"   DYNAMIC: Block C2 IPs: {', '.join(str(x) for x in c2_ips[:5])}")
    if persist_iocs:
        recommendations.append(f"   DYNAMIC: Remove persistence entry: {persist_iocs[0][:80]}")
    for rec in recommendations:
        rows.append(["  ", rec])

    df = pd.DataFrame(rows, columns=["Metric", "Value"])
    out_path = str(Path(output_dir) / OUTPUT_FILES["executive_summary"])
    df.to_csv(out_path, index=False)
    log.info("Executive summary CSV: %s", out_path)
    return out_path


def build_json_report(investigation: dict, output_dir: str) -> str:
    """
    Build a machine-readable JSON report for SIEM/SOAR ingestion.
    Returns file path.
    """
    stats        = investigation.get("stats", {})
    patient_zero = investigation.get("patient_zero", {})
    c2_ips       = investigation.get("c2_ips", [])
    incidents_df = investigation.get("incidents_df", pd.DataFrame())
    ioc_df       = investigation.get("ioc_df", pd.DataFrame())
    queue_df     = investigation.get("queue_df", pd.DataFrame())
    beacon_df    = investigation.get("beacon_df", pd.DataFrame())

    def _df_to_list(df, max_rows=50):
        if df is None or df.empty:
            return []
        return df.head(max_rows).fillna("").to_dict("records")

    report = {
        "meta": {
            "generated":          datetime.now().isoformat(),
            "framework":          "Anomaly Hunter v3",
            "tlp":                "AMBER",
        },
        "stats":          stats,
        "patient_zero":   patient_zero,
        "c2_ips":         c2_ips,
        "incidents":      _df_to_list(incidents_df),
        "top_alerts":     _df_to_list(queue_df, 30),
        "iocs":           _df_to_list(ioc_df, 50),
        "beaconing":      _df_to_list(beacon_df, 10),
    }

    out_path = str(Path(output_dir) / OUTPUT_FILES["json_report"])
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    log.info("JSON report written: %s", out_path)
    return out_path


def print_terminal_summary(investigation: dict) -> None:
    """Print a concise terminal summary after analysis completes."""
    stats        = investigation.get("stats", {})
    patient_zero = investigation.get("patient_zero", {})
    sev_counts   = investigation.get("severity_counts", {})
    c2_ips       = investigation.get("c2_ips", [])
    persist_iocs = investigation.get("persistence_indicators", [])
    incidents_df = investigation.get("incidents_df", pd.DataFrame())

    W = 64
    print()
    print("=" * W)
    print("  ANOMALY HUNTER v3  —  INVESTIGATION SUMMARY")
    print("=" * W)

    for k, v in stats.items():
        print(f"  {k:<30} {v}")

    print()
    print("  SEVERITY BREAKDOWN")
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","FP-SUPPRESSED"]:
        count = sev_counts.get(sev, 0)
        if count:
            bar = "█" * min(count, 30)
            print(f"  {sev:<14} {count:>4}  {bar}")

    if patient_zero:
        print()
        print("  PATIENT ZERO")
        print(f"  Process  : {patient_zero.get('Process Name','?')}")
        print(f"  Path     : {str(patient_zero.get('Process',''))[:60]}")
        print(f"  Parent   : {patient_zero.get('Parent Name','?')}")
        print(f"  Score    : {patient_zero.get('Risk Score',0)}")
        print(f"  Severity : {patient_zero.get('Severity','')}")

    if c2_ips:
        print()
        print("  SUSPECTED C2 IPs")
        for ip in c2_ips[:6]:
            print(f"    ► {ip}")

    if persist_iocs:
        print()
        print("  PERSISTENCE INDICATORS")
        for k in persist_iocs[:3]:
            print(f"    ► {str(k)[:70]}")

    if incidents_df is not None and not incidents_df.empty:
        print()
        print("  CORRELATED INCIDENTS")
        for _, inc in incidents_df.head(5).iterrows():
            print(
                f"    [{inc.get('Severity','?'):<8}] "
                f"{inc.get('Incident ID','')} — "
                f"{inc.get('Incident Type','')} "
                f"(score={inc.get('Incident Score',0)})"
            )

    print()
    print("=" * W)
