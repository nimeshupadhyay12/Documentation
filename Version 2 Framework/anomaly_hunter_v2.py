"""
anomaly_hunter_v2.py
Main Orchestration Engine  v2.1

IMPROVEMENTS OVER v2.0:
- validate_columns: gracefully warns on missing optional columns
  instead of crashing (Target.process.executable is often absent)
- Added kill_chain phase using build_full_kill_chain()
- generate_all_reports now passes kill_chain_df
- Statistics updated to show per-severity counts and IOC highlights
- print_statistics prints C2 IPs and persistence indicators if found
- Added --log argument so the log file path can be overridden from CLI
"""

import sys
import argparse
import pandas as pd
from datetime import datetime

from config import DEFAULT_LOG_FILE
from detectors import run_all_detectors
from scoring import enrich_alerts, get_investigation_queue
from attack_chain import (
    build_attack_chain_report,
    build_attack_timeline,
    build_full_kill_chain,
)
from reports import generate_all_reports


def banner():
    print("=" * 60)
    print("  Anomaly Hunter v2.1")
    print("  Advanced Threat Hunting Platform")
    print("=" * 60)


REQUIRED_COLUMNS = [
    "@timestamp",
    "process.executable",
    "process.parent.executable",
    "process.command_line",
    "source.ip",
    "destination.ip",
    "dns.question.name",
    "registry.path",
]

OPTIONAL_COLUMNS = [
    "Target.process.executable",
    "Target.process.pid",
    "file.path",
    "dll.path",
    "event.action",
]


def validate_columns(df):
    missing_required = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing_required:
        raise ValueError(f"Missing required columns: {missing_required}")

    missing_optional = [c for c in OPTIONAL_COLUMNS if c not in df.columns]
    if missing_optional:
        print(f"[~] Optional columns absent (detectors will adapt): {missing_optional}")


def load_logs(log_file):
    print(f"[+] Loading: {log_file}")
    df = pd.read_csv(log_file).fillna("")

    # Normalise PID column if comma-formatted ("34,940" → 34940)
    if "process.pid" in df.columns:
        df["process.pid"] = (
            df["process.pid"].astype(str)
            .str.replace(",", "", regex=False)
            .pipe(pd.to_numeric, errors="coerce")
            .fillna(0)
            .astype(int)
        )

    validate_columns(df)
    print(f"[+] Loaded {len(df)} events")
    return df


def build_statistics(raw_df, alerts_df, queue_df, chains_df):
    stats = {
        "Generated":          str(datetime.now()),
        "Total Events":       len(raw_df),
        "Unique Alerts":      len(alerts_df),
        "Investigation Queue": len(queue_df),
        "Attack Chains":      len(chains_df),
    }
    if not alerts_df.empty:
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            stats[sev] = int((alerts_df["Severity"] == sev).sum())

        # Highlight the highest-risk process
        top = alerts_df.iloc[0] if not alerts_df.empty else None
        if top is not None:
            stats["Top Risk Process"] = (
                str(top.get("Process", "")).split("\\")[-1]
                + f"  (score={top.get('Risk Score',0)})"
            )

        # C2 IPs
        c2 = (
            alerts_df[
                alerts_df["Detection Type"].str.contains("Beaconing|External", na=False)
            ]["Destination IP"]
            .replace("", pd.NA).dropna().unique().tolist()
        )
        if c2:
            stats["Suspicious C2 IPs"] = " | ".join(str(x) for x in c2[:6])

        # Persistence
        persist_count = int(
            alerts_df["Detection Type"].str.contains("Persistence", na=False).sum()
        )
        if persist_count:
            stats["Persistence Detections"] = persist_count

    return stats


def print_statistics(stats):
    print("\n")
    print("=" * 60)
    print("  Execution Summary")
    print("=" * 60)
    for k, v in stats.items():
        print(f"  {k:<28}: {v}")
    print("=" * 60)


def parse_args():
    parser = argparse.ArgumentParser(description="Anomaly Hunter v2.1")
    parser.add_argument(
        "--log", default=DEFAULT_LOG_FILE,
        help=f"Path to log CSV (default: {DEFAULT_LOG_FILE})"
    )
    return parser.parse_args()


def main():
    banner()
    args = parse_args()

    # ── Load ─────────────────────────────────────────────────────────
    raw_df = load_logs(args.log)

    # ── Detection ────────────────────────────────────────────────────
    print("[+] Running detectors …")
    alerts_df = run_all_detectors(raw_df)
    print(f"[+] Raw alerts generated: {len(alerts_df)}")

    # ── Scoring + Aggregation ────────────────────────────────────────
    print("[+] Running scoring engine …")
    alerts_df = enrich_alerts(alerts_df)
    print(f"[+] Unique enriched alerts: {len(alerts_df)}")

    queue_df = get_investigation_queue(alerts_df)
    print(f"[+] Investigation queue: {len(queue_df)} items")

    # ── Attack Chains ────────────────────────────────────────────────
    print("[+] Building attack chains …")
    chains_df   = build_attack_chain_report(alerts_df, raw_df)
    timeline_df = build_attack_timeline(alerts_df)

    # ── Kill Chain Reconstruction (NEW) ─────────────────────────────
    print("[+] Reconstructing kill chain …")
    kill_chain_df = build_full_kill_chain(alerts_df, raw_df)
    if not kill_chain_df.empty:
        print(f"[+] Kill-chain stages identified: {len(kill_chain_df)}")

    # ── Reports ──────────────────────────────────────────────────────
    print("[+] Generating reports …")
    generated = generate_all_reports(
        alerts_df, queue_df, chains_df, timeline_df,
        kill_chain_df=kill_chain_df
    )

    # ── Summary ──────────────────────────────────────────────────────
    stats = build_statistics(raw_df, alerts_df, queue_df, chains_df)
    print_statistics(stats)

    print("\nGenerated Files:")
    for name, path in generated.items():
        print(f"  {name:<22} -> {path}")

    print("\n[+] Analysis Complete\n")


if __name__ == "__main__":
    main()
