"""
anomaly_hunter_v2.py

Main Orchestration Engine
"""

import pandas as pd
from datetime import datetime

from config import DEFAULT_LOG_FILE

from detectors import run_all_detectors

from scoring import (
    enrich_alerts,
    get_investigation_queue
)

from attack_chain import (
    build_attack_chain_report,
    build_attack_timeline
)

from reports import (
    generate_all_reports
)


def banner():

    print("=" * 60)
    print("Anomaly Hunter v2")
    print("Advanced Threat Hunting Platform")
    print("=" * 60)


def validate_columns(df):

    required = [

        "@timestamp",

        "process.executable",

        "process.parent.executable",

        "process.command_line",

        "source.ip",

        "destination.ip",

        "dns.question.name",

        "registry.path"
    ]

    missing = []

    for col in required:

        if col not in df.columns:

            missing.append(col)

    if missing:

        raise Exception(
            f"Missing columns: {missing}"
        )


def load_logs(log_file):

    print(f"[+] Loading: {log_file}")

    df = pd.read_csv(
        log_file
    ).fillna("")

    validate_columns(df)

    print(
        f"[+] Loaded {len(df)} events"
    )

    return df


def build_statistics(

        raw_df,
        alerts_df,
        queue_df,
        chains_df):

    stats = {

        "Generated":
            str(datetime.now()),

        "Total Events":
            len(raw_df),

        "Total Alerts":
            len(alerts_df),

        "Investigation Queue":
            len(queue_df),

        "Attack Chains":
            len(chains_df)
    }

    if not alerts_df.empty:

        stats["Critical"] = int(
            (
                alerts_df["Severity"]
                == "CRITICAL"
            ).sum()
        )

        stats["High"] = int(
            (
                alerts_df["Severity"]
                == "HIGH"
            ).sum()
        )

        stats["Medium"] = int(
            (
                alerts_df["Severity"]
                == "MEDIUM"
            ).sum()
        )

    return stats


def print_statistics(stats):

    print("\n")

    print("=" * 60)

    print("Execution Summary")

    print("=" * 60)

    for k, v in stats.items():

        print(
            f"{k}: {v}"
        )

    print("=" * 60)


def main():

    banner()

    # -----------------------------------
    # Load Logs
    # -----------------------------------

    raw_df = load_logs(
        DEFAULT_LOG_FILE
    )

    # -----------------------------------
    # Detection Phase
    # -----------------------------------

    print(
        "[+] Running detectors"
    )

    alerts_df = run_all_detectors(
        raw_df
    )

    print(
        f"[+] Alerts Generated: {len(alerts_df)}"
    )

    # -----------------------------------
    # Scoring Phase
    # -----------------------------------

    print(
        "[+] Running scoring engine"
    )

    alerts_df = enrich_alerts(
        alerts_df
    )

    queue_df = (
        get_investigation_queue(
            alerts_df
        )
    )

    # -----------------------------------
    # Attack Chain Phase
    # -----------------------------------

    print(
        "[+] Building attack chains"
    )

    chains_df = (
        build_attack_chain_report(
            alerts_df,
            raw_df
        )
    )

    timeline_df = (
        build_attack_timeline(
            alerts_df
        )
    )

    # -----------------------------------
    # Report Generation
    # -----------------------------------

    print(
        "[+] Generating reports"
    )

    generated = (
        generate_all_reports(
            alerts_df,
            queue_df,
            chains_df,
            timeline_df
        )
    )

    # -----------------------------------
    # Statistics
    # -----------------------------------

    stats = build_statistics(

        raw_df,

        alerts_df,

        queue_df,

        chains_df
    )

    print_statistics(
        stats
    )

    print("\nGenerated Files:\n")

    for name, file in generated.items():

        print(
            f"{name} -> {file}"
        )

    print(
        "\n[+] Analysis Complete"
    )


if __name__ == "__main__":
    main()

