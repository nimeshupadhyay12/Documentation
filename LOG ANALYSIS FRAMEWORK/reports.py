"""
reports.py
Anomaly Hunter v2

Report Generation Engine
"""

import pandas as pd
from config import OUTPUT_FILES


def save_anomaly_report(alerts_df):

    if alerts_df.empty:
        pd.DataFrame().to_csv(
            OUTPUT_FILES["anomaly_report"],
            index=False
        )
        return

    alerts_df.sort_values(
        by="Risk Score",
        ascending=False
    ).to_csv(
        OUTPUT_FILES["anomaly_report"],
        index=False
    )


def save_investigation_queue(queue_df):

    if queue_df.empty:
        pd.DataFrame().to_csv(
            OUTPUT_FILES["investigation_queue"],
            index=False
        )
        return

    queue_df.sort_values(
        by="Risk Score",
        ascending=False
    ).to_csv(
        OUTPUT_FILES["investigation_queue"],
        index=False
    )


def save_attack_chain_report(chain_df):

    if chain_df.empty:
        pd.DataFrame().to_csv(
            OUTPUT_FILES["attack_chain"],
            index=False
        )
        return

    chain_df.sort_values(
        by="Chain Risk Score",
        ascending=False
    ).to_csv(
        OUTPUT_FILES["attack_chain"],
        index=False
    )


def save_timeline(timeline_df):

    if timeline_df.empty:
        pd.DataFrame().to_csv(
            OUTPUT_FILES["timeline"],
            index=False
        )
        return

    timeline_df.sort_values(
        by="Timestamp"
    ).to_csv(
        OUTPUT_FILES["timeline"],
        index=False
    )


def build_executive_summary(

        alerts_df,
        queue_df,
        chain_df):

    metrics = []

    metrics.append([
        "Total Alerts",
        len(alerts_df)
    ])

    metrics.append([
        "Investigation Queue",
        len(queue_df)
    ])

    metrics.append([
        "Attack Chains",
        len(chain_df)
    ])

    if not alerts_df.empty:

        metrics.append([
            "Critical Alerts",
            int(
                (
                    alerts_df["Severity"]
                    == "CRITICAL"
                ).sum()
            )
        ])

        metrics.append([
            "High Alerts",
            int(
                (
                    alerts_df["Severity"]
                    == "HIGH"
                ).sum()
            )
        ])

        metrics.append([
            "Persistence Events",
            int(
                (
                    alerts_df["Detection Type"]
                    == "Persistence"
                ).sum()
            )
        ])

        metrics.append([
            "Process Injection Events",
            int(
                (
                    alerts_df["Detection Type"]
                    == "Process Injection"
                ).sum()
            )
        ])

        metrics.append([
            "Download Execute Events",
            int(
                (
                    alerts_df["Detection Type"]
                    == "Download Execute"
                ).sum()
            )
        ])

        metrics.append([
            "LOLBin Events",
            int(
                (
                    alerts_df["Detection Type"]
                    == "LOLBin Abuse"
                ).sum()
            )
        ])

        top_processes = (

            alerts_df["Process"]
            .value_counts()
            .head(5)
            .index
            .tolist()

        )

        metrics.append([
            "Top Suspicious Processes",
            " | ".join(
                map(str, top_processes)
            )
        ])

    return pd.DataFrame(
        metrics,
        columns=[
            "Metric",
            "Value"
        ]
    )


def save_executive_summary(summary_df):

    summary_df.to_csv(
        OUTPUT_FILES["executive_summary"],
        index=False
    )


def generate_all_reports(

        alerts_df,
        queue_df,
        chain_df,
        timeline_df):

    save_anomaly_report(
        alerts_df
    )

    save_investigation_queue(
        queue_df
    )

    save_attack_chain_report(
        chain_df
    )

    save_timeline(
        timeline_df
    )

    summary = build_executive_summary(
        alerts_df,
        queue_df,
        chain_df
    )

    save_executive_summary(
        summary
    )

    return {
        "anomaly_report":
            OUTPUT_FILES["anomaly_report"],

        "investigation_queue":
            OUTPUT_FILES["investigation_queue"],

        "attack_chain":
            OUTPUT_FILES["attack_chain"],

        "timeline":
            OUTPUT_FILES["timeline"],

        "executive_summary":
            OUTPUT_FILES["executive_summary"]
    }


