"""
attack_chain.py
Anomaly Hunter v2

Attack Chain Reconstruction Engine
"""

import pandas as pd
from collections import defaultdict


def normalize_process(value):
    return str(value).lower().split("\\")[-1].strip()


def build_process_lineage(df):

    chains = []

    for _, row in df.iterrows():

        parent = normalize_process(
            row.get("process.parent.executable", "")
        )

        child = normalize_process(
            row.get("process.executable", "")
        )

        if parent and child:

            chains.append({
                "Timestamp": row.get("@timestamp", ""),
                "Parent Process": parent,
                "Child Process": child,
                "Relationship": f"{parent} -> {child}"
            })

    return pd.DataFrame(chains)


def build_suspicious_chains(alerts_df):

    if alerts_df.empty:
        return pd.DataFrame()

    chain_rows = []

    grouped = alerts_df.groupby(
        ["Process", "Parent Process"]
    )

    chain_id = 1

    for (process, parent), group in grouped:

        risk_score = int(
            group["Risk Score"].sum()
        )

        detections = sorted(
            group["Detection Type"]
            .dropna()
            .unique()
            .tolist()
        )

        chain_rows.append({

            "Chain ID":
                f"AC-{chain_id:04d}",

            "Root Process":
                parent,

            "Child Process":
                process,

            "Chain Risk Score":
                min(risk_score, 100),

            "Detection Count":
                len(group),

            "Detections":
                " | ".join(detections),

            "Chain Summary":
                f"{parent} -> {process}"
        })

        chain_id += 1

    chains = pd.DataFrame(chain_rows)

    if not chains.empty:

        chains = chains.sort_values(
            by="Chain Risk Score",
            ascending=False
        )

    return chains


def build_attack_chain_report(

        alerts_df,
        raw_df):

    lineage = build_process_lineage(
        raw_df
    )

    chains = build_suspicious_chains(
        alerts_df
    )

    if chains.empty:
        return chains

    attack_rows = []

    for _, row in chains.iterrows():

        attack_rows.append({

            "Chain ID":
                row["Chain ID"],

            "Root Process":
                row["Root Process"],

            "Child Process":
                row["Child Process"],

            "Chain Risk Score":
                row["Chain Risk Score"],

            "Detection Count":
                row["Detection Count"],

            "Detections":
                row["Detections"],

            "Chain Summary":
                row["Chain Summary"]
        })

    return pd.DataFrame(
        attack_rows
    )


def correlate_download_execute(

        raw_df):

    findings = []

    for _, row in raw_df.iterrows():

        cmd = str(
            row.get(
                "process.command_line",
                ""
            )
        ).lower()

        download_keywords = [

            "invoke-webrequest",
            "downloadstring",
            "downloadfile",
            "curl",
            "wget",
            "bitsadmin",
            "certutil"
        ]

        execute_keywords = [

            "start-process",
            "iex",
            "invoke-expression"
        ]

        if any(
                x in cmd
                for x in download_keywords
        ):

            if any(
                    x in cmd
                    for x in execute_keywords
            ):

                findings.append({

                    "Timestamp":
                        row.get(
                            "@timestamp",
                            ""
                        ),

                    "Process":
                        row.get(
                            "process.executable",
                            ""
                        ),

                    "Attack Step":
                        "Download Execute",

                    "Risk":
                        "Critical"
                })

    return pd.DataFrame(
        findings
    )


def correlate_persistence(

        raw_df):

    findings = []

    for _, row in raw_df.iterrows():

        reg = str(
            row.get(
                "registry.path",
                ""
            )
        ).lower()

        persistence = [

            "run",

            "runonce",

            "startup",

            "services",

            "tasks"
        ]

        if any(
                x in reg
                for x in persistence
        ):

            findings.append({

                "Timestamp":
                    row.get(
                        "@timestamp",
                        ""
                    ),

                "Process":
                    row.get(
                        "process.executable",
                        ""
                    ),

                "Attack Step":
                    "Persistence",

                "Risk":
                    "High"
            })

    return pd.DataFrame(
        findings
    )


def build_attack_timeline(

        alerts_df):

    if alerts_df.empty:
        return pd.DataFrame()

    timeline = alerts_df.copy()

    keep = [

        "Timestamp",

        "Process",

        "Parent Process",

        "Detection Type",

        "Risk Score"
    ]

    keep = [
        x for x in keep
        if x in timeline.columns
    ]

    timeline = timeline[keep]

    return timeline.sort_values(
        by="Timestamp"
    )


def get_top_attack_chains(

        chain_df,
        top_n=20):

    if chain_df.empty:
        return chain_df

    return chain_df.nlargest(
        top_n,
        "Chain Risk Score"
    )


def build_chain_metrics(

        chain_df):

    metrics = []

    metrics.append([
        "Attack Chains Found",
        len(chain_df)
    ])

    if not chain_df.empty:

        metrics.append([
            "Highest Chain Score",
            int(
                chain_df[
                    "Chain Risk Score"
                ].max()
            )
        ])

        metrics.append([
            "Chains Above 80",
            int(
                (
                    chain_df[
                        "Chain Risk Score"
                    ] >= 80
                ).sum()
            )
        ])

    return pd.DataFrame(
        metrics,
        columns=[
            "Metric",
            "Value"
        ]
    )

