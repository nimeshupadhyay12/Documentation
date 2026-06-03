
"""detectors.py
Anomaly Hunter v2
"""

import re
import math
import ipaddress
import pandas as pd
from collections import Counter

from config import *


def normalize_process_name(value):
    return str(value).lower().split("\\")[-1].strip()


def entropy(text):
    text = str(text)
    if not text:
        return 0.0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probs)


def is_external_ip(ip):
    try:
        return not ipaddress.ip_address(str(ip)).is_private
    except Exception:
        return False


def create_alert(row, detection_type, score, reason):
    return {
        "Timestamp": row.get("@timestamp", ""),
        "Process": row.get("process.executable", ""),
        "Parent Process": row.get("process.parent.executable", ""),
        "Detection Type": detection_type,
        "Risk Score": score,
        "Investigation Reason": reason,
        "Source IP": row.get("source.ip", ""),
        "Destination IP": row.get("destination.ip", "")
    }


def detect_rare_processes(df):
    alerts = []
    counts = Counter(df["process_name"])
    for _, row in df.iterrows():
        if counts[row["process_name"]] <= RARE_PROCESS_THRESHOLD:
            alerts.append(create_alert(
                row, "Rare Process",
                RISK_SCORES["RARE_PROCESS"],
                "Rare process execution"
            ))
    return alerts


def detect_rare_parent_child(df):
    alerts = []
    pairs = (
        df["parent_name"].astype(str)
        + "->" +
        df["process_name"].astype(str)
    )
    counts = Counter(pairs)

    for idx, row in df.iterrows():
        pair = pairs.iloc[idx]
        if counts[pair] <= RARE_PARENT_CHILD_THRESHOLD:
            alerts.append(create_alert(
                row, "Rare Parent Child",
                RISK_SCORES["RARE_PARENT_CHILD"],
                pair
            ))
    return alerts


def detect_lolbins(df):
    alerts = []
    for _, row in df.iterrows():
        if row["process_name"] in LOLBINS:
            alerts.append(create_alert(
                row, "LOLBin Abuse",
                RISK_SCORES["LOLBIN"],
                "Known LOLBin executed"
            ))
    return alerts


def detect_powershell_payloads(df):
    alerts = []
    for _, row in df.iterrows():
        cmd = str(row.get("process.command_line", "")).lower()
        if any(x in cmd for x in POWERSHELL_INDICATORS):
            alerts.append(create_alert(
                row, "PowerShell Payload",
                RISK_SCORES["POWERSHELL_PAYLOAD"],
                "Suspicious PowerShell activity"
            ))
    return alerts


def detect_download_execute(df):
    alerts = []
    for _, row in df.iterrows():
        cmd = str(row.get("process.command_line", "")).lower()

        download = any(x in cmd for x in DOWNLOAD_KEYWORDS)
        execute = any(x in cmd for x in DOWNLOAD_EXECUTE_KEYWORDS)

        if download and execute:
            alerts.append(create_alert(
                row, "Download Execute",
                RISK_SCORES["DOWNLOAD_EXECUTE"],
                "Download and execution pattern"
            ))
    return alerts


def detect_encoded_payloads(df):
    alerts = []
    for _, row in df.iterrows():
        cmd = str(row.get("process.command_line", "")).lower()

        if any(x in cmd for x in ENCODED_PAYLOAD_KEYWORDS):
            alerts.append(create_alert(
                row, "Encoded Payload",
                RISK_SCORES["ENCODED_PAYLOAD"],
                "Encoded or Base64 payload"
            ))
    return alerts


def detect_malware_staging(df):
    alerts = []
    for _, row in df.iterrows():
        target = (
            str(row.get("file.path", "")) + " " +
            str(row.get("process.executable", ""))
        ).lower()

        if any(x in target for x in USER_FOLDER_PATHS):
            alerts.append(create_alert(
                row, "Malware Staging",
                RISK_SCORES["MALWARE_STAGING"],
                "Execution from user-controlled path"
            ))
    return alerts


def detect_persistence(df):
    alerts = []
    for _, row in df.iterrows():
        reg = str(row.get("registry.path", "")).lower()

        if any(re.search(p, reg) for p in PERSISTENCE_PATTERNS):
            alerts.append(create_alert(
                row, "Persistence",
                RISK_SCORES["PERSISTENCE"],
                "Persistence indicator detected"
            ))
    return alerts


def detect_process_injection(df):
    alerts = []

    for _, row in df.iterrows():
        src = normalize_process_name(
            row.get("process.executable", "")
        )

        target = normalize_process_name(
            row.get("Target.process.executable", "")
        )

        if target and target in HIGH_VALUE_TARGETS:
            alerts.append(create_alert(
                row, "Process Injection",
                RISK_SCORES["PROCESS_INJECTION"],
                f"{src} -> {target}"
            ))

    return alerts


def detect_external_communication(df):
    alerts = []

    for _, row in df.iterrows():
        dst = str(row.get("destination.ip", ""))

        if is_external_ip(dst):
            alerts.append(create_alert(
                row, "External Communication",
                RISK_SCORES["EXTERNAL_COMMUNICATION"],
                dst
            ))

    return alerts


def detect_dns_entropy(df):
    alerts = []

    for _, row in df.iterrows():
        domain = str(row.get("dns.question.name", ""))

        if not domain:
            continue

        e = entropy(domain)

        if e >= DOMAIN_ENTROPY_THRESHOLD or len(domain) >= LONG_DOMAIN_THRESHOLD:
            alerts.append(create_alert(
                row, "DNS Anomaly",
                RISK_SCORES["DNS_ANOMALY"],
                f"Entropy={round(e,2)}"
            ))

    return alerts


def detect_network_outliers(df):
    alerts = []

    if "destination.ip" not in df.columns:
        return alerts

    counts = df.groupby("process_name")["destination.ip"].nunique()

    if len(counts) == 0:
        return alerts

    threshold = counts.mean() + counts.std()

    noisy = set(counts[counts > threshold].index)

    for _, row in df.iterrows():
        if row["process_name"] in noisy:
            alerts.append(create_alert(
                row, "Network Outlier",
                RISK_SCORES["NETWORK_OUTLIER"],
                "High destination count"
            ))

    return alerts


def run_all_detectors(df):

    df = df.fillna("").copy()

    df["process_name"] = df["process.executable"].apply(
        normalize_process_name
    )

    df["parent_name"] = df["process.parent.executable"].apply(
        normalize_process_name
    )

    alerts = []

    detectors = [
        detect_rare_processes,
        detect_rare_parent_child,
        detect_lolbins,
        detect_powershell_payloads,
        detect_download_execute,
        detect_encoded_payloads,
        detect_malware_staging,
        detect_persistence,
        detect_process_injection,
        detect_external_communication,
        detect_dns_entropy,
        detect_network_outliers
    ]

    for detector in detectors:
        alerts.extend(detector(df))

    return pd.DataFrame(alerts)
