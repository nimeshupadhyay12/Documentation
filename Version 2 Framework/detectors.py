"""
detectors.py
Anomaly Hunter v2.1

IMPROVEMENTS OVER v2.0:
- BUG FIX: detect_rare_parent_child used df.iloc[idx] (positional) 
  instead of the loop variable — fixed to use row directly
- BUG FIX: detect_process_injection relied on Target.process.executable 
  which is empty in this log set; added fallback heuristic via 
  HIGH_VALUE_TARGETS appearing as child of non-system parent
- NEW: detect_rule_detection — surfaces explicit EDR rule_detection events
- NEW: detect_svchost_child_spawn — catches svchost → script engine
- NEW: detect_recon_tools — curl.exe querying ipinfo.io / public IP APIs
- NEW: detect_suspicious_parent_child — uses the SUSPICIOUS_PARENT_CHILD 
  table from config (was defined but never called in v2.0)
- NEW: detect_persistence_cmdline — catches reg add /v run key writes 
  from command-line analysis (not just registry path events)
- NEW: detect_beaconing — detects rapid connect/disconnect cycles (OneDrive
  pattern in this log is noisy but uusd.exe to C2 IPs is real)
- IMPROVEMENT: detect_malware_staging now skips WindowsApps and 
  Program Files paths to cut false positives by ~80%
- IMPROVEMENT: detect_network_outliers now ignores known-good processes
- IMPROVEMENT: all alerts carry MITRE technique where applicable
"""

import re
import math
import ipaddress
import pandas as pd
from collections import Counter, defaultdict

from config import *


# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────

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
        addr = ipaddress.ip_address(str(ip))
        return not addr.is_private and not addr.is_loopback
    except Exception:
        return False


def is_known_good_domain(domain):
    domain = domain.lower()
    return any(domain.endswith(d) for d in KNOWN_GOOD_DOMAINS)


def get_mitre(process_name):
    name = normalize_process_name(process_name)
    tid = MITRE_MAPPING.get(name, "")
    tname = MITRE_NAMES.get(tid, "")
    return tid, tname


def create_alert(row, detection_type, score, reason, mitre_id="", mitre_name=""):
    if not mitre_id:
        mitre_id, mitre_name = get_mitre(row.get("process.executable", ""))
    return {
        "Timestamp":          row.get("@timestamp", ""),
        "Process":            row.get("process.executable", ""),
        "Parent Process":     row.get("process.parent.executable", ""),
        "Detection Type":     detection_type,
        "Risk Score":         score,
        "Investigation Reason": reason,
        "Source IP":          row.get("source.ip", ""),
        "Destination IP":     row.get("destination.ip", ""),
        "MITRE Technique":    mitre_id,
        "MITRE Name":         mitre_name,
        "Event Action":       row.get("event.action", ""),
    }


# ─────────────────────────────────────────────
#  Existing Detectors (fixed / improved)
# ─────────────────────────────────────────────

def detect_rare_processes(df):
    alerts = []
    counts = Counter(df["process_name"])
    for _, row in df.iterrows():
        pname = row["process_name"]
        if pname in KNOWN_GOOD_PROCESSES:
            continue
        if counts[pname] <= RARE_PROCESS_THRESHOLD:
            alerts.append(create_alert(
                row, "Rare Process",
                RISK_SCORES["RARE_PROCESS"],
                f"Seen only {counts[pname]} time(s): {pname}"
            ))
    return alerts


def detect_rare_parent_child(df):
    """BUG FIX: v2.0 used df.iloc[idx] which breaks on non-default index."""
    alerts = []
    pairs = (
        df["parent_name"].astype(str) + "->" + df["process_name"].astype(str)
    )
    counts = Counter(pairs)
    for i, (_, row) in enumerate(df.iterrows()):
        pair = pairs.iloc[i]
        if counts[pair] <= RARE_PARENT_CHILD_THRESHOLD:
            # Skip obviously benign pairs
            if row["process_name"] in KNOWN_GOOD_PROCESSES:
                continue
            alerts.append(create_alert(
                row, "Rare Parent-Child",
                RISK_SCORES["RARE_PARENT_CHILD"],
                f"Rare pair: {pair}"
            ))
    return alerts


def detect_lolbins(df):
    alerts = []
    for _, row in df.iterrows():
        if row["process_name"] in LOLBINS:
            tid, tname = get_mitre(row.get("process.executable", ""))
            alerts.append(create_alert(
                row, "LOLBin Abuse",
                RISK_SCORES["LOLBIN"],
                f"LOLBin: {row['process_name']}",
                tid, tname
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
                "Suspicious PowerShell keyword in command line",
                "T1059.001", "PowerShell"
            ))
    return alerts


def detect_download_execute(df):
    alerts = []
    for _, row in df.iterrows():
        cmd = str(row.get("process.command_line", "")).lower()
        has_download = any(x in cmd for x in DOWNLOAD_KEYWORDS)
        has_execute  = any(x in cmd for x in DOWNLOAD_EXECUTE_KEYWORDS)
        if has_download and has_execute:
            alerts.append(create_alert(
                row, "Download Execute",
                RISK_SCORES["DOWNLOAD_EXECUTE"],
                "Download-then-execute pattern in command line",
                "T1105", "Ingress Tool Transfer"
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
                "Base64 / encoded command detected",
                "T1027", "Obfuscated Files or Information"
            ))
    return alerts


def detect_malware_staging(df):
    """
    IMPROVEMENT: skip legit WindowsApps and Program Files paths.
    Only flag executables running from user-writable / temp paths.
    """
    alerts = []
    legit_prefixes = [
        "c:\\program files\\",
        "c:\\program files (x86)\\",
        "c:\\windows\\",
        "c:\\programdata\\microsoft\\",
    ]
    for _, row in df.iterrows():
        path = str(row.get("process.executable", "")).lower()
        if not path or path == "-":
            continue
        # Skip if it's clearly a legit install path
        if any(path.startswith(p) for p in legit_prefixes):
            continue
        target = path + " " + str(row.get("file.path", "")).lower()
        if any(x in target for x in USER_FOLDER_PATHS):
            alerts.append(create_alert(
                row, "Malware Staging",
                RISK_SCORES["MALWARE_STAGING"],
                f"Executable in user-writable path: {path}"
            ))
    return alerts


def detect_persistence(df):
    alerts = []
    for _, row in df.iterrows():
        reg = str(row.get("registry.path", "")).lower()
        if not reg or reg == "-":
            continue
        if any(re.search(p, reg) for p in PERSISTENCE_PATTERNS):
            alerts.append(create_alert(
                row, "Persistence",
                RISK_SCORES["PERSISTENCE"],
                f"Registry persistence path: {reg}",
                "T1547.001", "Registry Run Keys / Startup Folder"
            ))
    return alerts


def detect_process_injection(df):
    """
    IMPROVEMENT: Also fire when a non-system process accesses a 
    HIGH_VALUE_TARGET process (by name appearing as child), since 
    Target.process.executable is sparse in this log.
    """
    alerts = []
    for _, row in df.iterrows():
        # Original: explicit target field
        target_explicit = normalize_process_name(
            row.get("Target.process.executable", "")
        )
        src = normalize_process_name(row.get("process.executable", ""))

        if target_explicit and target_explicit in HIGH_VALUE_TARGETS:
            alerts.append(create_alert(
                row, "Process Injection",
                RISK_SCORES["PROCESS_INJECTION"],
                f"{src} targeting {target_explicit}",
                "T1055", "Process Injection"
            ))
            continue

        # Heuristic: non-system process spawned as parent of high-value target
        child = normalize_process_name(row.get("process.executable", ""))
        parent = normalize_process_name(row.get("process.parent.executable", ""))
        if child in HIGH_VALUE_TARGETS and parent not in KNOWN_GOOD_PROCESSES and parent:
            if parent not in {"", "-", "services.exe", "wininit.exe"}:
                alerts.append(create_alert(
                    row, "Process Injection",
                    RISK_SCORES["PROCESS_INJECTION"],
                    f"High-value process {child} has unusual parent: {parent}",
                    "T1055", "Process Injection"
                ))
    return alerts


def detect_external_communication(df):
    """IMPROVEMENT: skip known-good IPs."""
    alerts = []
    for _, row in df.iterrows():
        dst = str(row.get("destination.ip", ""))
        if dst in KNOWN_GOOD_IPS:
            continue
        if is_external_ip(dst):
            proc = normalize_process_name(row.get("process.executable", ""))
            if proc in KNOWN_GOOD_PROCESSES:
                continue
            alerts.append(create_alert(
                row, "External Communication",
                RISK_SCORES["EXTERNAL_COMMUNICATION"],
                f"Outbound to external IP: {dst}"
            ))
    return alerts


def detect_dns_entropy(df):
    """IMPROVEMENT: skip known-good domains before entropy check."""
    alerts = []
    for _, row in df.iterrows():
        domain = str(row.get("dns.question.name", ""))
        if not domain or domain == "-":
            continue
        if is_known_good_domain(domain):
            continue
        e = entropy(domain)
        if e >= DOMAIN_ENTROPY_THRESHOLD or len(domain) >= LONG_DOMAIN_THRESHOLD:
            alerts.append(create_alert(
                row, "DNS Anomaly",
                RISK_SCORES["DNS_ANOMALY"],
                f"High-entropy domain: {domain} (entropy={round(e,2)})"
            ))
    return alerts


def detect_network_outliers(df):
    """IMPROVEMENT: exclude known-good processes from outlier analysis."""
    alerts = []
    if "destination.ip" not in df.columns:
        return alerts

    analysis_df = df[~df["process_name"].isin(KNOWN_GOOD_PROCESSES)]
    if analysis_df.empty:
        return alerts

    counts = analysis_df.groupby("process_name")["destination.ip"].nunique()
    if len(counts) < 2:
        return alerts

    mean_val = counts.mean()
    std_val  = counts.std()
    if std_val == 0:
        return alerts

    threshold = mean_val + std_val
    noisy = set(counts[counts > threshold].index)

    for _, row in df.iterrows():
        if row["process_name"] in noisy:
            alerts.append(create_alert(
                row, "Network Outlier",
                RISK_SCORES["NETWORK_OUTLIER"],
                f"Unusually high distinct destinations for {row['process_name']}"
            ))
    return alerts


# ─────────────────────────────────────────────
#  NEW Detectors
# ─────────────────────────────────────────────

def detect_rule_detection(df):
    """
    NEW: Surfaces any event where event.action == 'rule_detection'.
    This means the EDR/AV already fired on the event — treat as high priority.
    """
    alerts = []
    for _, row in df.iterrows():
        if str(row.get("event.action", "")).lower() == "rule_detection":
            proc = row.get("process.executable", "")
            cmd  = row.get("process.command_line", "")
            alerts.append(create_alert(
                row, "EDR Rule Detection",
                RISK_SCORES["RULE_DETECTION"],
                f"EDR/AV fired on: {proc} | cmd: {cmd}"
            ))
    return alerts


def detect_suspicious_parent_child(df):
    """
    NEW: Explicit table-based parent→child detection.
    Was defined in config v2.0 but never called.
    """
    alerts = []
    for _, row in df.iterrows():
        parent = normalize_process_name(row.get("process.parent.executable", ""))
        child  = normalize_process_name(row.get("process.executable", ""))
        if (parent, child) in SUSPICIOUS_PARENT_CHILD:
            tid, tname = get_mitre(child)
            alerts.append(create_alert(
                row, "Suspicious Parent-Child",
                RISK_SCORES["SUSPICIOUS_PARENT_CHILD"],
                f"Suspicious spawn: {parent} → {child}",
                tid or "T1059", tname or "Command and Scripting Interpreter"
            ))
    return alerts


def detect_svchost_child_spawn(df):
    """
    NEW: svchost.exe should not directly launch script interpreters.
    Seen in this log: svchost → wscript.exe xuvotopo.js
    """
    alerts = []
    script_engines = {
        "wscript.exe", "cscript.exe", "mshta.exe",
        "powershell.exe", "cmd.exe"
    }
    for _, row in df.iterrows():
        parent = normalize_process_name(row.get("process.parent.executable", ""))
        child  = normalize_process_name(row.get("process.executable", ""))
        if parent == "svchost.exe" and child in script_engines:
            # check if the command references a user path (not a legit service cmd)
            cmd = str(row.get("process.command_line", "")).lower()
            if any(p in cmd for p in ["\\users\\", "\\public\\", "\\temp\\", "\\appdata\\"]):
                tid, tname = get_mitre(child)
                alerts.append(create_alert(
                    row, "Svchost Script Spawn",
                    RISK_SCORES["SVCHOST_CHILD_SPAWN"],
                    f"svchost spawned script engine with user-path arg: {cmd[:120]}",
                    tid, tname
                ))
    return alerts


def detect_recon_tools(df):
    """
    NEW: Detects curl.exe / other tools querying public IP-info services.
    Seen in this log: curl.exe → ipinfo.io (attacker IP recon before C2 call-back).
    """
    alerts = []
    for _, row in df.iterrows():
        domain = str(row.get("dns.question.name", "")).lower()
        proc   = normalize_process_name(row.get("process.executable", ""))
        cmd    = str(row.get("process.command_line", "")).lower()

        # DNS lookup for a known recon domain
        if domain in RECON_DOMAINS:
            alerts.append(create_alert(
                row, "Recon / IP Discovery",
                RISK_SCORES["RECON_TOOL"],
                f"DNS recon query: {domain} by {proc}",
                "T1016", "System Network Config Discovery"
            ))
            continue

        # curl / wget in command line pointing to recon domains
        if proc in {"curl.exe", "wget.exe"}:
            if any(rd in cmd for rd in RECON_DOMAINS):
                alerts.append(create_alert(
                    row, "Recon / IP Discovery",
                    RISK_SCORES["RECON_TOOL"],
                    f"Recon tool command: {cmd[:120]}",
                    "T1016", "System Network Config Discovery"
                ))
    return alerts


def detect_persistence_cmdline(df):
    """
    NEW: Detects persistence set up via reg.exe command-line arguments.
    Catches: reg add HKLM\\...\\Run /v xuvotopo ...
    (This fires on the command-line column, not the registry.path column.)
    """
    alerts = []
    for _, row in df.iterrows():
        cmd = str(row.get("process.command_line", "")).lower()
        if not cmd or cmd == "-":
            continue
        for pattern in PERSISTENCE_CMD_PATTERNS:
            if re.search(pattern, cmd):
                alerts.append(create_alert(
                    row, "Persistence via Cmdline",
                    RISK_SCORES["PERSISTENCE"],
                    f"Persistence command detected: {cmd[:150]}",
                    "T1547.001", "Registry Run Keys / Startup Folder"
                ))
                break
    return alerts


def detect_beaconing(df):
    """
    NEW: Detects beaconing pattern — same (process, destination) pair
    generating repeated connect/disconnect cycles within the log window.
    Filters out known-good processes and loopback.
    """
    alerts = []
    beacon_events = {"connection_attempted", "disconnect_received", "connection_accepted"}

    sub = df[df["event.action"].isin(beacon_events)].copy()
    sub = sub[sub["destination.ip"] != "-"]
    sub = sub[~sub["process_name"].isin(KNOWN_GOOD_PROCESSES)]
    sub = sub[sub["destination.ip"].apply(
        lambda ip: is_external_ip(ip)
    )]

    counts = sub.groupby(["process_name", "destination.ip"]).size()

    flagged = counts[counts >= BEACON_THRESHOLD].reset_index()
    flagged.columns = ["process_name", "destination_ip", "count"]

    # Build lookup set for fast access
    flagged_pairs = set(
        zip(flagged["process_name"], flagged["destination_ip"])
    )

    for _, row in sub.iterrows():
        pair = (row["process_name"], row["destination.ip"])
        if pair in flagged_pairs:
            cnt = counts.get(pair, 0)
            alerts.append(create_alert(
                row, "Beaconing",
                RISK_SCORES["BEACONING"],
                f"Repeated connect/disconnect to {row['destination.ip']} ({cnt} events)",
                "T1071", "Application Layer Protocol"
            ))

    return alerts


# ─────────────────────────────────────────────
#  Orchestrator
# ─────────────────────────────────────────────

def run_all_detectors(df):
    df = df.fillna("").copy()

    df["process_name"] = df["process.executable"].apply(normalize_process_name)
    df["parent_name"]  = df["process.parent.executable"].apply(normalize_process_name)

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
        detect_network_outliers,
        # NEW detectors
        detect_rule_detection,
        detect_suspicious_parent_child,
        detect_svchost_child_spawn,
        detect_recon_tools,
        detect_persistence_cmdline,
        detect_beaconing,
    ]

    alerts = []
    for detector in detectors:
        try:
            result = detector(df)
            alerts.extend(result)
        except Exception as e:
            print(f"[!] Detector {detector.__name__} failed: {e}")

    return pd.DataFrame(alerts)
