"""
detection/detectors.py  -  Anomaly Hunter Universal
=====================================================
Universal detection engine.

All detectors consume the NORMALISED DataFrame (with _internal columns)
via the SchemaMap — zero hardcoded field names.

Detectors gracefully skip when a required field is absent in the log.
"""

import re
import math
import logging
import ipaddress
from collections import Counter

import pandas as pd

from schema_mapper import SchemaMap, rget
from ah_config.config import (
    LOLBINS, USER_FOLDER_PATHS, LEGIT_EXEC_PREFIXES,
    DOWNLOAD_KEYWORDS, DOWNLOAD_EXECUTE_KEYWORDS,
    ENCODED_PAYLOAD_KEYWORDS, POWERSHELL_INDICATORS,
    DEFENSE_EVASION_KEYWORDS, PERSISTENCE_PATTERNS,
    PERSISTENCE_CMD_PATTERNS, HIGH_VALUE_TARGETS,
    SUSPICIOUS_PARENT_CHILD, RECON_DOMAINS,
    KNOWN_GOOD_IPS, KNOWN_GOOD_DOMAINS, KNOWN_GOOD_PROCESSES,
    KNOWN_GOOD_IP_PREFIXES, RISK_SCORES,
    RARE_PROCESS_THRESHOLD, RARE_PARENT_CHILD_THRESHOLD,
    DOMAIN_ENTROPY_THRESHOLD, LONG_DOMAIN_THRESHOLD,
    MITRE_MAPPING, MITRE_NAMES,
)

log = logging.getLogger("AnomalyHunter.Detectors")

# ── Helpers ───────────────────────────────────────────────────────────────────

def norm(value: str) -> str:
    return str(value).lower().replace("/", "\\").split("\\")[-1].strip()

def shannon_entropy(text: str) -> float:
    text = str(text)
    if not text: return 0.0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probs)

def is_external_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(str(ip))
        return not addr.is_private and not addr.is_loopback
    except Exception:
        return False

def is_known_good_ip(ip: str) -> bool:
    if ip in KNOWN_GOOD_IPS: return True
    return any(str(ip).startswith(pfx) for pfx in KNOWN_GOOD_IP_PREFIXES)

def is_known_good_domain(domain: str) -> bool:
    d = domain.lower()
    return any(d == g or d.endswith("." + g) for g in KNOWN_GOOD_DOMAINS)

def get_mitre(process_name: str) -> tuple:
    name = norm(process_name)
    tid = MITRE_MAPPING.get(name, "")
    return tid, MITRE_NAMES.get(tid, "")

def make_alert(row: pd.Series, sm: SchemaMap,
               det_type: str, score: int, reason: str,
               mitre_id: str = "", mitre_name: str = "") -> dict:
    proc = rget(row, "_process", sm)
    if not mitre_id:
        mitre_id, mitre_name = get_mitre(proc)
    return {
        "Timestamp":            rget(row, "_ts", sm),
        "Process":              proc,
        "Parent Process":       rget(row, "_parent", sm),
        "Command Line":         rget(row, "_cmdline", sm),
        "Detection Type":       det_type,
        "Risk Score":           score,
        "Investigation Reason": reason,
        "Source IP":            rget(row, "_src_ip", sm),
        "Destination IP":       rget(row, "_dst_ip", sm),
        "Registry Path":        rget(row, "_registry", sm),
        "File Path":            rget(row, "_filepath", sm),
        "DNS Query":            rget(row, "_domain", sm),
        "Event Action":         rget(row, "_event_action", sm),
        "PID":                  rget(row, "_pid", sm),
        "Username":             rget(row, "_username", sm),
        "Hostname":             rget(row, "_hostname", sm),
        "Severity Field":       rget(row, "_severity", sm),
        "Message":              rget(row, "_message", sm),
        "MITRE Technique":      mitre_id,
        "MITRE Name":           mitre_name,
    }

# ── Detectors ─────────────────────────────────────────────────────────────────

def detect_rare_processes(df: pd.DataFrame, sm: SchemaMap) -> list:
    if "_proc_name" not in df.columns: return []
    alerts = []
    counts = Counter(df["_proc_name"])
    for _, row in df.iterrows():
        pname = row["_proc_name"]
        if pname in KNOWN_GOOD_PROCESSES or not pname: continue
        if counts[pname] <= RARE_PROCESS_THRESHOLD:
            alerts.append(make_alert(row, sm, "Rare Process",
                RISK_SCORES["RARE_PROCESS"],
                f"Process seen only {counts[pname]} time(s): {pname}"))
    return alerts

def detect_rare_parent_child(df: pd.DataFrame, sm: SchemaMap) -> list:
    if "_proc_name" not in df.columns or "_parent_name" not in df.columns: return []
    alerts = []
    pairs = df["_parent_name"].astype(str) + "->" + df["_proc_name"].astype(str)
    counts = Counter(pairs)
    for i, (_, row) in enumerate(df.iterrows()):
        pair = pairs.iloc[i]
        if row["_proc_name"] in KNOWN_GOOD_PROCESSES or not row["_proc_name"]: continue
        if counts[pair] <= RARE_PARENT_CHILD_THRESHOLD:
            alerts.append(make_alert(row, sm, "Rare Parent-Child",
                RISK_SCORES["RARE_PARENT_CHILD"],
                f"Rare process pair: {pair}"))
    return alerts

def detect_lolbins(df: pd.DataFrame, sm: SchemaMap) -> list:
    if "_proc_name" not in df.columns: return []
    alerts = []
    for _, row in df.iterrows():
        if row["_proc_name"] in LOLBINS:
            tid, tname = get_mitre(row["_proc_name"])
            alerts.append(make_alert(row, sm, "LOLBin Abuse",
                RISK_SCORES["LOLBIN"],
                f"Living-off-the-land binary: {row['_proc_name']}",
                tid, tname))
    return alerts

def detect_powershell_payloads(df: pd.DataFrame, sm: SchemaMap) -> list:
    if not sm.has("_cmdline"): return []
    alerts = []
    for _, row in df.iterrows():
        cmd = rget(row, "_cmdline", sm).lower()
        if any(x in cmd for x in POWERSHELL_INDICATORS):
            alerts.append(make_alert(row, sm, "PowerShell Payload",
                RISK_SCORES["POWERSHELL_PAYLOAD"],
                "Suspicious PowerShell keyword in command",
                "T1059.001", "PowerShell"))
    return alerts

def detect_download_execute(df: pd.DataFrame, sm: SchemaMap) -> list:
    if not sm.has("_cmdline"): return []
    alerts = []
    for _, row in df.iterrows():
        cmd = rget(row, "_cmdline", sm).lower()
        if any(x in cmd for x in DOWNLOAD_KEYWORDS) and \
           any(x in cmd for x in DOWNLOAD_EXECUTE_KEYWORDS):
            alerts.append(make_alert(row, sm, "Download Execute",
                RISK_SCORES["DOWNLOAD_EXECUTE"],
                "Download-then-execute pattern detected",
                "T1105", "Ingress Tool Transfer"))
    return alerts

def detect_encoded_payloads(df: pd.DataFrame, sm: SchemaMap) -> list:
    if not sm.has("_cmdline"): return []
    alerts = []
    for _, row in df.iterrows():
        cmd = rget(row, "_cmdline", sm).lower()
        if any(x in cmd for x in ENCODED_PAYLOAD_KEYWORDS):
            alerts.append(make_alert(row, sm, "Encoded Payload",
                RISK_SCORES["ENCODED_PAYLOAD"],
                "Base64 / encoded command detected",
                "T1027", "Obfuscated Files or Information"))
    return alerts

def detect_defense_evasion(df: pd.DataFrame, sm: SchemaMap) -> list:
    if not sm.has("_cmdline"): return []
    alerts = []
    for _, row in df.iterrows():
        cmd = rget(row, "_cmdline", sm).lower()
        for kw in DEFENSE_EVASION_KEYWORDS:
            if kw in cmd:
                alerts.append(make_alert(row, sm, "Defense Evasion",
                    RISK_SCORES["DEFENSE_EVASION"],
                    f"Defense evasion keyword: '{kw}'",
                    "T1562.001", "Disable or Modify Tools"))
                break
    return alerts

def detect_malware_staging(df: pd.DataFrame, sm: SchemaMap) -> list:
    if not sm.has("_process"): return []
    alerts = []
    for _, row in df.iterrows():
        path = rget(row, "_process", sm).lower()
        if not path: continue
        if any(path.startswith(p) for p in LEGIT_EXEC_PREFIXES): continue
        fp = rget(row, "_filepath", sm).lower()
        target = path + " " + fp
        if any(x in target for x in USER_FOLDER_PATHS):
            alerts.append(make_alert(row, sm, "Malware Staging",
                RISK_SCORES["USER_FOLDER_EXECUTION"],
                f"Execution from user-writable path: {path}"))
    return alerts

def detect_persistence(df: pd.DataFrame, sm: SchemaMap) -> list:
    if not sm.has("_registry"): return []
    alerts = []
    for _, row in df.iterrows():
        reg = rget(row, "_registry", sm).lower()
        if not reg: continue
        if any(re.search(p, reg) for p in PERSISTENCE_PATTERNS):
            alerts.append(make_alert(row, sm, "Persistence",
                RISK_SCORES["PERSISTENCE"],
                f"Persistence registry path: {reg}",
                "T1547.001", "Registry Run Keys / Startup Folder"))
    return alerts

def detect_persistence_cmdline(df: pd.DataFrame, sm: SchemaMap) -> list:
    if not sm.has("_cmdline"): return []
    alerts = []
    for _, row in df.iterrows():
        cmd = rget(row, "_cmdline", sm).lower()
        if not cmd: continue
        for pattern in PERSISTENCE_CMD_PATTERNS:
            if re.search(pattern, cmd):
                alerts.append(make_alert(row, sm, "Persistence via Cmdline",
                    RISK_SCORES["PERSISTENCE"],
                    f"Persistence command: {cmd[:150]}",
                    "T1547.001", "Registry Run Keys / Startup Folder"))
                break
    return alerts

def detect_process_injection(df: pd.DataFrame, sm: SchemaMap) -> list:
    alerts = []
    for _, row in df.iterrows():
        target_explicit = norm(rget(row, "_target_process", sm))
        src = norm(rget(row, "_process", sm))
        if target_explicit and target_explicit in HIGH_VALUE_TARGETS:
            alerts.append(make_alert(row, sm, "Process Injection",
                RISK_SCORES["PROCESS_INJECTION"],
                f"{src} accessing high-value target: {target_explicit}",
                "T1055", "Process Injection"))
            continue
        child  = row.get("_proc_name", "")
        parent = row.get("_parent_name", "")
        if (child in HIGH_VALUE_TARGETS and parent and
                parent not in KNOWN_GOOD_PROCESSES and
                parent not in {"", "-", "services.exe", "wininit.exe"}):
            alerts.append(make_alert(row, sm, "Process Injection",
                RISK_SCORES["PROCESS_INJECTION"],
                f"High-value process {child} has unusual parent: {parent}",
                "T1055", "Process Injection"))
    return alerts

def detect_suspicious_parent_child(df: pd.DataFrame, sm: SchemaMap) -> list:
    if "_proc_name" not in df.columns or "_parent_name" not in df.columns: return []
    alerts = []
    for _, row in df.iterrows():
        pair = (row["_parent_name"], row["_proc_name"])
        if pair in SUSPICIOUS_PARENT_CHILD:
            tid, tname = get_mitre(row["_proc_name"])
            alerts.append(make_alert(row, sm, "Suspicious Parent-Child",
                RISK_SCORES["SUSPICIOUS_PARENT_CHILD"],
                f"Suspicious spawn: {pair[0]} → {pair[1]}",
                tid or "T1059", tname or "Command and Scripting Interpreter"))
    return alerts

def detect_svchost_script_spawn(df: pd.DataFrame, sm: SchemaMap) -> list:
    if "_proc_name" not in df.columns: return []
    script_engines = {"wscript.exe","cscript.exe","mshta.exe","powershell.exe","cmd.exe"}
    alerts = []
    for _, row in df.iterrows():
        if row.get("_parent_name","") == "svchost.exe" and row["_proc_name"] in script_engines:
            cmd = rget(row, "_cmdline", sm).lower()
            if any(p in cmd for p in ["\\users\\","\\public\\","\\temp\\","\\appdata\\"]):
                tid, tname = get_mitre(row["_proc_name"])
                alerts.append(make_alert(row, sm, "Svchost Script Spawn",
                    RISK_SCORES["SVCHOST_CHILD_SPAWN"],
                    f"svchost spawned script engine with suspicious path: {cmd[:120]}",
                    tid, tname))
    return alerts

def detect_recon_tools(df: pd.DataFrame, sm: SchemaMap) -> list:
    alerts = []
    for _, row in df.iterrows():
        domain = rget(row, "_domain", sm).lower()
        proc   = row.get("_proc_name", "")
        cmd    = rget(row, "_cmdline", sm).lower()
        if domain in RECON_DOMAINS:
            alerts.append(make_alert(row, sm, "Recon / IP Discovery",
                RISK_SCORES["RECON_TOOL"],
                f"Recon DNS query: {domain}",
                "T1016", "System Network Config Discovery"))
        elif proc in {"curl.exe","wget.exe"} and any(rd in cmd for rd in RECON_DOMAINS):
            alerts.append(make_alert(row, sm, "Recon / IP Discovery",
                RISK_SCORES["RECON_TOOL"],
                f"Recon tool query: {cmd[:120]}",
                "T1016", "System Network Config Discovery"))
    return alerts

def detect_edr_rule(df: pd.DataFrame, sm: SchemaMap) -> list:
    if not sm.has("_event_action"): return []
    alerts = []
    for _, row in df.iterrows():
        action = rget(row, "_event_action", sm).lower()
        if action in ("rule_detection", "alert", "blocked", "malware_detected",
                      "threat_detected", "intrusion_detected"):
            proc = rget(row, "_process", sm)
            cmd  = rget(row, "_cmdline", sm)
            alerts.append(make_alert(row, sm, "EDR Rule Detection",
                RISK_SCORES["RULE_DETECTION"],
                f"Security rule fired on: {norm(proc)} | {str(cmd)[:100]}"))
    return alerts

def detect_external_communication(df: pd.DataFrame, sm: SchemaMap) -> list:
    if not sm.has("_dst_ip"): return []
    alerts = []
    for _, row in df.iterrows():
        dst = rget(row, "_dst_ip", sm)
        if dst in ("-","") or is_known_good_ip(dst): continue
        if row.get("_proc_name","") in KNOWN_GOOD_PROCESSES: continue
        if is_external_ip(dst):
            alerts.append(make_alert(row, sm, "External Communication",
                RISK_SCORES["EXTERNAL_COMMUNICATION"],
                f"Outbound to external IP: {dst}"))
    return alerts

def detect_dns_entropy(df: pd.DataFrame, sm: SchemaMap) -> list:
    if not sm.has("_domain"): return []
    alerts = []
    for _, row in df.iterrows():
        domain = rget(row, "_domain", sm)
        if not domain or is_known_good_domain(domain): continue
        e = shannon_entropy(domain)
        if e >= DOMAIN_ENTROPY_THRESHOLD or len(domain) >= LONG_DOMAIN_THRESHOLD:
            alerts.append(make_alert(row, sm, "DNS Anomaly",
                RISK_SCORES["DNS_ANOMALY"],
                f"High-entropy domain: {domain} (entropy={round(e,2)}, len={len(domain)})"))
    return alerts

def detect_network_outliers(df: pd.DataFrame, sm: SchemaMap) -> list:
    if not sm.has("_dst_ip") or "_proc_name" not in df.columns: return []
    alerts = []
    dst_col = sm.col("_dst_ip")
    analysis = df[~df["_proc_name"].isin(KNOWN_GOOD_PROCESSES)]
    if analysis.empty: return []
    counts = analysis.groupby("_proc_name")[dst_col].nunique()
    if len(counts) < 2: return []
    std = counts.std()
    if not std or std == 0: return []
    threshold = counts.mean() + std
    noisy = set(counts[counts > threshold].index)
    for _, row in df.iterrows():
        if row["_proc_name"] in noisy:
            alerts.append(make_alert(row, sm, "Network Outlier",
                RISK_SCORES["NETWORK_OUTLIER"],
                f"High distinct destinations for {row['_proc_name']}"))
    return alerts

def detect_high_severity_log(df: pd.DataFrame, sm: SchemaMap) -> list:
    """Detect log entries with high native severity/priority."""
    if not sm.has("_severity"): return []
    alerts = []
    high_sev_values = {
        "critical","high","error","err","fatal","emergency","emerg",
        "alert","severe","5","4","3","2","1","0",
    }
    for _, row in df.iterrows():
        sev = rget(row, "_severity", sm).lower().strip()
        if sev in high_sev_values:
            msg = rget(row, "_message", sm)
            alerts.append(make_alert(row, sm, "High Severity Log",
                RISK_SCORES.get("RULE_DETECTION", 30),
                f"Native severity={sev}: {msg[:120]}"))
    return alerts

def detect_brute_force(df: pd.DataFrame, sm: SchemaMap) -> list:
    """Detect brute force: same source IP with many failed auth events."""
    if not sm.has("_src_ip") or not sm.has("_event_action"): return []
    alerts = []
    fail_keywords = {"failed","failure","invalid","denied","bad credentials",
                     "authentication failure","logon failure","4625"}
    src_col = sm.col("_src_ip")
    act_col = sm.col("_event_action")
    fails = df[df[act_col].str.lower().apply(
        lambda x: any(k in x for k in fail_keywords)
    )]
    if fails.empty: return []
    counts = fails.groupby(src_col).size()
    threshold = 10
    abusers = set(counts[counts >= threshold].index)
    seen = set()
    for _, row in fails.iterrows():
        src = rget(row, "_src_ip", sm)
        if src in abusers and src not in seen:
            seen.add(src)
            alerts.append(make_alert(row, sm, "Brute Force / Auth Failure",
                RISK_SCORES.get("EXTERNAL_COMMUNICATION", 20),
                f"Source IP {src} has {counts.get(src,0)} failed auth events",
                "T1110", "Brute Force"))
    return alerts

def detect_suspicious_user_agent(df: pd.DataFrame, sm: SchemaMap) -> list:
    """Detect suspicious/tool user-agents in web/proxy logs."""
    if not sm.has("_cmdline"): return []
    suspicious_ua = [
        "sqlmap", "nikto", "nmap", "masscan", "zgrab",
        "python-requests", "go-http-client", "curl/",
        "nuclei", "dirbuster", "gobuster", "wfuzz",
        "metasploit", "msfconsole", "havoc", "cobalt strike",
        "powershell", "wget/", "libwww-perl",
    ]
    alerts = []
    for _, row in df.iterrows():
        ua = rget(row, "_cmdline", sm).lower()
        for tool in suspicious_ua:
            if tool in ua:
                alerts.append(make_alert(row, sm, "Suspicious User-Agent / Tool",
                    RISK_SCORES.get("RECON_TOOL", 25),
                    f"Tool signature in user-agent/command: {tool}",
                    "T1595", "Active Scanning"))
                break
    return alerts

# ── Orchestrator ──────────────────────────────────────────────────────────────

DETECTOR_REGISTRY = [
    ("EDR Rule Detection",         detect_edr_rule),
    ("High Severity Log",          detect_high_severity_log),
    ("Rare Process",               detect_rare_processes),
    ("Rare Parent-Child",          detect_rare_parent_child),
    ("LOLBin Abuse",               detect_lolbins),
    ("PowerShell Payload",         detect_powershell_payloads),
    ("Download Execute",           detect_download_execute),
    ("Encoded Payload",            detect_encoded_payloads),
    ("Defense Evasion",            detect_defense_evasion),
    ("Malware Staging",            detect_malware_staging),
    ("Persistence",                detect_persistence),
    ("Persistence via Cmdline",    detect_persistence_cmdline),
    ("Process Injection",          detect_process_injection),
    ("Suspicious Parent-Child",    detect_suspicious_parent_child),
    ("Svchost Script Spawn",       detect_svchost_script_spawn),
    ("Recon / IP Discovery",       detect_recon_tools),
    ("External Communication",     detect_external_communication),
    ("DNS Anomaly",                detect_dns_entropy),
    ("Network Outlier",            detect_network_outliers),
    ("Brute Force / Auth Failure", detect_brute_force),
    ("Suspicious User-Agent",      detect_suspicious_user_agent),
]


def run_all_detectors(df: pd.DataFrame,
                      schema_map: SchemaMap) -> pd.DataFrame:
    all_alerts = []
    for name, fn in DETECTOR_REGISTRY:
        try:
            results = fn(df, schema_map)
            all_alerts.extend(results)
            if results:
                log.debug("  %-35s  %d hits", name, len(results))
        except Exception as e:
            log.error("Detector '%s' failed: %s", name, e, exc_info=True)

    log.info("Raw alerts: %d from %d detectors", len(all_alerts), len(DETECTOR_REGISTRY))
    return pd.DataFrame(all_alerts) if all_alerts else pd.DataFrame()
