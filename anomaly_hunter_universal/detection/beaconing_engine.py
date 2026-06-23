"""
detection/beaconing_engine.py  -  Anomaly Hunter Universal
============================================================
Universal beaconing detection — works with any log that has
a destination IP (or domain) field and timestamps.
"""
import logging, re
import numpy as np
import pandas as pd
from schema_mapper import SchemaMap, rget
from config.config import KNOWN_GOOD_PROCESSES, KNOWN_GOOD_IP_PREFIXES, KNOWN_GOOD_IPS, RISK_SCORES

log = logging.getLogger("AnomalyHunter.BeaconingEngine")
BEACON_EVENTS = {"connection_attempted","disconnect_received","connection_accepted",
                 "connect","network_connection","3"}   # 3 = Sysmon Network Connect
MIN_EVENTS = 5
MAX_CV     = 0.5

def _is_external(ip):
    import ipaddress
    try:
        addr = ipaddress.ip_address(str(ip))
        return not addr.is_private and not addr.is_loopback
    except: return False

def _is_known_good(ip):
    if ip in KNOWN_GOOD_IPS: return True
    return any(str(ip).startswith(p) for p in KNOWN_GOOD_IP_PREFIXES)

def _parse_ts(series):
    def _fix(s):
        s2 = re.sub(r'\s*@\s*', ' ', str(s))
        return pd.to_datetime(s2, errors='coerce')
    return series.apply(_fix)

def analyse_beaconing(df: pd.DataFrame, schema_map: SchemaMap) -> pd.DataFrame:
    if not schema_map.has("_dst_ip") or not schema_map.has("_ts"):
        return pd.DataFrame()

    dst_col = schema_map.col("_dst_ip")
    ts_col  = schema_map.col("_ts")
    act_col = schema_map.col("_event_action") or ""

    work = df.copy()
    work["_ts_parsed"] = _parse_ts(work[ts_col])

    # Filter: network events only (if event action column exists)
    if act_col and act_col in work.columns:
        mask = work[act_col].str.lower().isin(BEACON_EVENTS)
        work = work[mask | ~work[act_col].notna()]   # include rows where action is empty

    work = work[work[dst_col].astype(str).str.strip().isin(["","-"]) == False]
    work = work[work[dst_col].apply(lambda x: _is_external(x) and not _is_known_good(x))]
    work = work[work["_proc_name"].apply(lambda x: x not in KNOWN_GOOD_PROCESSES)]
    work = work.dropna(subset=["_ts_parsed"])

    if work.empty: return pd.DataFrame()

    findings = []
    for (proc, dst), grp in work.groupby(["_proc_name", dst_col]):
        if len(grp) < MIN_EVENTS: continue
        times     = grp["_ts_parsed"].sort_values()
        intervals = times.diff().dt.total_seconds().dropna()
        if intervals.empty or intervals.mean() == 0: continue
        mean_iv = intervals.mean()
        std_iv  = intervals.std()
        cv      = std_iv / mean_iv if mean_iv > 0 else 999
        beacon_score = max(0, round((1 - min(cv, 1)) * 100))
        if cv <= MAX_CV or len(grp) >= 10:
            sample = grp.iloc[0]
            findings.append({
                "Process":          rget(sample, "_process", schema_map) or proc,
                "Parent Process":   rget(sample, "_parent", schema_map),
                "Destination IP":   dst,
                "Event Count":      len(grp),
                "Mean Interval(s)": round(mean_iv, 2),
                "Std Interval(s)":  round(float(std_iv), 2) if not np.isnan(float(std_iv)) else 0,
                "CV":               round(cv, 3),
                "Beacon Score":     beacon_score,
                "Risk Score":       RISK_SCORES["BEACONING"],
                "Detection Type":   "Beaconing",
                "Timestamp":        str(grp["_ts_parsed"].min()),
                "Investigation Reason":
                    f"Beacon pattern to {dst}: {len(grp)} events, "
                    f"mean={round(mean_iv,1)}s, CV={round(cv,3)}",
                "MITRE Technique":  "T1071",
                "MITRE Name":       "Application Layer Protocol",
                "Event Action":     "beaconing_analysis",
                "Source IP":        "", "Registry Path": "",
                "File Path":        "", "DNS Query":     "",
                "PID":              "", "Username":      "",
                "Hostname":         "", "Severity Field": "",
                "Message":          "", "Command Line":  "",
            })

    result = pd.DataFrame(findings)
    if not result.empty:
        result = result.sort_values("Beacon Score", ascending=False)
        log.info("Beaconing: %d suspicious pairs found", len(result))
    return result
