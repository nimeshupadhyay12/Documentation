"""
intelligence/ioc_extractor.py  -  Anomaly Hunter Universal
============================================================
Universal IOC extraction — field names resolved via schema_map.
"""
import re, logging
from urllib.parse import urlparse
import pandas as pd
from schema_mapper import SchemaMap, rget
from config.config import KNOWN_GOOD_IPS, KNOWN_GOOD_DOMAINS, KNOWN_GOOD_PROCESSES, KNOWN_GOOD_IP_PREFIXES, USER_FOLDER_PATHS

log = logging.getLogger("AnomalyHunter.IOCExtractor")

RE_IPV4   = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
RE_MD5    = re.compile(r'\b[0-9a-fA-F]{32}\b')
RE_SHA256 = re.compile(r'\b[0-9a-fA-F]{64}\b')
RE_URL    = re.compile(r'https?://[^\s\'"<>]{5,}')

import ipaddress
def _is_ext(ip):
    try:
        a = ipaddress.ip_address(str(ip))
        return not a.is_private and not a.is_loopback
    except: return False

def _is_kg_ip(ip):
    if ip in KNOWN_GOOD_IPS: return True
    return any(str(ip).startswith(p) for p in KNOWN_GOOD_IP_PREFIXES)

def _is_kg_domain(d):
    d = d.lower()
    return any(d == g or d.endswith("."+g) for g in KNOWN_GOOD_DOMAINS)

def _is_susp_path(path):
    return any(p in path.lower() for p in USER_FOLDER_PATHS)

def _ioc(ioc_type, value, source, context, timestamp, risk="Unknown"):
    return {"IOC Type":ioc_type,"IOC Value":value,"Source":source,
            "Context":context,"Timestamp":timestamp,"Risk":risk}

def extract_all_iocs(df: pd.DataFrame, schema_map: SchemaMap) -> pd.DataFrame:
    seen  = set()
    iocs  = []

    def add(ioc_type, value, source, context, ts, risk="Unknown"):
        key = (ioc_type, value)
        if key not in seen and value and value not in ("-",""):
            seen.add(key)
            iocs.append(_ioc(ioc_type, value, source, context, ts, risk))

    for _, row in df.iterrows():
        ts   = rget(row, "_ts", schema_map)
        proc = rget(row, "_process", schema_map)
        ctx  = f"Process: {proc[:60]}" if proc else ""

        # IPs
        for field in ("_dst_ip","_src_ip"):
            ip = rget(row, field, schema_map)
            if ip and _is_ext(ip) and not _is_kg_ip(ip):
                add("IP", ip, schema_map.col(field) or field, ctx, ts)

        # IPs inside command lines
        cmd = rget(row, "_cmdline", schema_map)
        for ip in RE_IPV4.findall(cmd):
            if _is_ext(ip) and not _is_kg_ip(ip):
                add("IP", ip, "command_line", ctx, ts)

        # Domain
        domain = rget(row, "_domain", schema_map)
        if domain and not _is_kg_domain(domain):
            add("Domain", domain, schema_map.col("_domain") or "_domain", ctx, ts)

        # URLs in command
        for url in RE_URL.findall(cmd):
            try:
                dom = urlparse(url).netloc.split(":")[0].lower()
                if dom and not _is_kg_domain(dom):
                    add("URL", url[:200], "command_line", ctx, ts)
            except: pass

        # Registry
        reg = rget(row, "_registry", schema_map)
        if reg:
            suspicious_keys = [r"currentversion\\run",r"winlogon",r"userinit",r"policies\\explorer"]
            if any(re.search(p, reg.lower()) for p in suspicious_keys):
                add("Registry Key", reg, schema_map.col("_registry") or "_registry", ctx, ts, "High")

        # File paths
        for field in ("_filepath","_process"):
            path = rget(row, field, schema_map)
            if path and _is_susp_path(path):
                add("File Path", path, schema_map.col(field) or field, ctx, ts, "Medium")

        # Hashes
        for field in ("_hash","_cmdline","_filepath"):
            text = rget(row, field, schema_map)
            for h in RE_SHA256.findall(text) + RE_MD5.findall(text):
                add("Hash", h, field, ctx, ts)

        # Suspicious process
        pname = row.get("_proc_name","")
        if proc and pname and pname not in KNOWN_GOOD_PROCESSES and _is_susp_path(proc):
            parent = rget(row, "_parent", schema_map)
            add("Suspicious Process", proc, "_process",
                f"Parent: {parent[:60]}", ts, "High")

        # Username anomalies (privileged accounts)
        user = rget(row, "_username", schema_map).lower()
        if user and any(x in user for x in ["admin","root","system","administrator","sa "]):
            add("Privileged User Activity", user, "_username",
                f"Action: {rget(row, '_event_action', schema_map)}", ts, "Medium")

    if not iocs:
        return pd.DataFrame(columns=["IOC Type","IOC Value","Source","Context","Timestamp","Risk"])

    result = pd.DataFrame(iocs).drop_duplicates(subset=["IOC Type","IOC Value"])
    result = result.sort_values(["IOC Type","Timestamp"])
    log.info("IOC extraction: %d unique indicators", len(result))
    return result
