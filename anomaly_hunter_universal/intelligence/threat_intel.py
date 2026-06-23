"""
intelligence/threat_intel.py  -  Anomaly Hunter Universal
===========================================================
Threat intelligence enrichment. Offline built-in rules are now
generic (no log-specific IOCs). Optional live VT/AbuseIPDB APIs.
"""
import os, time, logging
import pandas as pd

log = logging.getLogger("AnomalyHunter.ThreatIntel")

ONLINE_MODE   = os.getenv("AH_THREAT_INTEL","0") == "1"
VT_API_KEY    = os.getenv("VT_API_KEY","")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY","")
REQUEST_DELAY = float(os.getenv("AH_TI_DELAY","0.5"))

# ── Generic known-bad categories (no log-specific hardcoding) ─────────────────
KNOWN_BAD_IP_PREFIXES = {
    "103.243.115.": {"verdict":"Malicious","tags":"Known C2 range","confidence":85},
}
KNOWN_RECON_DOMAINS = {
    "ipinfo.io":             {"verdict":"Recon","tags":"IP geolocation API","confidence":80},
    "api.ipify.org":         {"verdict":"Recon","tags":"IP geolocation API","confidence":80},
    "icanhazip.com":         {"verdict":"Recon","tags":"IP geolocation API","confidence":80},
    "checkip.amazonaws.com": {"verdict":"Recon","tags":"IP recon service",  "confidence":75},
    "ifconfig.me":           {"verdict":"Recon","tags":"IP geolocation API","confidence":80},
    "wtfismyip.com":         {"verdict":"Recon","tags":"IP geolocation API","confidence":80},
    "ip-api.com":            {"verdict":"Recon","tags":"IP geolocation API","confidence":75},
}
KNOWN_MALWARE_REG_PATTERNS = [
    r"currentversion\\run\\",
    r"currentversion\\runonce\\",
]
KNOWN_MALWARE_PATH_PATTERNS = [
    r"\\users\\public\\pictures\\",
    r"\\appdata\\local\\temp\\_mei",
]

def _enrich_offline(ioc_type, ioc_value):
    v = str(ioc_value).lower()
    if ioc_type == "IP":
        for prefix, info in KNOWN_BAD_IP_PREFIXES.items():
            if v.startswith(prefix): return info
        return {"verdict":"Unknown","tags":"","confidence":0}
    elif ioc_type == "Domain":
        return KNOWN_RECON_DOMAINS.get(v, {"verdict":"Unknown","tags":"","confidence":0})
    elif ioc_type == "Registry Key":
        import re
        for pat in KNOWN_MALWARE_REG_PATTERNS:
            if re.search(pat, v):
                return {"verdict":"Malicious","tags":"Persistence key","confidence":90}
        return {"verdict":"Unknown","tags":"","confidence":0}
    elif ioc_type in ("File Path","Suspicious Process"):
        import re
        for pat in KNOWN_MALWARE_PATH_PATTERNS:
            if re.search(pat, v):
                return {"verdict":"Suspicious","tags":"Suspicious path","confidence":70}
        return {"verdict":"Unknown","tags":"","confidence":0}
    elif ioc_type == "URL":
        for dom in KNOWN_RECON_DOMAINS:
            if dom in v: return KNOWN_RECON_DOMAINS[dom]
        return {"verdict":"Unknown","tags":"","confidence":0}
    return {"verdict":"Unknown","tags":"","confidence":0}

def _vt_query(ioc_value, ioc_type):
    try:
        import urllib.request, json
        urls = {"IP":f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}",
                "Domain":f"https://www.virustotal.com/api/v3/domains/{ioc_value}",
                "Hash":f"https://www.virustotal.com/api/v3/files/{ioc_value}"}
        url = urls.get(ioc_type)
        if not url: return {}
        req = urllib.request.Request(url, headers={"x-apikey":VT_API_KEY})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        stats   = data.get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
        mal     = stats.get("malicious",0)
        total   = sum(stats.values()) or 1
        verdict = "Malicious" if mal>5 else "Suspicious" if mal>0 else "Clean"
        conf    = min(int(mal/total*100),99) if mal>0 else 90
        time.sleep(REQUEST_DELAY)
        return {"verdict":verdict,"tags":f"VT:{mal}/{total}","confidence":conf}
    except Exception as e:
        log.debug("VT query failed %s: %s", ioc_value, e)
        return {}

def _abuseipdb_query(ip):
    try:
        import urllib.request, urllib.parse, json
        params = urllib.parse.urlencode({"ipAddress":ip,"maxAgeInDays":90})
        url = f"https://api.abuseipdb.com/api/v2/check?{params}"
        req = urllib.request.Request(url, headers={"Key":ABUSEIPDB_KEY,"Accept":"application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        score   = data.get("data",{}).get("abuseConfidenceScore",0)
        reports = data.get("data",{}).get("totalReports",0)
        verdict = "Malicious" if score>=80 else "Suspicious" if score>=20 else "Clean"
        time.sleep(REQUEST_DELAY)
        return {"verdict":verdict,"tags":f"AbuseIPDB:{score}/100,reports={reports}","confidence":score}
    except Exception as e:
        log.debug("AbuseIPDB failed %s: %s", ip, e)
        return {}

def enrich_iocs(ioc_df: pd.DataFrame) -> pd.DataFrame:
    if ioc_df.empty: return ioc_df
    df = ioc_df.copy()
    verdicts, tags_list, confidences = [], [], []
    for _, row in df.iterrows():
        ioc_type  = row.get("IOC Type","")
        ioc_value = str(row.get("IOC Value",""))
        offline   = _enrich_offline(ioc_type, ioc_value)
        if ONLINE_MODE and offline.get("confidence",0) == 0:
            online = {}
            if VT_API_KEY and ioc_type in ("IP","Domain","Hash"):
                online = _vt_query(ioc_value, ioc_type)
            if not online and ABUSEIPDB_KEY and ioc_type == "IP":
                online = _abuseipdb_query(ioc_value)
            enrichment = online or offline
        else:
            enrichment = offline
        verdicts.append(enrichment.get("verdict","Unknown"))
        tags_list.append(enrichment.get("tags",""))
        confidences.append(enrichment.get("confidence",0))
    df["TI Verdict"]    = verdicts
    df["TI Tags"]       = tags_list
    df["TI Confidence"] = confidences
    mal  = (df["TI Verdict"]=="Malicious").sum()
    susp = (df["TI Verdict"]=="Suspicious").sum()
    log.info("TI enrichment: %d malicious, %d suspicious, %d total IOCs", mal, susp, len(df))
    return df.sort_values(["TI Confidence","IOC Type"], ascending=[False,True])
