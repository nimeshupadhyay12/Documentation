"""
detection/sigma_engine.py  -  Anomaly Hunter Universal
========================================================
Universal Sigma-compatible rule engine using schema_map.
All field references go through rget() — no hardcoded column names.
"""
import os, re, logging
from pathlib import Path
import pandas as pd
from schema_mapper import SchemaMap, rget
from ah_config.config import RISK_SCORES, SIGMA_RULES_DIR

log = logging.getLogger("AnomalyHunter.SigmaEngine")

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

LEVEL_SCORE = {"critical":45,"high":35,"medium":25,"low":15,"informational":10}

BUILTIN_RULES = [
    {"id":"SIG-001","title":"Office Application Spawning Shell","level":"critical",
     "mitre":"T1059.003","description":"Office app spawning a shell interpreter",
     "detection":{"parent_contains":["winword.exe","excel.exe","outlook.exe","powerpnt.exe"],
                  "process_contains":["cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe"]}},
    {"id":"SIG-002","title":"Windows Defender Exclusion Added","level":"high",
     "mitre":"T1562.001","description":"PowerShell adding a Defender exclusion",
     "detection":{"cmdline_contains":["add-mppreference -exclusionpath"]}},
    {"id":"SIG-003","title":"Registry Run Key Persistence","level":"critical",
     "mitre":"T1547.001","description":"reg.exe adding a Run key entry",
     "detection":{"cmdline_contains":["reg add","\\currentversion\\run"]}},
    {"id":"SIG-004","title":"Suspicious Scheduled Task Creation","level":"high",
     "mitre":"T1053.005","description":"schtasks creating a task",
     "detection":{"process_contains":["schtasks.exe"],"cmdline_contains":["/create"]}},
    {"id":"SIG-005","title":"PowerShell Download Cradle","level":"high",
     "mitre":"T1105","description":"PowerShell downloading a remote file",
     "detection":{"cmdline_contains":["invoke-webrequest"]}},
    {"id":"SIG-006","title":"IP Geolocation Recon","level":"high",
     "mitre":"T1016","description":"Tool querying an IP geolocation service",
     "detection":{"process_contains":["curl.exe","wget.exe"],
                  "cmdline_contains":["ipinfo.io","api.ipify.org","icanhazip.com"]}},
    {"id":"SIG-007","title":"WScript Executing Script from User Path","level":"critical",
     "mitre":"T1059.005","description":"wscript.exe running a script from user-writable location",
     "detection":{"process_contains":["wscript.exe"],
                  "cmdline_contains":["\\users\\public\\","\\appdata\\","\\temp\\"]}},
    {"id":"SIG-008","title":"Executable from User Directory","level":"critical",
     "mitre":"T1036","description":"Executable running from Users/ directory — possible dropper",
     "detection":{"process_contains":["\\users\\"]}},
    {"id":"SIG-009","title":"Svchost Spawning Script Interpreter","level":"high",
     "mitre":"T1059.005","description":"svchost.exe launching a script interpreter",
     "detection":{"parent_contains":["svchost.exe"],
                  "process_contains":["wscript.exe","cscript.exe","mshta.exe"]}},
    {"id":"SIG-010","title":"SQL Injection Pattern","level":"high",
     "mitre":"T1190","description":"SQL injection pattern in query or command",
     "detection":{"cmdline_contains":["' or 1=1","union select","information_schema","--"]}},
    {"id":"SIG-011","title":"Path Traversal Attempt","level":"medium",
     "mitre":"T1083","description":"Path traversal pattern in request",
     "detection":{"cmdline_contains":["../","..\\","..%2f","..%5c"]}},
    {"id":"SIG-012","title":"Mimikatz Credential Dump","level":"critical",
     "mitre":"T1003.001","description":"Mimikatz or credential dumping tool detected",
     "detection":{"cmdline_contains":["sekurlsa","lsadump","invoke-mimikatz","mimikatz"]}},
    {"id":"SIG-013","title":"LSASS Memory Access","level":"critical",
     "mitre":"T1003.001","description":"Unusual process accessing LSASS memory",
     "detection":{"process_contains":["lsass.exe"]}},
    {"id":"SIG-014","title":"Net User / Group Enumeration","level":"medium",
     "mitre":"T1069","description":"net.exe used for user/group enumeration",
     "detection":{"process_contains":["net.exe","net1.exe"],
                  "cmdline_contains":["user","localgroup","group","accounts"]}},
    {"id":"SIG-015","title":"Volume Shadow Copy Deletion","level":"critical",
     "mitre":"T1490","description":"Shadow copies being deleted — ransomware indicator",
     "detection":{"cmdline_contains":["vssadmin delete shadows","wbadmin delete catalog",
                                      "bcdedit /set recoveryenabled no"]}},
]

def _load_yaml_rules(rules_dir):
    rules = []
    if not YAML_AVAILABLE: return rules
    p = Path(rules_dir)
    if not p.exists(): return rules
    for yml_file in p.glob("*.yml"):
        try:
            with open(yml_file) as f:
                rule = yaml.safe_load(f)
            if rule and isinstance(rule, dict) and "detection" in rule:
                rules.append(rule)
        except Exception as e:
            log.warning("Could not load rule %s: %s", yml_file.name, e)
    return rules

def _match_rule(rule, row, sm: SchemaMap):
    det    = rule.get("detection", {})
    proc   = rget(row, "_process", sm).lower()
    parent = rget(row, "_parent", sm).lower()
    cmd    = rget(row, "_cmdline", sm).lower()
    action = rget(row, "_event_action", sm).lower()
    msg    = rget(row, "_message", sm).lower()
    # combine searchable text
    all_text = f"{proc} {cmd} {msg}"

    checks = []
    if "process_contains"  in det: checks.append(any(kw in proc for kw in det["process_contains"]))
    if "parent_contains"   in det: checks.append(any(kw in parent for kw in det["parent_contains"]))
    if "cmdline_contains"  in det: checks.append(all(kw in all_text for kw in det["cmdline_contains"]))
    if "event_action"      in det: checks.append(action in det["event_action"])
    if "message_contains"  in det: checks.append(any(kw in msg for kw in det["message_contains"]))
    return len(checks) > 0 and all(checks)

def run_sigma_engine(df: pd.DataFrame, schema_map: SchemaMap) -> pd.DataFrame:
    yaml_rules = _load_yaml_rules(SIGMA_RULES_DIR)
    all_rules  = BUILTIN_RULES + yaml_rules
    log.info("Sigma engine: %d built-in + %d YAML rules", len(BUILTIN_RULES), len(yaml_rules))

    sigma_alerts = []
    for _, row in df.iterrows():
        for rule in all_rules:
            if _match_rule(rule, row, schema_map):
                score = LEVEL_SCORE.get(rule.get("level","medium"), 25)
                sigma_alerts.append({
                    "Timestamp":            rget(row, "_ts", schema_map),
                    "Process":              rget(row, "_process", schema_map),
                    "Parent Process":       rget(row, "_parent", schema_map),
                    "Command Line":         rget(row, "_cmdline", schema_map),
                    "Detection Type":       "Sigma Match",
                    "Sigma Rule ID":        rule.get("id",""),
                    "Sigma Rule Title":     rule.get("title",""),
                    "Sigma Level":          rule.get("level",""),
                    "Risk Score":           score,
                    "Investigation Reason": rule.get("description", rule.get("title","")),
                    "Source IP":            rget(row, "_src_ip", schema_map),
                    "Destination IP":       rget(row, "_dst_ip", schema_map),
                    "Registry Path":        rget(row, "_registry", schema_map),
                    "File Path":            rget(row, "_filepath", schema_map),
                    "DNS Query":            rget(row, "_domain", schema_map),
                    "Event Action":         rget(row, "_event_action", schema_map),
                    "PID":                  rget(row, "_pid", schema_map),
                    "Username":             rget(row, "_username", schema_map),
                    "Hostname":             rget(row, "_hostname", schema_map),
                    "Severity Field":       rget(row, "_severity", schema_map),
                    "Message":              rget(row, "_message", schema_map),
                    "MITRE Technique":      rule.get("mitre",""),
                    "MITRE Name":           "",
                })
    result = pd.DataFrame(sigma_alerts)
    log.info("Sigma engine: %d matches", len(result))
    return result
