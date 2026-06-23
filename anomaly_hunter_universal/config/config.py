"""
config/config.py  -  Anomaly Hunter v3
========================================
Master configuration. All thresholds, IOC lists, MITRE mappings,
output paths, and allowlists in one place.
Override any value via environment variable or ah_config.json.
"""

import os
import re
import json
import logging
from pathlib import Path

log = logging.getLogger("AnomalyHunter.Config")

VERSION = "3.0"

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR           = Path(__file__).resolve().parent.parent
DEFAULT_LOG_FILE   = os.getenv("AH_LOG_FILE",   str(BASE_DIR / "logs.csv"))
DEFAULT_OUTPUT_DIR = os.getenv("AH_OUTPUT_DIR", str(BASE_DIR / "output"))
DEFAULT_ALLOWLIST  = os.getenv("AH_ALLOWLIST",  str(Path(__file__).resolve().parent / "allowlist.json"))
SIGMA_RULES_DIR    = str(BASE_DIR / "sigma_rules")

OUTPUT_FILES = {
    "investigation_queue": "investigation_queue.csv",
    "attack_chain":        "attack_chain_report.csv",
    "anomaly_report":      "anomaly_report.csv",
    "timeline":            "timeline.csv",
    "executive_summary":   "executive_summary.csv",
    "kill_chain":          "kill_chain_report.csv",
    "process_tree":        "process_tree.csv",
    "ioc_summary":         "ioc_summary.csv",
    "correlation":         "correlation_report.csv",
    "html_report":         "investigation_report.html",
    "json_report":         "report.json",
    "sigma_alerts":        "sigma_alerts.csv",
}

# ── Risk scoring ──────────────────────────────────────────────────────────────
RISK_SCORES = {
    "PROCESS_INJECTION":       50,
    "DOWNLOAD_EXECUTE":        45,
    "ENCODED_PAYLOAD":         40,
    "PERSISTENCE":             40,
    "RULE_DETECTION":          45,
    "DEFENSE_EVASION":         45,
    "LOLBIN":                  25,
    "POWERSHELL_PAYLOAD":      25,
    "SUSPICIOUS_DLL":          25,
    "SVCHOST_CHILD_SPAWN":     30,
    "RECON_TOOL":              30,
    "USER_FOLDER_EXECUTION":   20,
    "DNS_ANOMALY":             20,
    "DGA_DOMAIN":              20,
    "SUSPICIOUS_PARENT_CHILD": 35,
    "NETWORK_OUTLIER":         15,
    "EXTERNAL_COMMUNICATION":  15,
    "RARE_PROCESS":            15,
    "RARE_PARENT_CHILD":       15,
    "BEACONING":               20,
    "NIGHT_ACTIVITY":          10,
    "SIGMA_MATCH":             40,
}

MAX_RISK_SCORE = 100

# ── Severity thresholds ───────────────────────────────────────────────────────
THRESHOLDS = {"INFO": 0, "LOW": 20, "MEDIUM": 40, "HIGH": 60, "CRITICAL": 80}

# ── Detection tuning ──────────────────────────────────────────────────────────
RARE_PROCESS_THRESHOLD      = 2
RARE_PARENT_CHILD_THRESHOLD = 2
DOMAIN_ENTROPY_THRESHOLD    = 4.5
LONG_DOMAIN_THRESHOLD       = 40
BEACON_THRESHOLD            = 5
BEACON_MIN_EVENTS           = 8
NETWORK_OUTLIER_ZSCORE      = 2.0

# ── LOLBins ───────────────────────────────────────────────────────────────────
LOLBINS = {
    "powershell.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe",
    "mshta.exe", "certutil.exe", "wscript.exe", "cscript.exe",
    "msbuild.exe", "installutil.exe", "msiexec.exe", "schtasks.exe",
    "wmic.exe", "forfiles.exe", "hh.exe", "bitsadmin.exe",
    "control.exe", "odbcconf.exe", "bash.exe", "reg.exe", "curl.exe",
    "regasm.exe", "regsvcs.exe", "ieexec.exe", "xwizard.exe",
}

# ── Paths ─────────────────────────────────────────────────────────────────────
USER_FOLDER_PATHS = [
    "\\users\\", "\\users\\public\\", "\\downloads\\", "\\desktop\\",
    "\\appdata\\", "\\appdata\\local\\temp\\", "\\appdata\\roaming\\",
    "\\temp\\", "\\programdata\\", "\\recycler\\", "\\$recycle.bin\\",
]

LEGIT_EXEC_PREFIXES = [
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\programdata\\microsoft\\",
]

# ── Keyword lists ─────────────────────────────────────────────────────────────
DOWNLOAD_KEYWORDS = [
    "invoke-webrequest", "iwr", "downloadstring", "downloadfile",
    "webclient", "system.net.webclient", "curl", "wget",
    "bitsadmin", "start-bitstransfer", "certutil -urlcache",
    "certutil -decode", "mshta http", "regsvr32 /i:http",
    "msiexec /i http", "rundll32 javascript:", "ftp", "tftp",
]

DOWNLOAD_EXECUTE_KEYWORDS = [
    "start-process", "invoke-expression", "iex",
    "cmd /c", "powershell -c", "createprocess",
    "shell.execute", "shell.application",
]

ENCODED_PAYLOAD_KEYWORDS = [
    "-enc", "-encodedcommand", "encodedcommand", "frombase64string",
    "base64", "convert.frombase64string", "powershell -e",
]

POWERSHELL_INDICATORS = [
    "invoke-webrequest", "downloadstring", "downloadfile",
    "iex", "invoke-expression", "new-object net.webclient",
    "frombase64string", "invoke-command", "invoke-mimikatz",
    "invoke-shellcode", "reflection.assembly",
    "add-mppreference",            # Defender exclusion
    "set-mppreference",
]

DEFENSE_EVASION_KEYWORDS = [
    "add-mppreference -exclusionpath",
    "add-mppreference -exclusionprocess",
    "set-mppreference -disablerealtimemonitoring",
    "bcdedit /set recoveryenabled no",
    "wbadmin delete catalog",
    "vssadmin delete shadows",
]

PERSISTENCE_PATTERNS = [
    r"currentversion\\run",
    r"currentversion\\runonce",
    r"runservices",
    r"policies\\explorer\\run",
    r"startup",
    r"winlogon",
    r"userinit",
    r"image file execution options",
]

PERSISTENCE_CMD_PATTERNS = [
    r"reg\s+add.*\\run\\",
    r"reg\s+add.*\\runonce\\",
    r"schtasks\s+/create",
    r"schtasks\s+/change",
]

# ── Injection / high-value targets ────────────────────────────────────────────
HIGH_VALUE_TARGETS = {
    "lsass.exe", "explorer.exe", "winlogon.exe",
    "services.exe", "svchost.exe", "csrss.exe", "spoolsv.exe",
}

# ── Suspicious parent→child pairs ─────────────────────────────────────────────
SUSPICIOUS_PARENT_CHILD = {
    ("winword.exe",    "powershell.exe"),
    ("excel.exe",      "powershell.exe"),
    ("outlook.exe",    "powershell.exe"),
    ("winword.exe",    "cmd.exe"),
    ("excel.exe",      "cmd.exe"),
    ("outlook.exe",    "cmd.exe"),
    ("winword.exe",    "mshta.exe"),
    ("excel.exe",      "mshta.exe"),
    ("outlook.exe",    "mshta.exe"),
    ("powershell.exe", "rundll32.exe"),
    ("powershell.exe", "regsvr32.exe"),
    ("powershell.exe", "certutil.exe"),
    ("svchost.exe",    "wscript.exe"),
    ("svchost.exe",    "cscript.exe"),
    ("svchost.exe",    "mshta.exe"),
    ("excel.exe",      "wscript.exe"),
    ("excel.exe",      "cscript.exe"),
}

# ── Network / DNS ─────────────────────────────────────────────────────────────
RECON_DOMAINS = {
    "ipinfo.io", "checkip.amazonaws.com", "api.ipify.org",
    "icanhazip.com", "ifconfig.me", "ip-api.com",
    "wtfismyip.com", "ipecho.net",
}

KNOWN_GOOD_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"}

KNOWN_GOOD_DOMAINS = {
    "microsoft.com", "office.com", "office365.com", "live.com",
    "msn.com", "bing.com", "msedge.net", "windowsupdate.com",
    "windows.net", "azure.com", "akamai.net", "cloudflare.com",
    "fastly.net", "lencr.org", "msftncsi.com", "google.com",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".biz", ".click", ".work",
    ".live", ".monster", ".gq", ".tk", ".ml", ".cf",
}

# Known Microsoft IP ranges (rough, for FP suppression)
KNOWN_GOOD_IP_PREFIXES = (
    "150.171.", "20.135.", "52.110.", "52.123.",
    "20.189.", "13.107.", "40.104.",
)

# ── Known-good processes ──────────────────────────────────────────────────────
KNOWN_GOOD_PROCESSES = {
    "explorer.exe", "svchost.exe", "runtimebroker.exe",
    "taskhostw.exe", "ctfmon.exe", "dwm.exe", "searchhost.exe",
    "searchindexer.exe", "startmenuexperiencehost.exe", "sihost.exe",
    "onedrive.exe", "msedge.exe", "chrome.exe", "firefox.exe",
    "teams.exe", "officeclicktorun.exe", "integrator.exe",
    "msedgewebview2.exe", "conhost.exe",
}

# ── MITRE ATT&CK ──────────────────────────────────────────────────────────────
MITRE_MAPPING = {
    "powershell.exe":  "T1059.001",
    "cmd.exe":         "T1059.003",
    "wscript.exe":     "T1059.005",
    "cscript.exe":     "T1059.005",
    "rundll32.exe":    "T1218.011",
    "regsvr32.exe":    "T1218.010",
    "mshta.exe":       "T1218.005",
    "certutil.exe":    "T1105",
    "msbuild.exe":     "T1127.001",
    "installutil.exe": "T1218.004",
    "schtasks.exe":    "T1053.005",
    "msiexec.exe":     "T1218",
    "wmic.exe":        "T1047",
    "reg.exe":         "T1547.001",
    "curl.exe":        "T1016",
}

MITRE_NAMES = {
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1059.005": "Visual Basic",
    "T1218.011": "Rundll32",
    "T1218.010": "Regsvr32",
    "T1218.005": "MSHTA",
    "T1105":     "Ingress Tool Transfer",
    "T1127.001": "MSBuild",
    "T1218.004": "InstallUtil",
    "T1053.005": "Scheduled Task",
    "T1047":     "WMI",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1016":     "System Network Config Discovery",
    "T1027":     "Obfuscated Files or Information",
    "T1055":     "Process Injection",
    "T1071":     "Application Layer Protocol",
    "T1562.001": "Disable or Modify Tools",
    "T1036":     "Masquerading",
}

MITRE_TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
}

# ── Built-in allowlist patterns ───────────────────────────────────────────────
# Matched against Investigation Reason field to suppress known-benign FPs
BUILTIN_ALLOWLIST_PATTERNS = [
    r"schedule.taskcache.tasks",
    r"internet settings.zonemap",
    r"currentversion.internet settings",
    r"windowsapps",
    r"\\windows\\system32\\conhost\.exe.*-ForceV1",
    r"backgroundtaskhost",
    r"runtimebroker.*-embedding",
]

# ── Runtime allowlist (loaded from file) ──────────────────────────────────────
_RUNTIME_ALLOWLIST: list = []


def load_allowlist(path: str = DEFAULT_ALLOWLIST) -> list:
    global _RUNTIME_ALLOWLIST
    p = Path(path)
    if p.exists():
        try:
            with open(p) as f:
                _RUNTIME_ALLOWLIST = json.load(f)
            log.info("Loaded %d allowlist entries from %s", len(_RUNTIME_ALLOWLIST), path)
        except Exception as e:
            log.warning("Could not load allowlist %s: %s", path, e)
    return _RUNTIME_ALLOWLIST


def get_runtime_allowlist() -> list:
    return _RUNTIME_ALLOWLIST


def is_allowlisted(reason: str, process: str = "") -> bool:
    r = str(reason).lower()
    p = str(process).lower()
    for pattern in BUILTIN_ALLOWLIST_PATTERNS:
        if re.search(pattern, r) or re.search(pattern, p):
            return True
    for entry in _RUNTIME_ALLOWLIST:
        if isinstance(entry, dict):
            if re.search(entry.get("pattern", ""), r, re.IGNORECASE):
                return True
        elif isinstance(entry, str):
            if entry.lower() in r:
                return True
    return False


# ── External config override ──────────────────────────────────────────────────
def load_external_config(path: str = "") -> dict:
    if not path:
        path = str(BASE_DIR / "ah_config.json")
    p = Path(path)
    if not p.exists():
        return {}
    try:
        with open(p) as f:
            overrides = json.load(f)
        log.info("Loaded config overrides from %s", path)
        return overrides
    except Exception as e:
        log.warning("Could not parse config %s: %s", path, e)
        return {}


def apply_overrides(overrides: dict):
    g = globals()
    for key, val in overrides.items():
        if key in g:
            if isinstance(g[key], dict) and isinstance(val, dict):
                g[key].update(val)
            else:
                g[key] = val
