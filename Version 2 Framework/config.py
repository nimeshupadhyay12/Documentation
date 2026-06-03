"""
config.py
==========================================================
Anomaly Hunter v2 - Configuration File

IMPROVEMENTS:
- Added event.action-based detection triggers
- Added file.path to USER_FOLDER_PATHS sentinel check
- Extended LOLBINS with reg.exe, curl.exe, wscript, etc.
- Added KNOWN_GOOD_IPS whitelist expansion
- Added KNOWN_GOOD_DOMAINS for FP suppression
- Added SUSPICIOUS_PATHS_REGEX for tighter path matching
- Tuned risk scores: PROCESS_INJECTION was never firing;
  added RULE_DETECTION_SCORE for explicit EDR hits
- Added BEACONING detection config
- Added SVCHOST_CHILD_SPAWN detection
- Added CURL_RECON detection

Author: Nimesh Upadhyay (improved)
Version: 2.1
==========================================================
"""

VERSION = "2.1"

# ==========================================================
# LOG FILE
# ==========================================================

DEFAULT_LOG_FILE = "logs.csv"

# ==========================================================
# OUTPUT FILES
# ==========================================================

OUTPUT_FILES = {
    "investigation_queue":  "investigation_queue.csv",
    "attack_chain":         "attack_chain_report.csv",
    "anomaly_report":       "anomaly_report.csv",
    "timeline":             "timeline.csv",
    "executive_summary":    "executive_summary.csv"
}

# ==========================================================
# RISK SCORING  (max cap = 100)
# ==========================================================

RISK_SCORES = {
    # Critical
    "PROCESS_INJECTION":        50,
    "DOWNLOAD_EXECUTE":         45,
    "ENCODED_PAYLOAD":          40,
    "PERSISTENCE":              40,   # bumped: Run-key write is critical
    "MALWARE_STAGING":          35,
    "RULE_DETECTION":           45,   # NEW: explicit EDR/AV rule hit

    # High
    "LOLBIN":                   25,
    "POWERSHELL_PAYLOAD":       25,
    "SUSPICIOUS_DLL":           25,
    "SVCHOST_CHILD_SPAWN":      30,   # NEW: svchost spawning script engines
    "RECON_TOOL":               30,   # NEW: curl/ping querying public IP info

    # Medium
    "USER_FOLDER_EXECUTION":    20,
    "DNS_ANOMALY":              20,
    "DGA_DOMAIN":               20,
    "SUSPICIOUS_PARENT_CHILD":  35,   # NEW: Office/svchost → script engine

    # Low
    "NETWORK_OUTLIER":          15,
    "EXTERNAL_COMMUNICATION":   15,
    "RARE_PROCESS":             15,
    "RARE_PARENT_CHILD":        15,
    "BEACONING":                20,   # bumped: repeated disconnect pattern
    "NIGHT_ACTIVITY":           10,
}

# ==========================================================
# SEVERITY THRESHOLDS
# ==========================================================

INFO_THRESHOLD     = 0
LOW_THRESHOLD      = 20
MEDIUM_THRESHOLD   = 40
HIGH_THRESHOLD     = 60
CRITICAL_THRESHOLD = 80

# ==========================================================
# DETECTION THRESHOLDS
# ==========================================================

RARE_PROCESS_THRESHOLD       = 2
RARE_PARENT_CHILD_THRESHOLD  = 2
DOMAIN_ENTROPY_THRESHOLD     = 4.5
LONG_DOMAIN_THRESHOLD        = 40
BEACON_THRESHOLD             = 5       # repeated disconnect/connect cycles
NETWORK_OUTLIER_ZSCORE       = 2.0
BURST_EVENT_THRESHOLD        = 50
MAX_RISK_SCORE               = 100

# Minimum events for beaconing detection (avoid FP on single connections)
BEACON_MIN_EVENTS            = 8

# ==========================================================
# SUSPICIOUS PROCESS EXECUTION PATHS
# ==========================================================

USER_FOLDER_PATHS = [
    "\\users\\",
    "\\users\\public\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\appdata\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\temp\\",
    "\\programdata\\",
    "\\recycler\\",
    "\\$recycle.bin\\"
]

# NEW: tighter regex for truly suspicious staging paths
# (excludes legit WindowsApps / Program Files paths)
MALWARE_STAGING_PATHS = [
    r"\\users\\[^\\]+\\[^\\]+\.exe",             # exe directly in user root
    r"\\users\\public\\pictures\\",              # PUBLIC\Pictures (suspicious)
    r"\\appdata\\local\\temp\\_mei",             # PyInstaller extraction
    r"\\users\\[^\\]+\\appdata\\local\\temp\\",  # Temp execution
]

# ==========================================================
# SUSPICIOUS FILE EXTENSIONS
# ==========================================================

SUSPICIOUS_EXTENSIONS = [
    ".exe", ".dll", ".bat", ".cmd", ".vbs",
    ".js", ".jse", ".hta", ".ps1", ".scr",
    ".cpl", ".pif"
]

# ==========================================================
# LOLBINS  (expanded)
# ==========================================================

LOLBINS = {
    "powershell.exe",
    "cmd.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "certutil.exe",
    "wscript.exe",
    "cscript.exe",
    "msbuild.exe",
    "installutil.exe",
    "msiexec.exe",
    "schtasks.exe",
    "wmic.exe",
    "forfiles.exe",
    "hh.exe",
    "bitsadmin.exe",
    "control.exe",
    "odbcconf.exe",
    "pcwrun.exe",
    "bash.exe",
    # NEW additions
    "reg.exe",          # used in this log for persistence
    "curl.exe",         # used in this log for recon (ipinfo.io)
    "regasm.exe",
    "regsvcs.exe",
    "ieexec.exe",
    "xwizard.exe",
    "syncappvpublishingserver.exe",
    "appsyncpublishingserver.exe",
}

# ==========================================================
# DOWNLOAD TECHNIQUES
# ==========================================================

DOWNLOAD_KEYWORDS = [
    "invoke-webrequest", "iwr", "downloadstring", "downloadfile",
    "webclient", "system.net.webclient", "curl", "wget",
    "bitsadmin", "start-bitstransfer", "download",
    "certutil -urlcache", "certutil -decode",
    "mshta http", "regsvr32 /i:http", "msiexec /i http",
    "rundll32 javascript:", "ftp", "tftp"
]

# ==========================================================
# DOWNLOAD + EXECUTE INDICATORS
# ==========================================================

DOWNLOAD_EXECUTE_KEYWORDS = [
    "start-process", "invoke-expression", "iex",
    "cmd /c", "powershell -c", "powershell.exe",
    "createprocess", "shell.execute", "shell.application"
]

# ==========================================================
# ENCODED PAYLOAD DETECTION
# ==========================================================

ENCODED_PAYLOAD_KEYWORDS = [
    "-enc", "-encodedcommand", "encodedcommand",
    "frombase64string", "base64", "convert.frombase64string",
    "jabh", "sqbfag", "tvqqaamaaaaeaaaa", "powershell -e"
]

# ==========================================================
# POWERSHELL PAYLOAD INDICATORS
# ==========================================================

POWERSHELL_INDICATORS = [
    "invoke-webrequest", "downloadstring", "downloadfile",
    "iex", "invoke-expression", "new-object net.webclient",
    "frombase64string", "invoke-command", "invoke-mimikatz",
    "invoke-shellcode", "reflection.assembly"
]

# ==========================================================
# PERSISTENCE DETECTION  (expanded)
# ==========================================================

PERSISTENCE_PATTERNS = [
    r"currentversion\\run",
    r"currentversion\\runonce",
    r"runservices",
    r"runservicesonce",
    r"policies\\explorer\\run",
    r"startup",
    r"scheduledtasks",
    r"tasks",
    r"services",
    r"winlogon",
    r"userinit",
    r"shell",
    r"image file execution options",
    # NEW: svchost task cache (seen in logs)
    r"schedule\\taskcache\\tasks",
]

# Persistence via reg.exe command line (NEW)
PERSISTENCE_CMD_PATTERNS = [
    r"reg\s+add.*\\run\\",
    r"reg\s+add.*\\runonce\\",
    r"reg\s+add.*\\startup",
    r"schtasks\s+/create",
    r"schtasks\s+/change",
]

# ==========================================================
# SUSPICIOUS DLL LOCATIONS
# ==========================================================

SUSPICIOUS_DLL_PATHS = [
    "\\temp\\", "\\users\\", "\\downloads\\",
    "\\desktop\\", "\\appdata\\", "\\public\\", "\\programdata\\"
]

# ==========================================================
# PROCESS INJECTION TARGETS
# ==========================================================

HIGH_VALUE_TARGETS = {
    "lsass.exe", "explorer.exe", "winlogon.exe",
    "services.exe", "svchost.exe", "csrss.exe", "spoolsv.exe"
}

# ==========================================================
# SUSPICIOUS PARENT → CHILD RELATIONSHIPS  (expanded)
# ==========================================================

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
    # NEW: seen in this log
    ("svchost.exe",    "wscript.exe"),   # svchost → wscript.exe xuvotopo.js
    ("svchost.exe",    "cscript.exe"),
    ("svchost.exe",    "mshta.exe"),
    ("excel.exe",      "wscript.exe"),
    ("excel.exe",      "cscript.exe"),
}

# ==========================================================
# RECON DOMAINS  (NEW)
# ==========================================================

RECON_DOMAINS = {
    "ipinfo.io",
    "checkip.amazonaws.com",
    "api.ipify.org",
    "icanhazip.com",
    "ifconfig.me",
    "ip-api.com",
    "wtfismyip.com",
    "ipecho.net",
}

# ==========================================================
# KNOWN GOOD PROCESSES
# ==========================================================

KNOWN_GOOD_PROCESSES = {
    "explorer.exe", "svchost.exe", "runtimebroker.exe",
    "taskhostw.exe", "ctfmon.exe", "dwm.exe",
    "searchhost.exe", "searchindexer.exe",
    "startmenuexperiencehost.exe", "sihost.exe",
    "onedrive.exe", "msedge.exe", "chrome.exe",
    "firefox.exe", "teams.exe",
    # Office apps (benign parent, not benign child of suspicious parent)
    "officeclicktorun.exe", "integrator.exe",
    "msedgewebview2.exe", "conhost.exe",
}

# ==========================================================
# KNOWN GOOD IPS
# ==========================================================

KNOWN_GOOD_IPS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"
}

# ==========================================================
# KNOWN GOOD DOMAINS  (NEW – suppress FPs)
# ==========================================================

KNOWN_GOOD_DOMAINS = {
    "microsoft.com", "office.com", "office365.com",
    "live.com", "msn.com", "bing.com", "msedge.net",
    "windowsupdate.com", "windows.net", "azure.com",
    "akamai.net", "cloudflare.com", "fastly.net",
    "lencr.org",  # Let's Encrypt OCSP
    "msftncsi.com",
}

# ==========================================================
# SUSPICIOUS TOP LEVEL DOMAINS
# ==========================================================

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".biz", ".click", ".work",
    ".live", ".monster", ".gq", ".tk", ".ml", ".cf"
}

# ==========================================================
# MITRE ATT&CK MAPPINGS  (expanded)
# ==========================================================

MITRE_MAPPING = {
    "powershell.exe":   "T1059.001",
    "cmd.exe":          "T1059.003",
    "wscript.exe":      "T1059.005",
    "cscript.exe":      "T1059.005",
    "rundll32.exe":     "T1218.011",
    "regsvr32.exe":     "T1218.010",
    "mshta.exe":        "T1218.005",
    "certutil.exe":     "T1105",
    "msbuild.exe":      "T1127.001",
    "installutil.exe":  "T1218.004",
    "schtasks.exe":     "T1053.005",
    "msiexec.exe":      "T1218",
    "wmic.exe":         "T1047",
    "reg.exe":          "T1547.001",   # NEW: Boot/Logon Autostart – Registry Run Keys
    "curl.exe":         "T1016",       # NEW: System Network Configuration Discovery
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
    "T1547.001": "Registry Run Keys / Startup Folder",  # NEW
    "T1016":     "System Network Config Discovery",     # NEW
}

# ==========================================================
# OUTPUT COLUMNS
# ==========================================================

INVESTIGATION_COLUMNS = [
    "Timestamp", "Risk Score", "Severity", "Process",
    "Parent Process", "Detection Type", "MITRE Technique",
    "MITRE Name", "Source IP", "Destination IP",
    "Confidence", "Investigation Reason",
    "Analyst Verdict", "Recommendation"
]
