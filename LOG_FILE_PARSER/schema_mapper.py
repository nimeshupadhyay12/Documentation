"""
schema_mapper.py  -  Anomaly Hunter Universal
===============================================
Universal schema normalisation layer.

Converts ANY log CSV — regardless of field names, log source, or platform —
into the standard internal schema that all detectors consume.

How it works:
  1. AUTO-DETECT: Scans column names using pattern matching to identify
     what each column represents (timestamp, process, IP, etc.)
  2. MAP: Creates a SchemaMap object that maps raw column names to
     standard internal field names
  3. NORMALISE: Returns a DataFrame with standard columns added alongside
     the original columns (originals preserved, never deleted)
  4. REPORT: Tells the user exactly what was mapped and what was not found

Standard internal field names (all optional — detectors skip gracefully):
  _ts               timestamp
  _process          executing process / binary / script / user
  _parent           parent process / caller
  _cmdline          command line / query / message / description  
  _src_ip           source IP address
  _dst_ip           destination IP address / remote host
  _domain           DNS query / hostname / domain
  _registry         registry path / config key / parameter name
  _filepath         file path / object path / resource
  _pid              process ID / session ID / thread ID
  _event_action     event type / action / operation / category
  _username         user / account / subject
  _hostname         host / device / machine name
  _port             destination port / service port
  _protocol         protocol / service name
  _hash             file hash / checksum
  _severity         log severity / level / priority
  _message          log message / description / reason

Supported log sources (auto-detected):
  - Elastic ECS (process.executable, @timestamp, dns.question.name ...)
  - Windows Event Log (EventID, SubjectUserName, ProcessName ...)
  - Sysmon (Image, ParentImage, CommandLine, TargetImage ...)
  - AWS CloudTrail (eventName, sourceIPAddress, userAgent ...)
  - Apache / Nginx access logs (client, request, status ...)
  - Zeek/Bro network logs (id.orig_h, id.resp_h, proto ...)
  - Suricata EVE JSON (src_ip, dest_ip, alert.signature ...)
  - CEF / LEEF (src, dst, act, msg, duser ...)
  - Generic syslog (host, facility, severity, message ...)
  - Any CSV with readable column names
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Optional

import pandas as pd

log = logging.getLogger("AnomalyHunter.SchemaMapper")


# ── Canonical field registry ──────────────────────────────────────────────────
# Each entry: (internal_name, display_name, [candidate_column_patterns])
# Patterns are matched case-insensitively against column names.
# First match wins. Order within each list = priority.

FIELD_REGISTRY = [
    # ── Timestamp ────────────────────────────────────────────────────────────
    ("_ts", "Timestamp", [
        r"^@timestamp$", r"^timestamp$", r"^time$", r"^datetime$",
        r"^event\.created$", r"^event_time$", r"^eventtime$",
        r"^log_time$", r"^logtime$", r"^date_time$", r"^datetime$",
        r"^created_at$", r"^occurred$", r"^ts$", r"^start_time$",
        r"^utctime$", r"^systemtime$", r"^eventdatetime$",
        r"time",   # broad fallback
    ]),

    # ── Process / executable ─────────────────────────────────────────────────
    ("_process", "Process", [
        r"^process\.executable$", r"^process\.name$",
        r"^image$",               r"^newprocessname$",
        r"^processname$",         r"^process_name$",
        r"^application$",         r"^app_name$",
        r"^program$",             r"^binary$",
        r"^exe$",                 r"^executable$",
        r"^cmdpath$",             r"^process_path$",
        r"^proc$",
        # AWS/cloud
        r"^eventsource$",         r"^eventname$",
        # Web logs
        r"^request$",             r"^uri$",   r"^url$",
        # Broad
        r"process",
    ]),

    # ── Parent process ────────────────────────────────────────────────────────
    ("_parent", "Parent Process", [
        r"^process\.parent\.executable$", r"^process\.parent\.name$",
        r"^parentimage$",         r"^parentprocessname$",
        r"^parent_process$",      r"^parent_image$",
        r"^parentprocesspath$",   r"^creator_process_name$",
        r"^callerprocessname$",   r"^parentcommandline$",
        r"parent",
    ]),

    # ── Command line / query ──────────────────────────────────────────────────
    ("_cmdline", "Command Line", [
        r"^process\.command_line$", r"^commandline$",
        r"^process\.command_line$", r"^command_line$",
        r"^cmdline$",               r"^command$",
        r"^process\.args$",         r"^processcommandline$",
        r"^parentcommandline$",
        # SQL / query logs
        r"^query$",                 r"^sql$",          r"^statement$",
        # Web
        r"^user_agent$",            r"^useragent$",    r"^requestbody$",
        # AWS
        r"^requestparameters$",
        r"command", r"cmdline", r"commandline",
    ]),

    # ── Source IP ─────────────────────────────────────────────────────────────
    ("_src_ip", "Source IP", [
        r"^source\.ip$",        r"^src_ip$",       r"^sourceip$",
        r"^src\.ip$",           r"^client_ip$",    r"^clientip$",
        r"^remote_ip$",         r"^remote_addr$",
        r"^id\.orig_h$",        r"^orig_ip$",
        r"^ipaddress$",         r"^ip_address$",
        r"^caller_ip$",
        r"src.*ip", r"source.*ip", r"client.*ip",
    ]),

    # ── Destination IP ────────────────────────────────────────────────────────
    ("_dst_ip", "Destination IP", [
        r"^destination\.ip$",   r"^dest_ip$",      r"^destinationip$",
        r"^dst_ip$",            r"^server_ip$",    r"^serverip$",
        r"^remote_host$",       r"^target_ip$",
        r"^id\.resp_h$",        r"^resp_ip$",
        r"dst.*ip", r"dest.*ip", r"remote.*host",
    ]),

    # ── Domain / DNS ──────────────────────────────────────────────────────────
    ("_domain", "DNS Query", [
        r"^dns\.question\.name$", r"^dns_query$",   r"^query_name$",
        r"^domain$",              r"^hostname$",     r"^host$",
        r"^fqdn$",                r"^dns_name$",     r"^queried_domain$",
        r"^dns\.resolved_ip$",    r"^rdns$",
        r"^serverName$",          r"^server_name$",
        r"dns", r"domain", r"hostname",
    ]),

    # ── Registry path ─────────────────────────────────────────────────────────
    ("_registry", "Registry Path", [
        r"^registry\.path$",    r"^registry_path$", r"^regpath$",
        r"^targetobject$",      r"^registrykey$",   r"^reg_key$",
        r"^objectname$",        r"^objectpath$",
        r"registry", r"regkey", r"reg_path",
    ]),

    # ── File path ─────────────────────────────────────────────────────────────
    ("_filepath", "File Path", [
        r"^file\.path$",        r"^filepath$",      r"^file_path$",
        r"^targetfilename$",    r"^filename$",       r"^file_name$",
        r"^image_path$",        r"^imagepath$",
        r"^resource$",          r"^object$",         r"^objectname$",
        r"^s3key$",             r"^key$",
        r"file.*path", r"file.*name", r"^path$",
    ]),

    # ── Process ID ────────────────────────────────────────────────────────────
    ("_pid", "PID", [
        r"^process\.pid$",      r"^processid$",     r"^process_id$",
        r"^pid$",               r"^newprocessid$",  r"^subjectlogonid$",
        r"^session_id$",        r"^thread_id$",
        r"pid", r"processid",
    ]),

    # ── Event action / type ───────────────────────────────────────────────────
    ("_event_action", "Event Action", [
        r"^event\.action$",     r"^eventid$",       r"^event_id$",
        r"^event_type$",        r"^eventtype$",     r"^action$",
        r"^operation$",         r"^operationname$", r"^opcode$",
        r"^category$",          r"^task$",          r"^keywords$",
        r"^activity$",          r"^method$",
        # AWS
        r"^eventname$",
        # Web
        r"^status$",            r"^response_code$", r"^http_method$",
        r"event.*type", r"event.*action", r"^action$",
    ]),

    # ── Username / account ────────────────────────────────────────────────────
    ("_username", "Username", [
        r"^user\.name$",        r"^username$",      r"^user_name$",
        r"^user$",              r"^account_name$",  r"^accountname$",
        r"^subjectusername$",   r"^targetusername$",
        r"^login$",             r"^logon_user$",    r"^actor$",
        # AWS
        r"^useridentity\.username$", r"^principalid$",
        r"user", r"account", r"login",
    ]),

    # ── Hostname / device ─────────────────────────────────────────────────────
    ("_hostname", "Hostname", [
        r"^host\.name$",        r"^hostname$",      r"^host$",
        r"^computer$",          r"^computername$",  r"^device$",
        r"^device_name$",       r"^machine$",       r"^endpoint$",
        r"^workstation$",       r"^node$",
        r"host", r"computer", r"machine",
    ]),

    # ── Port ──────────────────────────────────────────────────────────────────
    ("_port", "Destination Port", [
        r"^destination\.port$", r"^dest_port$",     r"^dport$",
        r"^dst_port$",          r"^target_port$",   r"^port$",
        r"^id\.resp_p$",
        r"port", r"dport",
    ]),

    # ── Protocol ──────────────────────────────────────────────────────────────
    ("_protocol", "Protocol", [
        r"^network\.protocol$", r"^protocol$",      r"^proto$",
        r"^transport$",         r"^service$",        r"^app_protocol$",
        r"protocol", r"proto",
    ]),

    # ── Hash ──────────────────────────────────────────────────────────────────
    ("_hash", "Hash", [
        r"^hashes$",            r"^hash$",           r"^md5$",
        r"^sha256$",            r"^sha1$",           r"^file\.hash\.sha256$",
        r"^imphash$",           r"^checksum$",
        r"hash", r"sha", r"md5",
    ]),

    # ── Severity / level ──────────────────────────────────────────────────────
    ("_severity", "Log Severity", [
        r"^severity$",          r"^level$",          r"^log\.level$",
        r"^priority$",          r"^criticalityLabel$",
        r"^alert\.severity$",   r"^risk_score$",
        r"severity", r"level", r"priority",
    ]),

    # ── Log message ───────────────────────────────────────────────────────────
    ("_message", "Message", [
        r"^message$",           r"^msg$",            r"^description$",
        r"^detail$",            r"^summary$",        r"^reason$",
        r"^log\.message$",      r"^alert\.signature$",
        r"^comment$",           r"^notes$",
        r"message", r"description", r"detail",
    ]),

    # ── Target process (injection target) ────────────────────────────────────
    ("_target_process", "Target Process", [
        r"^target\.process\.executable$", r"^targetimage$",
        r"^target_process$",   r"^calledprocess$",
        r"target.*process", r"target.*image",
    ]),
]


# ── Schema map dataclass ──────────────────────────────────────────────────────

@dataclass
class SchemaMap:
    """
    Maps raw column names to standard internal field names.
    Carries metadata for reporting to the user.
    """
    # internal_name → raw_column_name
    mapping:        dict = field(default_factory=dict)
    # internal_name → display_name (for UI)
    display_names:  dict = field(default_factory=dict)
    # raw columns that could not be mapped
    unmapped_cols:  list = field(default_factory=list)
    # detected log source type
    log_source:     str  = "Generic CSV"
    # original DataFrame column list
    original_cols:  list = field(default_factory=list)

    def get(self, internal_name: str, row: pd.Series, default: str = "") -> str:
        """Get a value from a row using the internal field name."""
        raw_col = self.mapping.get(internal_name)
        if raw_col and raw_col in row.index:
            val = row[raw_col]
            return str(val) if val is not None and str(val) not in ("nan", "") else default
        return default

    def col(self, internal_name: str) -> Optional[str]:
        """Return the raw column name for an internal field, or None."""
        return self.mapping.get(internal_name)

    def has(self, internal_name: str) -> bool:
        return internal_name in self.mapping

    def summary(self) -> str:
        lines = [f"  Log source: {self.log_source}",
                 f"  Mapped fields ({len(self.mapping)}):"]
        for k, v in sorted(self.mapping.items()):
            dn = self.display_names.get(k, k)
            lines.append(f"    {dn:<22} ← '{v}'")
        if self.unmapped_cols:
            lines.append(f"  Unmapped columns ({len(self.unmapped_cols)}):")
            for c in self.unmapped_cols[:10]:
                lines.append(f"    '{c}'")
            if len(self.unmapped_cols) > 10:
                lines.append(f"    ... and {len(self.unmapped_cols)-10} more")
        return "\n".join(lines)


# ── Log source fingerprinting ─────────────────────────────────────────────────

LOG_SOURCE_SIGNATURES = {
    "Elastic ECS":      ["@timestamp", "process.executable", "event.action"],
    "Sysmon":           ["Image", "ParentImage", "CommandLine"],
    "Windows EventLog": ["EventID", "SubjectUserName", "ProcessName"],
    "AWS CloudTrail":   ["eventName", "sourceIPAddress", "userAgent"],
    "Zeek/Bro":         ["id.orig_h", "id.resp_h", "proto"],
    "Suricata EVE":     ["src_ip", "dest_ip", "alert.signature"],
    "Apache/Nginx":     ["clientip", "request", "response"],
    "CEF/LEEF":         ["src", "dst", "act"],
    "Palo Alto":        ["Source address", "Destination address", "Application"],
    "Cisco ASA":        ["source_ip", "dest_ip", "action"],
    "Fortinet":         ["srcip", "dstip", "action"],
    "CrowdStrike":      ["ComputerName", "ImageFileName", "CommandLine"],
}


def _detect_log_source(columns: list) -> str:
    cols_lower = {c.lower() for c in columns}
    best_match = "Generic CSV"
    best_count = 0
    for source, sigs in LOG_SOURCE_SIGNATURES.items():
        count = sum(1 for s in sigs if s.lower() in cols_lower)
        if count > best_count:
            best_count = count
            best_match = source
    return best_match


# ── Core mapping engine ───────────────────────────────────────────────────────

def _match_column(pattern: str, columns: list) -> Optional[str]:
    """Find first column matching the pattern (case-insensitive)."""
    for col in columns:
        if re.match(pattern, col, re.IGNORECASE):
            return col
    return None


def build_schema_map(df: pd.DataFrame,
                     manual_overrides: dict = None) -> SchemaMap:
    """
    Auto-detect field mappings from a DataFrame's column names.

    Args:
        df:               Input DataFrame (any CSV)
        manual_overrides: dict of {internal_name: raw_col_name} to force-map

    Returns:
        SchemaMap with all detected mappings
    """
    columns       = list(df.columns)
    mapping       = {}
    display_names = {}
    already_mapped = set()

    # Apply manual overrides first (highest priority)
    if manual_overrides:
        for internal, raw_col in manual_overrides.items():
            if raw_col in columns:
                mapping[internal] = raw_col
                already_mapped.add(raw_col)
                log.debug("Manual override: %s → '%s'", internal, raw_col)
            else:
                log.warning("Manual override: column '%s' not found in CSV", raw_col)

    # Auto-detect remaining fields
    for internal_name, display_name, patterns in FIELD_REGISTRY:
        if internal_name in mapping:
            continue   # already set by manual override
        display_names[internal_name] = display_name
        for pattern in patterns:
            matched = _match_column(pattern, columns)
            if matched and matched not in already_mapped:
                mapping[internal_name] = matched
                already_mapped.add(matched)
                log.debug("Auto-mapped: %-22s → '%s'", internal_name, matched)
                break

    unmapped = [c for c in columns if c not in already_mapped]
    log_source = _detect_log_source(columns)

    schema_map = SchemaMap(
        mapping=mapping,
        display_names=display_names,
        unmapped_cols=unmapped,
        log_source=log_source,
        original_cols=columns,
    )

    log.info("Schema detection complete — source: %s | mapped: %d/%d fields",
             log_source, len(mapping), len(FIELD_REGISTRY))
    return schema_map


# ── DataFrame normalisation ───────────────────────────────────────────────────

def normalise_dataframe(df: pd.DataFrame,
                        schema_map: SchemaMap) -> pd.DataFrame:
    """
    Add standard internal columns to df, derived from the schema map.
    Original columns are preserved unchanged.
    All internal columns are prefixed with _ to avoid collisions.
    """
    df = df.copy().fillna("")

    for internal_name, raw_col in schema_map.mapping.items():
        if raw_col in df.columns:
            df[internal_name] = df[raw_col].astype(str).replace("nan", "")

    # ── Timestamp normalisation ────────────────────────────────────────────
    if "_ts" in df.columns:
        df["_ts_parsed"] = df["_ts"].apply(_parse_timestamp)
    elif "_ts" not in df.columns:
        # Create a dummy sequential index as timestamp proxy
        df["_ts"]        = pd.RangeIndex(len(df)).astype(str)
        df["_ts_parsed"] = pd.NaT

    # ── Process name normalisation (basename only) ─────────────────────────
    if "_process" in df.columns:
        df["_proc_name"] = df["_process"].apply(
            lambda x: str(x).lower().replace("/", "\\").split("\\")[-1].strip()
        )
    else:
        df["_proc_name"] = ""

    if "_parent" in df.columns:
        df["_parent_name"] = df["_parent"].apply(
            lambda x: str(x).lower().replace("/", "\\").split("\\")[-1].strip()
        )
    else:
        df["_parent_name"] = ""

    # ── PID cleaning ───────────────────────────────────────────────────────
    if "_pid" in df.columns:
        df["_pid_int"] = (
            df["_pid"].astype(str).str.replace(",", "", regex=False)
            .pipe(pd.to_numeric, errors="coerce").fillna(0).astype(int)
        )

    return df


def _parse_timestamp(ts_str: str) -> pd.Timestamp:
    """Parse timestamps in any common format."""
    s = re.sub(r"\s*@\s*", " ", str(ts_str))
    try:
        return pd.to_datetime(s, infer_datetime_format=True)
    except Exception:
        return pd.NaT


# ── Universal row getter ───────────────────────────────────────────────────────

def rget(row: pd.Series, internal_name: str,
         schema_map: SchemaMap, default: str = "") -> str:
    """
    Get a field value from a normalised row using the internal field name.
    Falls back to the raw column if the internal column wasn't added.
    """
    # Try internal column first (added by normalise_dataframe)
    if internal_name in row.index:
        val = row[internal_name]
        s = str(val) if val is not None else ""
        return "" if s in ("nan", "None", "-") else s

    # Try raw mapped column
    raw_col = schema_map.col(internal_name)
    if raw_col and raw_col in row.index:
        val = row[raw_col]
        s = str(val) if val is not None else ""
        return "" if s in ("nan", "None", "-") else s

    return default


# ── Field-map config helper ───────────────────────────────────────────────────

def load_field_map_overrides(config_path: str) -> dict:
    """
    Load manual field map overrides from a JSON file.
    Format:
        {
          "_ts":      "log_time",
          "_process": "app_name",
          "_dst_ip":  "remote_host"
        }
    """
    import json
    from pathlib import Path
    p = Path(config_path)
    if not p.exists():
        return {}
    try:
        with open(p) as f:
            data = json.load(f)
        log.info("Loaded %d field map overrides from %s", len(data), config_path)
        return data
    except Exception as e:
        log.warning("Could not load field map from %s: %s", config_path, e)
        return {}
