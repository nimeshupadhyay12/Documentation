#.internal.alerts-security.alerts-default*
#logs-o365.audit-*
"""
Microsoft 365 Rare Location Login Detection & Investigation
================================================================================
Alert Rule  : Alert Rule Name 
================================================================================

VERIFIED FIELD MAP (from live logs-o365.audit-* document):
  user.id                              → full email  
  user.name                            → short name 
  user.email                           → full email  (same as user.id)
  user.domain                          → tenant domain
  o365.audit.UserId                    → full email  (primary identity key)
  o365.audit.ActorIpAddress            → source IP   (fallback)
  o365.audit.ResultStatus              → "Success" / "Failure"
  o365.audit.ApplicationId             → app GUID
  o365.audit.CreationTime              → event creation time (string)
  o365.audit.DeviceProperties[]        → OS, BrowserType (array of {Name, Value})
  source.ip                            → primary IP
  source.geo.country_name              → e.g. "India"
  source.geo.country_iso_code          → e.g. "IN"
  source.geo.city_name                 → e.g. "South West"
  source.geo.region_name               → e.g. "National Capital Territory of Delhi"
  source.geo.continent_name            → e.g. "Asia"
  source.as.number                     → e.g. 9498
  source.as.organization.name          → e.g. "BHARTI Airtel Ltd."
  user_agent.name                      → e.g. "Firefox"
  user_agent.version                   → e.g. "151.0"
  user_agent.os.name                   → e.g. "Windows"
  user_agent.os.version                → e.g. "10"
  user_agent.os.full                   → e.g. "Windows 10"
  user_agent.original                  → full UA string
  event.action                         → "UserLoggedIn"
  event.outcome                        → "success"
  event.provider                       → "AzureActiveDirectory"
  data_stream.namespace                → customer tenant namespace
  host.name                            → tenant domain
  client.ip / client.address           → source IP (alternate)
  @timestamp                           → ISO8601 UTC

Dependencies:
    pip install elasticsearch>=8.0.0 pandas>=2.0.0 urllib3>=2.0.0 openpyxl>=3.1.0

Usage:
    python Alert_Automation.py
================================================================================
"""

# STANDARD LIBRARY IMPORTS
import os
import sys
import json
import smtplib
import ssl
import logging
import logging.handlers
import time
import re
import socket
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import Counter, defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

try:
    from elasticsearch import Elasticsearch
    from elasticsearch.exceptions import NotFoundError
except ImportError:
    print("[FATAL] Run: pip install elasticsearch>=8.0.0")
    sys.exit(1)

try:
    import pandas as pd
except ImportError:
    print("[FATAL] Run: pip install pandas>=2.0.0")
    sys.exit(1)

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[FATAL] Run: pip install urllib3>=2.0.0")
    sys.exit(1)


# CONFIGURATION  — edit before running
CONFIG = {
    "ES_HOST"              : "Elasticsearch Host URL,
    "ELK_API_KEY_PATH"     : "Path to API Key (same folder path copied)",
    "ES_VERIFY_CERTS"      : true or flase,
    "ES_REQUEST_TIMEOUT"   : 60,
    "ES_MAX_RETRIES"       : 3,

    "ALERT_INDEX"          : ".alerts-security.alerts-default*",
    "TARGET_RULE_NAME"     : "Alert Exact Name",
    "ALERT_LOOKBACK_HOURS" : 1,

    "O365_INDEX"           : "logs-o365.audit-*",
    "HISTORY_DAYS"         : 7,
    "O365_PAGE_SIZE"       : 1000,

    "SMTP_SERVER"          : "smtp.gmail.com",
    "SMTP_PORT"            : 587,
    "SMTP_USER"            : "gmail user",
    "SMTP_PASSWORD"        : "gmail app password",
    "EMAIL_FROM"           : "email sender",
    "EMAIL_TO"             : ["email receiver"],
    "EMAIL_SUBJECT_PREFIX" : "[SOC ALERT]",

    "OUTPUT_DIR"           : "output/csv_files",
    "PROCESSED_DB_PATH"    : "output/processed_alerts.json",
    "LOG_FILE_PATH"        : "output/logs/soc_automation.log",

    # ── CSV retention ────────────────────────────────────────────────────────
    # CSV files older than this are deleted automatically at the top of every
    # cycle.  48h keeps the last ~192 files for analyst review; anything older
    # is pruned so the output folder never accumulates indefinitely.
    "CSV_RETENTION_HOURS"  : 48,

    # ── Polling ──────────────────────────────────────────────────────────────
    # RUN_ONCE = False  → the script loops internally every POLL_INTERVAL_SECONDS.
    # Start it once (e.g. in a terminal or as a Windows Service / Task Scheduler
    # one-time launch) and it will self-schedule every 15 minutes forever.
    # Set to True only if you want Task Scheduler to fire it externally each run.
    "POLL_INTERVAL_SECONDS": 900,      # 900 s = 15 minutes
    "RUN_ONCE"             : False,    # False = self-looping every 15 min

    "LOG_LEVEL"            : "INFO",
    "LOG_MAX_BYTES"        : 10 * 1024 * 1024,
    "LOG_BACKUP_COUNT"     : 5,
}

# ============================================================
#  LOGGING
# ============================================================
def setup_logging(config: dict) -> logging.Logger:
    log_path = Path(config["LOG_FILE_PATH"])
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("SOCAutomation")
    logger.setLevel(getattr(logging, config["LOG_LEVEL"], logging.INFO))

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(funcName)-35s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S UTC"
    )
    fh = logging.handlers.RotatingFileHandler(
        log_path, maxBytes=config["LOG_MAX_BYTES"],
        backupCount=config["LOG_BACKUP_COUNT"], encoding="utf-8"
    )
    fh.setFormatter(fmt)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


# ============================================================
#  API KEY
# ============================================================
def read_api_key(api_path: str, logger: logging.Logger) -> str | None:
    try:
        key = Path(api_path).read_text(encoding="utf-8").strip()
        if not key:
            logger.error("API key file is empty: %s", api_path)
            return None
        logger.info("API key loaded from: %s", api_path)
        return key
    except FileNotFoundError:
        logger.error("API key file not found: %s", api_path)
        return None
    except OSError as exc:
        logger.error("Failed to read API key: %s", exc)
        return None


# ============================================================
#  ELASTICSEARCH CLIENT
# ============================================================
def build_es_client(config: dict, api_key: str, logger: logging.Logger) -> Elasticsearch | None:
    try:
        client = Elasticsearch(
            config["ES_HOST"],
            api_key=api_key,
            verify_certs=config["ES_VERIFY_CERTS"],
            ssl_show_warn=False,
            request_timeout=config["ES_REQUEST_TIMEOUT"],
            max_retries=config["ES_MAX_RETRIES"],
            retry_on_timeout=True,
        )
        if not client.ping():
            logger.error("Elasticsearch not reachable at %s", config["ES_HOST"])
            return None
        info = client.info()
        logger.info(
            "Connected | cluster: %s | version: %s",
            info.get("cluster_name", "?"),
            info.get("version", {}).get("number", "?"),
        )
        return client
    except Exception as exc:
        logger.error("ES client build failed: %s", exc)
        return None


# ============================================================
#  DEDUPLICATION DATABASE
# ============================================================
class ProcessedAlertsDB:
    """JSON-backed store of processed alert UUIDs. Prevents duplicate emails."""

    def __init__(self, db_path: str, logger: logging.Logger):
        self.db_path = Path(db_path)
        self.logger  = logger
        self._db     = self._load()

    def _load(self) -> dict:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if self.db_path.exists():
            try:
                with open(self.db_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.logger.info("Loaded %d processed records from %s", len(data), self.db_path)
                return data
            except (json.JSONDecodeError, OSError) as exc:
                self.logger.warning("Could not load processed DB (%s). Starting fresh.", exc)
        return {}

    def _save(self):
        try:
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(self._db, f, indent=2, default=str)
        except OSError as exc:
            self.logger.error("Failed to save processed DB: %s", exc)

    def is_processed(self, uuid: str) -> bool:
        return uuid in self._db

    def mark_processed(self, uuid: str, metadata: dict):
        self._db[uuid] = {"processed_at": datetime.now(timezone.utc).isoformat(), **metadata}
        self._save()

    def mark_batch_processed(self, uuids: list[str], metadata: dict):
        """Mark multiple UUIDs as processed in a single save."""
        now = datetime.now(timezone.utc).isoformat()
        for uuid in uuids:
            self._db[uuid] = {"processed_at": now, **metadata}
        self._save()

    def __len__(self):
        return len(self._db)


# ============================================================
#  CSV OUTPUT FOLDER CLEANUP  ← ADDED
# ============================================================
def cleanup_old_csvs(config: dict, logger: logging.Logger):
    """
    Delete CSV files in OUTPUT_DIR that are older than CSV_RETENTION_HOURS.

    Called at the top of every poll cycle so the output folder never
    accumulates indefinitely across hundreds of 15-minute runs.
    Files generated in the current cycle are always new (timestamped names)
    and are therefore never deleted on the same run they were created.
    """
    output_dir      = Path(config["OUTPUT_DIR"])
    retention_hours = config.get("CSV_RETENTION_HOURS", 48)
    cutoff          = datetime.now(timezone.utc) - timedelta(hours=retention_hours)

    if not output_dir.exists():
        logger.info("CSV cleanup | output dir does not exist yet — nothing to clean.")
        return

    deleted = 0
    errors  = 0
    for csv_file in output_dir.glob("*.csv"):
        try:
            mtime = datetime.fromtimestamp(csv_file.stat().st_mtime, tz=timezone.utc)
            if mtime < cutoff:
                csv_file.unlink()
                deleted += 1
                logger.debug("CSV deleted: %s (mtime: %s)", csv_file.name, mtime)
        except OSError as exc:
            errors += 1
            logger.warning("Could not delete CSV %s: %s", csv_file.name, exc)

    if deleted or errors:
        logger.info(
            "CSV cleanup done | deleted: %d | errors: %d | retention: %dh | cutoff: %s",
            deleted, errors, retention_hours,
            cutoff.strftime("%Y-%m-%d %H:%M:%S UTC"),
        )
    else:
        logger.info(
            "CSV cleanup | nothing to remove | retention: %dh", retention_hours
        )


# ============================================================
#  STAGE 1 — ALERT DISCOVERY
# ============================================================
def discover_rare_location_alerts(
    es: Elasticsearch, config: dict, logger: logging.Logger
) -> list[dict]:
    """
    Query .internal.alerts-security.alerts-default* for the target rule
    within the lookback window.
    """
    query = {
        "size": 1000,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"term": {"kibana.alert.rule.name": {"value": config["TARGET_RULE_NAME"]}}},
                    {"range": {"@timestamp": {
                        "gte": f"now-{config['ALERT_LOOKBACK_HOURS']}h",
                        "lte": "now"
                    }}}
                ]
            }
        }
    }
    try:
        response = es.search(index=config["ALERT_INDEX"], body=query)
        hits = response.get("hits", {}).get("hits", [])

        # ── Cap warning ── ADDED ─────────────────────────────────────────────
        # If the page is full, there may be more alerts beyond the 1000-hit
        # limit that were silently dropped.  Log a prominent warning so
        # operators know to investigate.  The dedup DB still prevents any
        # already-processed UUID from being re-emailed.
        if len(hits) >= 1000:
            total_val = (
                response.get("hits", {}).get("total", {}).get("value", "?")
            )
            logger.warning(
                "Alert discovery returned %d hits (size cap reached). "
                "Total matching in Elastic: %s. Alerts beyond hit #1000 were NOT retrieved. "
                "Consider reducing ALERT_LOOKBACK_HOURS if this is recurring.",
                len(hits), total_val,
            )

        logger.info("Alert discovery: %d hits (window: last %dh)",
                    len(hits), config["ALERT_LOOKBACK_HOURS"])
        alerts = []
        for hit in hits:
            src = hit.get("_source", {})
            src["_alert_uuid"] = src.get("kibana.alert.uuid", hit.get("_id", ""))
            alerts.append(src)
        return alerts
    except Exception as exc:
        logger.error("Alert discovery failed: %s", exc)
        return []


# ============================================================
#  STAGE 2 — GROUP ALERTS BY USER
# ============================================================
def group_alerts_by_user(
    alerts: list[dict],
    processed_db: ProcessedAlertsDB,
    logger: logging.Logger,
) -> dict[str, list[dict]]:
    """
    Filter out already-processed alert UUIDs, then bucket the remaining
    alerts by user_id (full email).  Returns {user_id: [alert_raw, ...]}
    """
    grouped: dict[str, list[dict]] = defaultdict(list)
    skipped = 0

    for alert in alerts:
        uuid = alert.get("_alert_uuid", "")
        if processed_db.is_processed(uuid):
            skipped += 1
            continue

        # Resolve user_id using same priority chain as extract_alert_context
        user_id = (
            alert.get("o365.audit.UserId")
            or alert.get("user", {}).get("id")
            or alert.get("user", {}).get("email")
            or alert.get("user", {}).get("name")
            or "unknown"
        )
        grouped[user_id].append(alert)

    logger.info(
        "Grouping | total: %d | skipped (dup): %d | unique users with new alerts: %d",
        len(alerts), skipped, len(grouped)
    )
    return dict(grouped)


# ============================================================
#  STAGE 3 & 4 — ALERT VALIDATION & CONTEXT EXTRACTION
# ============================================================
def extract_alert_context(alert: dict, logger: logging.Logger) -> dict | None:
    """
    Pull all investigation fields from one alert document.
    Returns None if mandatory fields are absent.
    """
    alert_uuid    = alert.get("_alert_uuid") or alert.get("kibana.alert.uuid", "")
    rule_name     = alert.get("kibana.alert.rule.name", "")
    severity      = alert.get("kibana.alert.rule.severity") or alert.get("kibana.alert.severity", "")
    risk_score    = alert.get("kibana.alert.risk_score", "")
    reason        = alert.get("kibana.alert.reason", "")
    alert_ts      = alert.get("@timestamp", "")

    user_id = (
        alert.get("o365.audit.UserId")
        or alert.get("user", {}).get("id")
        or alert.get("user", {}).get("email")
        or alert.get("user", {}).get("name")
    )
    user_name   = alert.get("user", {}).get("name", "")
    user_domain = alert.get("user", {}).get("domain", "")

    namespace = (
        alert.get("data_stream", {}).get("namespace")
        or alert.get("kibana.alert.original_data_stream.namespace", "")
    )

    source_ip = (
        alert.get("source", {}).get("ip")
        or alert.get("client", {}).get("ip")
        or alert.get("o365.audit.ActorIpAddress", "")
    )

    geo           = alert.get("source", {}).get("geo", {})
    country       = geo.get("country_name", "")
    country_code  = geo.get("country_iso_code", "")
    city          = geo.get("city_name", "")
    region        = geo.get("region_name", "")
    continent     = geo.get("continent_name", "")

    asn           = alert.get("source", {}).get("as", {})
    asn_number    = asn.get("number", "")
    asn_org       = asn.get("organization", {}).get("name", "")

    ua            = alert.get("user_agent", {})
    browser       = ua.get("name", "")
    browser_ver   = ua.get("version", "")
    ua_os         = ua.get("os", {})
    os_name       = ua_os.get("name", "")
    os_version    = ua_os.get("version", "")
    os_full       = ua_os.get("full", "")
    ua_original   = ua.get("original", "")

    host_name     = alert.get("host", {}).get("name", "")

    missing = []
    if not alert_uuid : missing.append("kibana.alert.uuid")
    if not user_id    : missing.append("user.id / o365.audit.UserId")
    if not namespace  : missing.append("data_stream.namespace")
    if not source_ip  : missing.append("source.ip")

    if missing:
        logger.warning("Alert validation failed — missing: %s | rule: %s", missing, rule_name)
        return None

    return {
        "alert_uuid"     : alert_uuid,
        "rule_name"      : rule_name,
        "severity"       : severity,
        "risk_score"     : risk_score,
        "reason"         : reason,
        "alert_timestamp": alert_ts,
        "user_id"        : user_id,
        "username"       : user_name,
        "user_domain"    : user_domain,
        "namespace"      : namespace,
        "host_name"      : host_name,
        "source_ip"      : source_ip,
        "asn_number"     : asn_number,
        "asn_org"        : asn_org,
        "country"        : country,
        "country_code"   : country_code,
        "city"           : city,
        "region"         : region,
        "continent"      : continent,
        "browser"        : browser,
        "browser_version": browser_ver,
        "os_name"        : os_name,
        "os_version"     : os_version,
        "os_full"        : os_full,
        "ua_original"    : ua_original,
    }


# ============================================================
#  STAGE 5 — O365 SIGN-IN HISTORY (scroll — unlimited records)
# ============================================================
def fetch_signin_history(
    es: Elasticsearch, ctx: dict, config: dict, logger: logging.Logger
) -> list[dict]:
    """
    Retrieve ALL UserLoggedIn events for the alerted user from logs-o365.audit-*
    over the past HISTORY_DAYS days.
    """
    since_iso = (
        datetime.now(timezone.utc) - timedelta(days=config["HISTORY_DAYS"])
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    user_id   = ctx["user_id"]
    namespace = ctx["namespace"]

    query = {
        "size": config["O365_PAGE_SIZE"],
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": True,
        "query": {
            "bool": {
                "must": [
                    {
                        "bool": {
                            "should": [
                                {"term": {"o365.audit.UserId": user_id}},
                                {"term": {"user.id": user_id}},
                                {"term": {"user.email": user_id}},
                            ],
                            "minimum_should_match": 1
                        }
                    },
                    {"term": {"event.action": "UserLoggedIn"}},
                    {"term": {"event.dataset": "o365.audit"}},
                    {"range": {"@timestamp": {"gte": since_iso, "lte": "now"}}}
                ],
                "filter": [
                    {"term": {"data_stream.namespace": namespace}}
                ]
            }
        }
    }

    logger.info(
        "O365 query | User: %s | Namespace: %s | Since: %s",
        user_id, namespace, since_iso
    )

    all_hits  = []
    scroll_id = None

    try:
        resp      = es.search(index=config["O365_INDEX"], body=query, scroll="5m")
        scroll_id = resp.get("_scroll_id")
        hits      = resp.get("hits", {}).get("hits", [])
        total     = resp.get("hits", {}).get("total", {}).get("value", 0)
        logger.info("O365 total matching: %d | first page: %d", total, len(hits))
        all_hits.extend(hits)

        while hits:
            resp      = es.scroll(scroll_id=scroll_id, scroll="5m")
            scroll_id = resp.get("_scroll_id")
            hits      = resp.get("hits", {}).get("hits", [])
            if hits:
                all_hits.extend(hits)
                logger.debug("Scroll page: %d | running total: %d", len(hits), len(all_hits))

    except NotFoundError:
        logger.warning("O365 index not found: %s", config["O365_INDEX"])
    except Exception as exc:
        logger.error("O365 history query failed: %s", exc)
    finally:
        if scroll_id:
            try:
                es.clear_scroll(scroll_id=scroll_id)
            except Exception:
                pass

    logger.info("O365 records retrieved: %d for user: %s", len(all_hits), user_id)
    return all_hits


# ============================================================
#  STAGE 6 — FIELD EXTRACTION FROM EACH SIGN-IN EVENT
# ============================================================
def _device_property(device_list: list, name: str) -> str:
    if not isinstance(device_list, list):
        return ""
    for item in device_list:
        if isinstance(item, dict) and item.get("Name") == name:
            return item.get("Value", "")
    return ""


def parse_signin_event(hit: dict) -> dict:
    src = hit.get("_source", {})

    raw_ts = src.get("@timestamp", "")
    try:
        dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        timestamp_utc = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        timestamp_utc = raw_ts

    user     = src.get("user", {})
    o365     = src.get("o365", {}).get("audit", {})

    user_id     = o365.get("UserId") or user.get("id") or user.get("email") or user.get("name", "")
    user_domain = user.get("domain", "")

    source_ip = (
        src.get("source", {}).get("ip")
        or src.get("client", {}).get("ip")
        or src.get("client", {}).get("address")
        or o365.get("ActorIpAddress", "")
    )

    geo = src.get("source", {}).get("geo", {})
    ua    = src.get("user_agent", {})
    ua_os = ua.get("os", {})

    device_props = o365.get("DeviceProperties", [])
    dp_session   = _device_property(device_props, "SessionId")

    event = src.get("event", {})

    return {
        "Timestamp (UTC)"           : timestamp_utc,
        "O365 Creation Time"        : o365.get("CreationTime", ""),
        "User ID (Full Email)"      : user_id,
        "User Domain"               : user_domain,
        "Actor IP Address (O365)"   : o365.get("ActorIpAddress", ""),
        "Source IP"                 : source_ip,
        "Country"                   : geo.get("country_name", ""),
        "City"                      : geo.get("city_name", ""),
        "Region"                    : geo.get("region_name", ""),
        "Browser (UA)"              : ua.get("name", ""),
        "Browser Version (UA)"      : ua.get("version", ""),
        "OS Name (UA)"              : ua_os.get("name", ""),
        "OS Version (UA)"           : ua_os.get("version", ""),
        "User Agent String"         : ua.get("original", ""),
        "Is Compliant & Managed"    : _device_property(device_props, "IsCompliantAndManaged"),
        "Session ID"                : dp_session,
        "Result Status (O365)"      : o365.get("ResultStatus", ""),
        "Request Type"              : o365.get("ExtendedProperties", {}).get("RequestType", ""),
        "Event Outcome"             : event.get("outcome", ""),
        "Event Action"              : event.get("action", ""),
        "ES Index"                  : hit.get("_index", ""),
    }


# ============================================================
#  STAGE 7 — DATA QUALITY
# ============================================================
def clean_signin_dataframe(df: pd.DataFrame, logger: logging.Logger) -> pd.DataFrame:
    initial = len(df)
    df = df.drop_duplicates()
    str_cols = df.select_dtypes(include="object").columns
    df[str_cols] = df[str_cols].apply(lambda c: c.str.strip())
    df.replace("", pd.NA, inplace=True)
    df.fillna("N/A", inplace=True)
    if "Country" in df.columns:
        df["Country"] = df["Country"].apply(
            lambda x: x.title() if isinstance(x, str) and x != "N/A" else x
        )
    if "Timestamp (UTC)" in df.columns:
        df = df.sort_values("Timestamp (UTC)", ascending=False).reset_index(drop=True)
    logger.info(
        "Data quality | Initial: %d | After dedup: %d | Removed: %d",
        initial, len(df), initial - len(df)
    )
    return df


# ============================================================
#  STAGE 9 — INVESTIGATION SUMMARY
# ============================================================
def build_investigation_summary(df: pd.DataFrame, ctx: dict) -> dict:
    def most_common(col_name):
        if col_name not in df.columns:
            return "N/A"
        non_na = df[col_name][df[col_name] != "N/A"]
        if non_na.empty:
            return "N/A"
        return Counter(non_na).most_common(1)[0][0]

    def unique_count(col_name):
        if col_name not in df.columns or df.empty:
            return 0
        return df[col_name][df[col_name] != "N/A"].nunique()

    countries_list = "N/A"
    if "Country" in df.columns and not df.empty:
        vals = sorted(df["Country"][df["Country"] != "N/A"].unique().tolist())
        countries_list = ", ".join(vals[:30])

    return {
        "Total Login Events"      : len(df),
        "Unique Countries"        : unique_count("Country"),
        "Countries Observed"      : countries_list,
        "Unique Cities"           : unique_count("City"),
        "Unique Source IPs"       : unique_count("Source IP"),
        "Unique Browsers (UA)"    : unique_count("Browser (UA)"),
        "Unique OS (UA)"          : unique_count("OS Name (UA)"),
        "First Seen (UTC)"        : df["Timestamp (UTC)"].iloc[-1] if not df.empty else "N/A",
        "Last Seen (UTC)"         : df["Timestamp (UTC)"].iloc[0]  if not df.empty else "N/A",
        "Most Common Country"     : most_common("Country"),
        "Most Common Source IP"   : most_common("Source IP"),
        "Most Common Browser"     : most_common("Browser (UA)"),
        "Most Common OS"          : most_common("OS Name (UA)"),
        "Most Common ASN Org"     : most_common("ASN Organization"),
        "Successful Logins"       : len(df[df.get("Result Status (O365)", pd.Series()) == "Success"]) if "Result Status (O365)" in df.columns else "N/A",
        "Alert Triggered Country" : ctx.get("country", "N/A"),
        "Alert Source IP"         : ctx.get("source_ip", "N/A"),
        "Alert Timestamp"         : ctx.get("alert_timestamp", "N/A"),
    }


# ============================================================
#  STAGE 8 — CSV GENERATION
# ============================================================
def generate_csv(
    df: pd.DataFrame, ctx: dict, config: dict, logger: logging.Logger
) -> Path | None:
    Path(config["OUTPUT_DIR"]).mkdir(parents=True, exist_ok=True)
    safe_user = re.sub(r"[^\w@.-]", "_", ctx.get("user_id", "unknown"))
    # For consolidated emails the CSV covers all alerts for this user this cycle
    ts_suffix = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    csv_path  = Path(config["OUTPUT_DIR"]) / f"{safe_user}_{ts_suffix}_signin_history.csv"
    try:
        df.to_csv(csv_path, index=False, encoding="utf-8-sig")
        logger.info("CSV written | %s | rows: %d | size: %.1f KB",
                    csv_path, len(df), csv_path.stat().st_size / 1024)
        return csv_path
    except OSError as exc:
        logger.error("CSV write failed: %s", exc)
        return None


# ============================================================
#  STAGE 10 — CONSOLIDATED HTML EMAIL BODY
# ============================================================
def build_consolidated_email_html(
    user_id: str,
    alert_contexts: list[dict],
    summary: dict,
    csv_path: Path,
) -> str:
    """
    Build one HTML email that covers ALL alerts fired for a single user
    in this poll cycle, plus a combined 7-day investigation summary.
    """
    ist = timezone(timedelta(hours=5, minutes=30))
    now_ist = datetime.now(ist).strftime("%Y-%m-%d %H:%M:%S IST")
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    now_utc = f"{now_ist} ({now_utc})"

    alert_count = len(alert_contexts)

    # Highest severity across all alerts (critical > high > medium > low)
    SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    top_severity = max(
        alert_contexts,
        key=lambda c: SEV_ORDER.get(c.get("severity", "").lower(), 0),
        default={}
    ).get("severity", "medium")

    SEV_COLOR = {
        "critical": "#dc3545", "high": "#fd7e14",
        "medium"  : "#ffc107", "low" : "#28a745"
    }.get(top_severity.lower(), "#6c757d")

    # ── Helpers ──────────────────────────────────────────────────────────────
    def td(label, value, highlight=False):
        bg = "#fff8e1" if highlight else "#ffffff"
        return (
            f'<tr style="background:{bg};">'
            f'<td class="lbl">{label}</td>'
            f'<td class="val">{value}</td>'
            f'</tr>'
        )

    def sec_hdr(title):
        return (
            f'<div class="sec-hdr">{title}</div>'
            f'<table class="data-tbl">'
        )

    def sec_end():
        return '</table>'

    # ── Per-alert accordion blocks ────────────────────────────────────────────
    alert_blocks_html = ""
    for idx, ctx in enumerate(alert_contexts, start=1):
        sev = ctx.get("severity", "N/A")
        sev_color = {
            "critical": "#dc3545", "high": "#fd7e14",
            "medium"  : "#ffc107", "low" : "#28a745"
        }.get(sev.lower(), "#6c757d")

        vt_link = (
            f'<a href="https://www.virustotal.com/gui/ip-address/{ctx["source_ip"]}" '
            f'style="color:#0d6efd;">Check on VirusTotal ↗</a>'
            if ctx.get("source_ip") else "N/A"
        )

        alert_blocks_html += f"""
        <div class="alert-card">
          <div class="alert-card-hdr">
            <span>🚨 Alert #{idx}</span>
            <span class="sev-badge" style="background:{sev_color};">{sev.upper()}</span>
            <span class="alert-card-country">📍 {ctx.get("country","N/A")} &nbsp;|&nbsp; {ctx.get("source_ip","N/A")}</span>
          </div>
          <table class="data-tbl" style="margin-top:0;">
            {td("Alert UUID",      ctx.get("alert_uuid","N/A"))}
            {td("Alert Timestamp", ctx.get("alert_timestamp","N/A"))}
            {td("Risk Score",      ctx.get("risk_score","N/A"))}
            {td("Alert Reason",    ctx.get("reason","N/A"))}
            {td("Source IP",       ctx.get("source_ip","N/A"), highlight=True)}
            {td("Country",         ctx.get("country","N/A"),   highlight=True)}
            {td("City / Region",   f'{ctx.get("city","N/A")} / {ctx.get("region","N/A")}')}
            {td("ASN",             f'{ctx.get("asn_number","N/A")} — {ctx.get("asn_org","N/A")}')}
            {td("Browser",         f'{ctx.get("browser","N/A")} {ctx.get("browser_version","")}'.strip())}
            {td("OS",              ctx.get("os_full","N/A"))}
            {td("User Agent",      ctx.get("ua_original","N/A"))}
            {td("VirusTotal IP",   vt_link)}
            {td("MITRE ATT&CK",   "T1078 / T1078.004 — Valid Accounts · Cloud Accounts")}
            {td("Tactic",          "Initial Access")}
          </table>
        </div>
        """

    # ── Investigation summary rows ────────────────────────────────────────────
    inv_rows = "".join([
        td("Total Login Events (7 days)",  summary.get("Total Login Events",    "N/A"), highlight=True),
        td("Unique Countries",             summary.get("Unique Countries",       "N/A")),
        td("Countries Observed",           summary.get("Countries Observed",     "N/A")),
        td("Unique Cities",                summary.get("Unique Cities",          "N/A")),
        td("Unique Source IPs",            summary.get("Unique Source IPs",      "N/A")),
        td("Unique Browsers",              summary.get("Unique Browsers (UA)",   "N/A")),
        td("Unique Operating Systems",     summary.get("Unique OS (UA)",         "N/A")),
        td("First Login Seen",             summary.get("First Seen (UTC)",       "N/A")),
        td("Last Login Seen",              summary.get("Last Seen (UTC)",        "N/A")),
        td("Most Common Country",          summary.get("Most Common Country",    "N/A")),
        td("Most Common Source IP",        summary.get("Most Common Source IP",  "N/A")),
        td("Most Common Browser",          summary.get("Most Common Browser",    "N/A")),
        td("Most Common OS",               summary.get("Most Common OS",         "N/A")),
        td("Most Common ASN",              summary.get("Most Common ASN Org",    "N/A")),
    ])

    # ── Unique countries list for banner ──────────────────────────────────────
    countries_in_this_batch = sorted({
        c.get("country", "") for c in alert_contexts if c.get("country")
    })
    countries_str = ", ".join(countries_in_this_batch) if countries_in_this_batch else "unknown location(s)"

    # Use first ctx for user/tenant info (same across all alerts for this user)
    first_ctx = alert_contexts[0]

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  * {{ box-sizing: border-box; }}
  body {{
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 14px;
    color: #222;
    margin: 0;
    padding: 0;
    background: #f4f4f4;
    -webkit-text-size-adjust: 100%;
  }}
  .wrap {{
    max-width: 700px;
    width: 100%;
    margin: 16px auto;
    background: #fff;
    border: 1px solid #ccc;
    border-radius: 6px;
    overflow: hidden;
    box-shadow: 0 2px 8px rgba(0,0,0,.12);
  }}
  .hdr {{
    background: #1a1a2e;
    color: #fff;
    padding: 18px 20px;
  }}
  .hdr h2 {{ margin: 0 0 6px; font-size: 16px; line-height: 1.4; word-break: break-word; }}
  .hdr p  {{ margin: 0; font-size: 11px; color: #aaa; }}
  .sev-badge {{
    display: inline-block;
    padding: 2px 10px;
    border-radius: 10px;
    font-size: 11px;
    font-weight: bold;
    vertical-align: middle;
    margin-top: 4px;
  }}
  .body {{ padding: 16px 20px; }}

  /* banner */
  .note {{
    background: #e8f4fd;
    border-left: 4px solid #0d6efd;
    padding: 10px 14px;
    margin: 0 0 16px;
    font-size: 12px;
    color: #084298;
    border-radius: 0 4px 4px 0;
    word-break: break-word;
  }}
  .warn {{
    background: #fff3cd;
    border-left: 4px solid #ffc107;
    padding: 10px 14px;
    margin: 16px 0 0;
    font-size: 12px;
    color: #664d03;
    border-radius: 0 4px 4px 0;
    word-break: break-word;
  }}

  /* section header */
  .sec-hdr {{
    background: #1a1a2e;
    color: #f0f0f0;
    padding: 9px 14px;
    margin: 20px 0 0;
    border-radius: 4px 4px 0 0;
    font-size: 13px;
    letter-spacing: .4px;
    word-break: break-word;
  }}

  /* data table */
  .data-tbl {{
    border-collapse: collapse;
    width: 100%;
    margin-bottom: 4px;
    table-layout: fixed;
  }}
  .data-tbl td {{
    padding: 7px 12px;
    border: 1px solid #dee2e6;
    vertical-align: top;
    word-break: break-word;
    overflow-wrap: anywhere;
    font-size: 13px;
    line-height: 1.5;
  }}
  .data-tbl .lbl {{
    font-weight: bold;
    color: #444;
    width: 38%;
    background: inherit;
  }}
  .data-tbl .val {{ color: #222; }}
  .data-tbl tr[style*="#fff8e1"] {{ background: #fff8e1; }}

  /* per-alert card */
  .alert-card {{
    border: 1px solid #dee2e6;
    border-radius: 4px;
    margin: 12px 0;
    overflow: hidden;
  }}
  .alert-card-hdr {{
    background: #f8f9fa;
    padding: 8px 14px;
    font-size: 13px;
    font-weight: bold;
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    border-bottom: 1px solid #dee2e6;
  }}
  .alert-card-country {{
    font-weight: normal;
    color: #555;
    font-size: 12px;
    margin-left: auto;
  }}

  /* counter pill */
  .count-pill {{
    display: inline-block;
    background: {SEV_COLOR};
    color: #fff;
    font-size: 11px;
    font-weight: bold;
    padding: 2px 10px;
    border-radius: 10px;
    margin-left: 8px;
  }}

  /* footer */
  .foot {{
    background: #f8f9fa;
    border-top: 1px solid #dee2e6;
    padding: 10px 20px;
    font-size: 11px;
    color: #888;
    text-align: center;
    word-break: break-word;
  }}
  a {{ color: #0d6efd; word-break: break-all; }}

  @media only screen and (max-width: 480px) {{
    .wrap {{ margin: 0; border-radius: 0; border-left: none; border-right: none; }}
    .hdr {{ padding: 14px; }}
    .hdr h2 {{ font-size: 14px; }}
    .body {{ padding: 12px 14px; }}
    .sec-hdr {{ font-size: 12px; padding: 8px 12px; }}
    .data-tbl, .data-tbl tbody, .data-tbl tr, .data-tbl td {{
      display: block; width: 100% !important;
    }}
    .data-tbl tr {{ border-bottom: 2px solid #dee2e6; }}
    .data-tbl td {{ border: none; border-top: 1px solid #eee; padding: 5px 10px; }}
    .data-tbl .lbl {{ font-size: 11px; color: #666; padding-bottom: 2px; }}
    .alert-card-hdr {{ flex-direction: column; align-items: flex-start; gap: 4px; }}
    .alert-card-country {{ margin-left: 0; }}
  }}
</style>
</head>
<body>
<div class="wrap">

  <!-- HEADER -->
  <div class="hdr">
    <h2>
      🚨 Microsoft 365 Rare Location Login
      <span class="count-pill">{alert_count} alert{"s" if alert_count > 1 else ""}</span>
    </h2>
    <span class="sev-badge" style="background:{SEV_COLOR};">{top_severity.upper()}</span>
    <p style="margin-top:8px;">
      PKF Algosmic SOC Automation Platform &nbsp;|&nbsp; Generated: {now_utc}
    </p>
  </div>

  <!-- BODY -->
  <div class="body">

    <div class="note">
      ⚠️ <strong>Consolidated Alert:</strong>
      User <strong>{user_id}</strong> triggered
      <strong>{alert_count} rare-location login alert{"s" if alert_count > 1 else ""}</strong>
      from <strong>{countries_str}</strong>.
      All {alert_count} alert{"s are" if alert_count > 1 else " is"} detailed below.
      The attached CSV contains the complete 7-day sign-in history for investigation.
    </div>

    <!-- User & Tenant (common across all alerts) -->
    <div class="sec-hdr">👤 User &amp; Tenant Information</div>
    <table class="data-tbl">
      <tr style="background:#fff8e1;"><td class="lbl">User ID (Full Email)</td><td class="val">{first_ctx.get("user_id","N/A")}</td></tr>
      <tr><td class="lbl">Short Username</td><td class="val">{first_ctx.get("username","N/A")}</td></tr>
      <tr><td class="lbl">User Domain</td><td class="val">{first_ctx.get("user_domain","N/A")}</td></tr>
      <tr><td class="lbl">Tenant Host</td><td class="val">{first_ctx.get("host_name","N/A")}</td></tr>
      <tr style="background:#fff8e1;"><td class="lbl">Customer Namespace</td><td class="val">{first_ctx.get("namespace","N/A")}</td></tr>
      <tr><td class="lbl">Rule Name</td><td class="val">{first_ctx.get("rule_name","N/A")}</td></tr>
    </table>

    <!-- Individual Alert Cards -->
    <div class="sec-hdr">🔔 Individual Alert Details ({alert_count} alert{"s" if alert_count > 1 else ""})</div>
    {alert_blocks_html}

    <!-- 7-Day Investigation Summary -->
    <div class="sec-hdr">📊 7-Day Sign-in Investigation Summary (Across All Alerts)</div>
    <table class="data-tbl">
      {inv_rows}
    </table>

    <div class="warn">
      📎 Attached: <strong>{csv_path.name if csv_path else "N/A"}</strong>
      — Full 7-day sign-in history export with {summary.get("Total Login Events","?")} records.
      All timestamps in UTC. Open in Excel (UTF-8 BOM encoded).
    </div>

  </div><!-- /body -->

  <!-- FOOTER -->
  <div class="foot">
    PKF Algosmic SOC Automation Platform &nbsp;|&nbsp;
    {alert_count} alert{"s" if alert_count > 1 else ""} consolidated for: {user_id} &nbsp;|&nbsp;
    Do not reply &nbsp;|&nbsp; All times UTC
  </div>

</div><!-- /wrap -->
</body></html>"""


# ============================================================
#  STAGE 11 — EMAIL DELIVERY
# ============================================================
def send_consolidated_alert_email(
    user_id: str,
    alert_contexts: list[dict],
    summary: dict,
    csv_path: Path,
    config: dict,
    logger: logging.Logger,
) -> bool:
    """Send one email covering all alerts for a single user in this cycle."""
    alert_count  = len(alert_contexts)
    first_ctx    = alert_contexts[0]

    # Highest severity for subject line
    SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    top_sev = max(
        alert_contexts,
        key=lambda c: SEV_ORDER.get(c.get("severity", "").lower(), 0),
        default={}
    ).get("severity", "medium").upper()

    # All unique countries triggered
    countries = sorted({c.get("country","?") for c in alert_contexts if c.get("country")})
    country_str = "/".join(countries) if countries else "?"

    subject = (
        f"{config['EMAIL_SUBJECT_PREFIX']} M365 Rare Location Login | "
        f"{top_sev} | "
        f"User: {user_id} | "
        f"{alert_count} alert{'s' if alert_count > 1 else ''} | "
        f"Countries: {country_str} | "
        f"NS: {first_ctx.get('namespace','?')}"
    )

    msg = MIMEMultipart("mixed")
    msg["From"]        = config["EMAIL_FROM"]
    msg["To"]          = ", ".join(config["EMAIL_TO"])
    msg["Subject"]     = subject
    msg["X-User-ID"]   = user_id
    msg["X-Namespace"] = first_ctx.get("namespace", "")
    msg["X-Alert-Count"] = str(alert_count)

    html_body = build_consolidated_email_html(user_id, alert_contexts, summary, csv_path)
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    # Attach CSV
    if csv_path and csv_path.exists():
        try:
            with open(csv_path, "rb") as f:
                data = f.read()
            part = MIMEBase("application", "octet-stream")
            part.set_payload(data)
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", "attachment", filename=csv_path.name)
            msg.attach(part)
            logger.info("CSV attached: %s (%.1f KB)", csv_path.name, len(data) / 1024)
        except OSError as exc:
            logger.warning("CSV attach failed: %s", exc)
    else:
        logger.warning("CSV not found for attachment: %s", csv_path)

    try:
        logger.info("Sending consolidated email for user: %s (%d alerts) to: %s",
                    user_id, alert_count, config["EMAIL_TO"])
        with smtplib.SMTP(config["SMTP_SERVER"], config["SMTP_PORT"], timeout=30) as srv:
            srv.ehlo()
            srv.starttls(context=ssl.create_default_context())
            srv.ehlo()
            srv.login(config["SMTP_USER"], config["SMTP_PASSWORD"])
            srv.sendmail(config["EMAIL_FROM"], config["EMAIL_TO"], msg.as_string())
        logger.info("✅ Consolidated email sent | User: %s | Alerts: %d", user_id, alert_count)
        return True
    except smtplib.SMTPAuthenticationError as exc:
        logger.error("SMTP auth failed: %s", exc)
    except smtplib.SMTPException as exc:
        logger.error("SMTP error: %s", exc)
    except socket.timeout:
        logger.error("SMTP timeout")
    except Exception as exc:
        logger.error("Email send error: %s", exc)
    return False


# ============================================================
#  CORE PIPELINE — process all alerts for ONE user → 1 email
# ============================================================
def process_alerts_for_user(
    user_id: str,
    raw_alerts: list[dict],
    es: Elasticsearch,
    processed_db: ProcessedAlertsDB,
    config: dict,
    logger: logging.Logger,
) -> bool:
    """
    Given all unprocessed raw alerts for a single user:
      1. Validate & extract context for each alert
      2. Fetch O365 sign-in history ONCE for the user
      3. Build combined CSV + 7-day summary
      4. Send ONE consolidated email listing all alert cards
      5. Mark ALL alert UUIDs as processed in a single DB write
    Returns True if the email was sent successfully.
    """
    logger.info("━" * 70)
    logger.info("Processing user: %s | %d alert(s)", user_id, len(raw_alerts))

    # Stage 3 — validate each alert and collect contexts
    alert_contexts = []
    valid_uuids    = []
    for alert_raw in raw_alerts:
        ctx = extract_alert_context(alert_raw, logger)
        if ctx:
            alert_contexts.append(ctx)
            valid_uuids.append(ctx["alert_uuid"])
        else:
            logger.warning("Skipping invalid alert for user: %s", user_id)

    if not alert_contexts:
        logger.warning("No valid alert contexts for user: %s — skipping.", user_id)
        return False

    # Use first valid context to drive the O365 history query
    # (user_id and namespace are the same across all alerts for this user)
    primary_ctx = alert_contexts[0]

    # Stage 5 — fetch O365 history ONCE per user
    raw_events = fetch_signin_history(es, primary_ctx, config, logger)

    if not raw_events:
        logger.warning("No sign-in history found for user: %s. Emailing alert context only.", user_id)
        df      = pd.DataFrame()
        summary = build_investigation_summary(df, primary_ctx)
    else:
        # Stage 6 — parse
        parsed  = [parse_signin_event(h) for h in raw_events]
        df_raw  = pd.DataFrame(parsed)
        # Stage 7 — clean
        df      = clean_signin_dataframe(df_raw, logger)
        # Stage 9 — summarise
        summary = build_investigation_summary(df, primary_ctx)

    # Stage 8 — CSV (one file per user per cycle)
    csv_path = generate_csv(df, primary_ctx, config, logger)

    # Stage 10 & 11 — consolidated email
    email_sent = send_consolidated_alert_email(
        user_id, alert_contexts, summary, csv_path, config, logger
    )

    # Stage 12 — persist all UUIDs for this user in one write
    processed_db.mark_batch_processed(valid_uuids, {
        "user"         : user_id,
        "namespace"    : primary_ctx["namespace"],
        "alert_count"  : len(alert_contexts),
        "countries"    : list({c.get("country","") for c in alert_contexts}),
        "email_sent"   : email_sent,
        "csv_path"     : str(csv_path) if csv_path else "",
        "total_events" : summary.get("Total Login Events", 0),
    })

    logger.info(
        "Done | User: %s | alerts: %d | email_sent: %s | signin_records: %d",
        user_id, len(alert_contexts), email_sent, summary.get("Total Login Events", 0)
    )
    return email_sent


# ============================================================
#  MAIN ORCHESTRATION LOOP
# ============================================================
def run_automation(config: dict, logger: logging.Logger):
    logger.info("=" * 70)
    logger.info("PKF Algosmic SOC Automation — v3.0.0 (consolidated per-user email)")
    logger.info("Rule  : %s", config["TARGET_RULE_NAME"])
    logger.info("Alerts: %s", config["ALERT_INDEX"])
    logger.info("O365  : %s", config["O365_INDEX"])
    logger.info(
        "Schedule: self-looping every %ds | lookback: %dh | CSV retention: %dh",
        config["POLL_INTERVAL_SECONDS"],
        config["ALERT_LOOKBACK_HOURS"],
        config.get("CSV_RETENTION_HOURS", 48),
    )
    logger.info("=" * 70)

    api_key = read_api_key(config["ELK_API_KEY_PATH"], logger)
    if not api_key:
        logger.critical("No API key. Exiting.")
        sys.exit(1)

    es = build_es_client(config, api_key, logger)
    if es is None:
        logger.critical("Cannot connect to Elasticsearch. Exiting.")
        sys.exit(1)

    processed_db = ProcessedAlertsDB(config["PROCESSED_DB_PATH"], logger)
    logger.info("Dedup DB: %d previously processed alerts.", len(processed_db))

    poll = 0
    while True:
        poll += 1
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        logger.info("─" * 70)
        logger.info("Poll cycle #%d | %s", poll, now)

        # ── CSV FOLDER CLEANUP ─────────────────────────────────────────────
        # Runs at the top of every cycle.  Deletes CSV files older than
        # CSV_RETENTION_HOURS so the output folder never accumulates.
        # Files written in the current cycle are always new (timestamp in name)
        # and are therefore never touched by this cleanup.
        logger.info(
            "CSV cleanup (retention: %dh) ...", config.get("CSV_RETENTION_HOURS", 48)
        )
        cleanup_old_csvs(config, logger)

        # Stage 1 — discover alerts
        alerts = discover_rare_location_alerts(es, config, logger)
        logger.info("Found %d alert(s) total.", len(alerts))

        # Stage 2 — group by user, skip already-processed UUIDs
        grouped = group_alerts_by_user(alerts, processed_db, logger)

        if not grouped:
            logger.info("No new alerts to process this cycle.")
        else:
            logger.info(
                "New alerts: %d unique user(s) to process -> 1 email per user.",
                len(grouped)
            )

        emails_sent = 0
        for user_id, user_alerts in grouped.items():
            if process_alerts_for_user(
                user_id, user_alerts, es, processed_db, config, logger
            ):
                emails_sent += 1

        logger.info(
            "Cycle #%d | total alerts: %d | unique users: %d | emails sent: %d",
            poll, len(alerts), len(grouped), emails_sent
        )

        if config.get("RUN_ONCE", False):
            logger.info("RUN_ONCE=True — exiting.")
            break

        nxt = datetime.now(timezone.utc) + timedelta(seconds=config["POLL_INTERVAL_SECONDS"])
        logger.info(
            "Next poll: %s (sleep %ds) ...",
            nxt.strftime("%Y-%m-%d %H:%M:%S UTC"),
            config["POLL_INTERVAL_SECONDS"]
        )
        time.sleep(config["POLL_INTERVAL_SECONDS"])


# ============================================================
#  ENTRY POINT
# ============================================================
if __name__ == "__main__":
    _logger = setup_logging(CONFIG)
    try:
        run_automation(CONFIG, _logger)
    except KeyboardInterrupt:
        _logger.info("Stopped by operator.")
        sys.exit(0)
    except Exception as _exc:
        _logger.critical("Fatal error: %s", _exc, exc_info=True)
        sys.exit(1)
