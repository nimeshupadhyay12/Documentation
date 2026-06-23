"""
core/persistence.py  -  Anomaly Hunter Pro
============================================
SQLite-backed persistent storage layer.

Stores:
  - Every analysis run with metadata
  - All alerts with deduplication across runs
  - IOCs with first/last seen tracking
  - Analyst verdicts and notes (TP/FP/In-Progress)
  - Run comparison (new alerts since last run)

Zero external dependencies — sqlite3 is Python built-in.
Database file: anomaly_hunter.db (in project root by default)
"""

import sqlite3
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from contextlib import contextmanager

import pandas as pd

log = logging.getLogger("AnomalyHunter.Persistence")

DEFAULT_DB = str(Path(__file__).resolve().parent.parent / "anomaly_hunter.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT    UNIQUE NOT NULL,
    log_file        TEXT,
    log_source      TEXT,
    started_at      TEXT,
    finished_at     TEXT,
    total_events    INTEGER DEFAULT 0,
    total_alerts    INTEGER DEFAULT 0,
    critical_count  INTEGER DEFAULT 0,
    high_count      INTEGER DEFAULT 0,
    medium_count    INTEGER DEFAULT 0,
    fp_count        INTEGER DEFAULT 0,
    status          TEXT    DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id        TEXT    UNIQUE NOT NULL,
    run_id          TEXT    NOT NULL,
    timestamp       TEXT,
    process         TEXT,
    parent_process  TEXT,
    detection_type  TEXT,
    risk_score      INTEGER DEFAULT 0,
    severity        TEXT,
    mitre_technique TEXT,
    mitre_name      TEXT,
    destination_ip  TEXT,
    investigation_reason TEXT,
    recommendation  TEXT,
    analyst_status  TEXT    DEFAULT 'new',
    analyst_notes   TEXT    DEFAULT '',
    analyst_updated TEXT,
    created_at      TEXT    DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS iocs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type    TEXT    NOT NULL,
    ioc_value   TEXT    NOT NULL,
    ti_verdict  TEXT    DEFAULT 'Unknown',
    ti_tags     TEXT    DEFAULT '',
    confidence  INTEGER DEFAULT 0,
    first_seen  TEXT,
    last_seen   TEXT,
    seen_count  INTEGER DEFAULT 1,
    run_ids     TEXT    DEFAULT '',
    UNIQUE(ioc_type, ioc_value)
);

CREATE TABLE IF NOT EXISTS incidents (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id     TEXT    UNIQUE NOT NULL,
    run_id          TEXT    NOT NULL,
    incident_type   TEXT,
    severity        TEXT,
    incident_score  INTEGER DEFAULT 0,
    root_process    TEXT,
    mitre_tactics   TEXT,
    c2_ips          TEXT,
    first_seen      TEXT,
    last_seen       TEXT,
    analyst_status  TEXT    DEFAULT 'new',
    created_at      TEXT    DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alerts_run_id    ON alerts(run_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_alert_id  ON alerts(alert_id);
CREATE INDEX IF NOT EXISTS idx_iocs_verdict     ON iocs(ti_verdict);
CREATE INDEX IF NOT EXISTS idx_incidents_run_id ON incidents(run_id);
"""


def _make_run_id() -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    return f"RUN-{ts}"


@contextmanager
def _conn(db_path: str):
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


class PersistenceLayer:
    """
    Main interface for all database operations.

    Usage:
        db = PersistenceLayer()          # uses default DB path
        db = PersistenceLayer("/path/to/ah.db")

        run_id = db.start_run("logs.csv", "Elastic ECS")
        db.save_alerts(alerts_df, run_id)
        db.save_iocs(ioc_df, run_id)
        db.finish_run(run_id, stats)
        new_alerts = db.get_new_alerts_since_last_run(alerts_df)
    """

    def __init__(self, db_path: str = DEFAULT_DB):
        self.db_path = db_path
        self._init_db()
        log.info("Database: %s", db_path)

    def _init_db(self):
        with _conn(self.db_path) as con:
            con.executescript(SCHEMA)

    # ── Run management ────────────────────────────────────────────────────────

    def start_run(self, log_file: str, log_source: str = "") -> str:
        run_id = _make_run_id()
        with _conn(self.db_path) as con:
            con.execute(
                "INSERT OR IGNORE INTO runs "
                "(run_id, log_file, log_source, started_at, status) "
                "VALUES (?,?,?,?,?)",
                (run_id, log_file, log_source,
                 datetime.now().isoformat(), "running")
            )
        log.info("Run started: %s", run_id)
        return run_id

    def finish_run(self, run_id: str, stats: dict):
        with _conn(self.db_path) as con:
            con.execute(
                "UPDATE runs SET finished_at=?, total_events=?, total_alerts=?, "
                "critical_count=?, high_count=?, medium_count=?, fp_count=?, "
                "status=? WHERE run_id=?",
                (
                    datetime.now().isoformat(),
                    stats.get("Total Events", 0),
                    stats.get("Unique Alerts", 0),
                    stats.get("CRITICAL", 0),
                    stats.get("HIGH", 0),
                    stats.get("MEDIUM", 0),
                    stats.get("FP-SUPPRESSED", 0),
                    "complete",
                    run_id,
                )
            )
        log.info("Run finished: %s", run_id)

    def get_runs(self, limit: int = 20) -> pd.DataFrame:
        with _conn(self.db_path) as con:
            rows = con.execute(
                "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
        if not rows:
            return pd.DataFrame()
        return pd.DataFrame([dict(r) for r in rows])

    # ── Alert storage & deduplication ────────────────────────────────────────

    @staticmethod
    def _alert_hash(timestamp: str, process: str, detection_type: str) -> str:
        key = f"{timestamp}{process}{detection_type[:30]}"
        return "AH-" + hashlib.md5(key.encode()).hexdigest()[:8].upper()

    def save_alerts(self, alerts_df: pd.DataFrame, run_id: str) -> int:
        """Save alerts. Returns count of NEW alerts (not seen in previous runs)."""
        if alerts_df.empty:
            return 0

        saved = 0
        with _conn(self.db_path) as con:
            for _, row in alerts_df.iterrows():
                alert_id = row.get("Alert ID") or self._alert_hash(
                    str(row.get("Timestamp", "")),
                    str(row.get("Process", "")),
                    str(row.get("Detection Type", "")),
                )
                try:
                    con.execute(
                        "INSERT OR IGNORE INTO alerts "
                        "(alert_id, run_id, timestamp, process, parent_process, "
                        "detection_type, risk_score, severity, mitre_technique, "
                        "mitre_name, destination_ip, investigation_reason, "
                        "recommendation) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            alert_id, run_id,
                            str(row.get("Timestamp", "")),
                            str(row.get("Process", "")),
                            str(row.get("Parent Process", "")),
                            str(row.get("Detection Type", "")),
                            int(row.get("Risk Score", 0)),
                            str(row.get("Severity", "")),
                            str(row.get("MITRE Technique", "")),
                            str(row.get("MITRE Name", "")),
                            str(row.get("Destination IP", "")),
                            str(row.get("Investigation Reason", ""))[:500],
                            str(row.get("Recommendation", ""))[:300],
                        )
                    )
                    if con.execute(
                        "SELECT changes()"
                    ).fetchone()[0] > 0:
                        saved += 1
                except Exception as e:
                    log.debug("Alert insert skip: %s", e)

        log.info("Alerts saved: %d new out of %d total", saved, len(alerts_df))
        return saved

    def get_new_alerts_since_last_run(self, alerts_df: pd.DataFrame,
                                       current_run_id: str) -> pd.DataFrame:
        """
        Returns subset of alerts_df that are NEW — not seen in any previous run.
        Useful for --incremental mode: only show what changed.
        """
        if alerts_df.empty:
            return alerts_df

        with _conn(self.db_path) as con:
            # Get alert IDs from ALL previous runs (excluding current)
            existing = set(row[0] for row in con.execute(
                "SELECT alert_id FROM alerts WHERE run_id != ?",
                (current_run_id,)
            ).fetchall())

        # If no previous runs exist, everything is new
        if not existing:
            return alerts_df

        def is_new(row):
            aid = row.get("Alert ID") or self._alert_hash(
                str(row.get("Timestamp", "")),
                str(row.get("Process", "")),
                str(row.get("Detection Type", "")),
            )
            return aid not in existing

        mask = alerts_df.apply(is_new, axis=1)
        new_count = mask.sum()
        log.info("New alerts this run: %d (suppressed %d seen before)",
                 new_count, len(alerts_df) - new_count)
        return alerts_df[mask].reset_index(drop=True)

    def update_analyst_verdict(self, alert_id: str, status: str,
                                notes: str = "") -> bool:
        """
        Update analyst verdict for an alert.
        status: 'true_positive' | 'false_positive' | 'in_progress' | 'closed'
        """
        valid = {"true_positive", "false_positive", "in_progress", "closed", "new"}
        if status not in valid:
            log.warning("Invalid analyst status: %s", status)
            return False
        with _conn(self.db_path) as con:
            con.execute(
                "UPDATE alerts SET analyst_status=?, analyst_notes=?, "
                "analyst_updated=? WHERE alert_id=?",
                (status, notes, datetime.now().isoformat(), alert_id)
            )
        return True

    def get_alert_history(self, process: str = "",
                           detection_type: str = "",
                           limit: int = 100) -> pd.DataFrame:
        """Query historical alerts with optional filters."""
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        if process:
            query += " AND process LIKE ?"
            params.append(f"%{process}%")
        if detection_type:
            query += " AND detection_type LIKE ?"
            params.append(f"%{detection_type}%")
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with _conn(self.db_path) as con:
            rows = con.execute(query, params).fetchall()
        if not rows:
            return pd.DataFrame()
        return pd.DataFrame([dict(r) for r in rows])

    # ── IOC tracking ──────────────────────────────────────────────────────────

    def save_iocs(self, ioc_df: pd.DataFrame, run_id: str) -> int:
        if ioc_df.empty:
            return 0
        saved = 0
        with _conn(self.db_path) as con:
            for _, row in ioc_df.iterrows():
                ioc_type  = str(row.get("IOC Type", ""))
                ioc_value = str(row.get("IOC Value", ""))
                if not ioc_type or not ioc_value:
                    continue
                now = datetime.now().isoformat()
                # Try insert; if exists, update last_seen + increment count
                existing = con.execute(
                    "SELECT id, run_ids, seen_count FROM iocs "
                    "WHERE ioc_type=? AND ioc_value=?",
                    (ioc_type, ioc_value)
                ).fetchone()
                if existing:
                    run_ids = existing["run_ids"]
                    if run_id not in run_ids:
                        run_ids = (run_ids + "," + run_id).strip(",")
                    con.execute(
                        "UPDATE iocs SET last_seen=?, seen_count=seen_count+1, "
                        "run_ids=?, ti_verdict=?, ti_tags=?, confidence=? "
                        "WHERE ioc_type=? AND ioc_value=?",
                        (now, run_ids,
                         str(row.get("TI Verdict", "Unknown")),
                         str(row.get("TI Tags", "")),
                         int(row.get("TI Confidence", 0)),
                         ioc_type, ioc_value)
                    )
                else:
                    con.execute(
                        "INSERT INTO iocs (ioc_type, ioc_value, ti_verdict, "
                        "ti_tags, confidence, first_seen, last_seen, run_ids) "
                        "VALUES (?,?,?,?,?,?,?,?)",
                        (ioc_type, ioc_value,
                         str(row.get("TI Verdict", "Unknown")),
                         str(row.get("TI Tags", "")),
                         int(row.get("TI Confidence", 0)),
                         now, now, run_id)
                    )
                    saved += 1
        log.info("IOCs saved: %d new", saved)
        return saved

    def get_known_bad_iocs(self) -> set:
        """Return set of (type, value) tuples for all Malicious IOCs seen before."""
        with _conn(self.db_path) as con:
            rows = con.execute(
                "SELECT ioc_type, ioc_value FROM iocs "
                "WHERE ti_verdict IN ('Malicious','Suspicious')"
            ).fetchall()
        return {(r["ioc_type"], r["ioc_value"]) for r in rows}

    # ── Incident storage ──────────────────────────────────────────────────────

    def save_incidents(self, incidents_df: pd.DataFrame, run_id: str):
        if incidents_df is None or incidents_df.empty:
            return
        with _conn(self.db_path) as con:
            for _, row in incidents_df.iterrows():
                try:
                    con.execute(
                        "INSERT OR IGNORE INTO incidents "
                        "(incident_id, run_id, incident_type, severity, "
                        "incident_score, root_process, mitre_tactics, "
                        "c2_ips, first_seen, last_seen) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (
                            str(row.get("Incident ID", "")),
                            run_id,
                            str(row.get("Incident Type", "")),
                            str(row.get("Severity", "")),
                            int(row.get("Incident Score", 0)),
                            str(row.get("Root Process", "")),
                            str(row.get("MITRE Tactics", "")),
                            str(row.get("C2 IPs", "")),
                            str(row.get("First Seen", "")),
                            str(row.get("Last Seen", "")),
                        )
                    )
                except Exception as e:
                    log.debug("Incident insert skip: %s", e)

    # ── Summary ───────────────────────────────────────────────────────────────

    def get_summary(self) -> dict:
        with _conn(self.db_path) as con:
            total_runs     = con.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
            total_alerts   = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            total_iocs     = con.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
            malicious_iocs = con.execute(
                "SELECT COUNT(*) FROM iocs WHERE ti_verdict='Malicious'"
            ).fetchone()[0]
            open_alerts    = con.execute(
                "SELECT COUNT(*) FROM alerts WHERE analyst_status='new'"
            ).fetchone()[0]
            last_run = con.execute(
                "SELECT run_id, started_at, total_alerts FROM runs "
                "ORDER BY started_at DESC LIMIT 1"
            ).fetchone()

        return {
            "Total Runs":          total_runs,
            "Total Alerts (all)":  total_alerts,
            "Open Alerts":         open_alerts,
            "Total IOCs":          total_iocs,
            "Malicious IOCs":      malicious_iocs,
            "Last Run":            dict(last_run) if last_run else {},
        }
