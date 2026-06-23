#!/usr/bin/env python3
"""
main.py  -  Anomaly Hunter Pro
================================
Industry-grade universal threat hunting platform.

New in Pro edition (vs Universal):
  - Vectorised detection engine  (10-50x faster, handles 500K+ events)
  - Machine learning engine       (Isolation Forest, UEBA, Burst, DGA)
  - Live threat intel feeds       (Abuse.ch URLhaus, ThreatFox, MalwareBazaar, OTX)
  - SQLite persistence            (run history, deduplication, analyst verdicts)
  - MITRE ATT&CK Navigator export (navigator_layer.json)
  - Embedded charts in HTML       (severity pie, top processes, timeline, etc.)
  - Real-time watch mode          (--watch flag)
  - Slack / Teams / webhook alerts (via env vars)
  - Full pytest test suite        (51 tests, run: pytest tests/)

Usage:
  python main.py --log logs.csv
  python main.py --log logs.csv --output ./results
  python main.py --log logs.csv --watch
  python main.py --log logs.csv --ml
  python main.py --log logs.csv --threat-feeds
  python main.py --log logs.csv --incremental
  python main.py --log logs.csv --show-schema
  python main.py --log logs.csv --field-map ah_config/field_maps/sysmon.json
"""

import os
import sys
import logging
import argparse
import re
from datetime import datetime
from pathlib import Path

import pandas as pd

def setup_logging(verbose=False):
    level  = logging.DEBUG if verbose else logging.INFO
    fmt    = "%(asctime)s [%(levelname)-8s] %(name)-28s  %(message)s"
    logging.basicConfig(level=level, format=fmt, datefmt="%H:%M:%S")
    for lib in ("urllib3","requests","chardet","matplotlib"):
        logging.getLogger(lib).setLevel(logging.WARNING)

sys.path.insert(0, str(Path(__file__).resolve().parent))

# ── Core imports ──────────────────────────────────────────────────────────────
from schema_mapper import (
    build_schema_map, normalise_dataframe, load_field_map_overrides
)
from ah_config.config import (
    DEFAULT_OUTPUT_DIR, OUTPUT_FILES,
    load_allowlist, load_external_config, apply_overrides,
)

# Detection
from core.vectorised_detectors import run_vectorised_detectors
from detection.sigma_engine     import run_sigma_engine
from detection.beaconing_engine import analyse_beaconing

# ML
from core.ml_engine import run_ml_engine

# Intelligence
from intelligence.ioc_extractor  import extract_all_iocs
from intelligence.threat_intel   import enrich_iocs

# Correlation
from correlation.risk_engine        import enrich_alerts, get_investigation_queue
from correlation.attack_chain       import (
    build_attack_chain_report, build_full_kill_chain, build_attack_timeline
)
from correlation.correlation_engine import correlate_alerts

# Investigation
from investigation.process_tree    import build_process_tree, render_ascii_tree
from investigation.timeline_engine import build_staged_timeline, render_timeline_text
from investigation.investigation_engine import build_investigation_report

# Reporting
from reporting.reports          import save_all_csv
from reporting.html_report      import generate_html_report
from reporting.executive_report import (
    build_executive_csv, build_json_report, print_terminal_summary
)

# Pro additions
from core.persistence    import PersistenceLayer
from core.mitre_navigator import build_navigator_layer
from core.threat_feed    import get_feed_manager
from integrations.notifiers import send_all_notifications, get_configured_channels

VERSION = "Pro 1.0"

SUPPORTED_FORMATS = [".csv",".json",".jsonl",".ndjson",".xls",".xlsx",".tsv",".log"]


def banner():
    print()
    print("=" * 68)
    print("  ANOMALY HUNTER PRO  —  Industry-Grade Threat Hunting Platform")
    print(f"  Version {VERSION}")
    print("  Detection · ML Anomaly · Live TI · Persistence · Navigator")
    print("=" * 68)
    print()


def load_logs(log_file: str) -> pd.DataFrame:
    log = logging.getLogger("AnomalyHunter.Main")
    log.info("Loading: %s", log_file)
    if not Path(log_file).exists():
        raise FileNotFoundError(f"Log file not found: {log_file}")
    ext = Path(log_file).suffix.lower()
    try:
        if ext == ".csv":
            df = pd.read_csv(log_file, low_memory=False)
        elif ext == ".tsv":
            df = pd.read_csv(log_file, sep="\t", low_memory=False)
        elif ext in (".json",):
            try:   df = pd.read_json(log_file)
            except: df = pd.read_json(log_file, lines=True)
        elif ext in (".jsonl",".ndjson"):
            df = pd.read_json(log_file, lines=True)
        elif ext in (".xls",".xlsx"):
            df = pd.read_excel(log_file)
        else:
            try:   df = pd.read_csv(log_file, low_memory=False)
            except: df = pd.read_json(log_file, lines=True)
    except Exception as e:
        raise ValueError(f"Failed to load {log_file}: {e}")
    df = df.fillna("")
    log.info("Loaded %d rows × %d columns", len(df), len(df.columns))
    return df


def _step(name, fn, *args, **kwargs):
    log = logging.getLogger("AnomalyHunter.Main")
    t0  = datetime.now()
    log.info("▶ %s", name)
    try:
        result  = fn(*args, **kwargs)
        elapsed = (datetime.now()-t0).total_seconds()
        rows    = len(result) if isinstance(result, pd.DataFrame) else "ok"
        log.info("  ✓ %-38s [%s rows, %.2fs]", name, rows, elapsed)
        return result
    except Exception as e:
        log.error("  ✗ %s failed: %s", name, e, exc_info=True)
        return pd.DataFrame()


def _merge_alert_frames(frames):
    valid = [f for f in frames if f is not None and not f.empty]
    if not valid:
        return pd.DataFrame()
    all_cols = set()
    for f in valid: all_cols.update(f.columns)
    aligned = []
    for f in valid:
        for col in all_cols:
            if col not in f.columns: f[col] = ""
        aligned.append(f)
    return pd.concat(aligned, ignore_index=True)


def parse_args():
    p = argparse.ArgumentParser(
        description="Anomaly Hunter Pro — Industry-Grade Threat Hunting Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --log logs.csv
  python main.py --log sysmon_events.csv --output ./hunt
  python main.py --log logs.csv --ml --threat-feeds
  python main.py --log logs.csv --watch
  python main.py --log logs.csv --incremental
  python main.py --log logs.csv --show-schema
  python main.py --log logs.csv --field-map ah_config/field_maps/sysmon.json

Notification channels (set env vars before running):
  export AH_SLACK_WEBHOOK="https://hooks.slack.com/services/..."
  export AH_TEAMS_WEBHOOK="https://your-org.webhook.office.com/..."

Threat intel APIs (optional):
  export VT_API_KEY="..."
  export ABUSEIPDB_KEY="..."
  export OTX_API_KEY="..."
        """)
    p.add_argument("--log",           default="logs.csv",
                   help="Log file path (CSV/JSON/XLSX/TSV)")
    p.add_argument("--output",        default=DEFAULT_OUTPUT_DIR,
                   help="Output directory (default: ./output)")
    p.add_argument("--field-map",     default="",
                   help="JSON field-map override file")
    p.add_argument("--config",        default="",
                   help="Runtime config override JSON")
    p.add_argument("--allowlist",     default="",
                   help="Allowlist JSON for FP suppression")
    p.add_argument("--db",            default="",
                   help="SQLite database path (default: anomaly_hunter.db)")
    p.add_argument("--ml",            action="store_true",
                   help="Enable ML anomaly detection (Isolation Forest, UEBA, DGA)")
    p.add_argument("--threat-feeds",  action="store_true",
                   help="Enable live threat intel feeds (Abuse.ch, OTX)")
    p.add_argument("--threat-intel",  action="store_true",
                   help="Enable live VT/AbuseIPDB enrichment")
    p.add_argument("--watch",         action="store_true",
                   help="Real-time file monitoring mode")
    p.add_argument("--incremental",   action="store_true",
                   help="Only report new alerts not seen in previous runs")
    p.add_argument("--no-html",       action="store_true",
                   help="Skip HTML report generation")
    p.add_argument("--no-json",       action="store_true",
                   help="Skip JSON report generation")
    p.add_argument("--show-schema",   action="store_true",
                   help="Print detected schema and exit")
    p.add_argument("--verbose",       action="store_true",
                   help="Debug logging")
    return p.parse_args()


def main():
    args = parse_args()
    setup_logging(args.verbose)
    logger = logging.getLogger("AnomalyHunter.Main")
    banner()
    t_start = datetime.now()

    # ── Config ────────────────────────────────────────────────────────────────
    if args.config:
        apply_overrides(load_external_config(args.config))
    default_al = str(Path(__file__).resolve().parent / "ah_config" / "allowlist.json")
    load_allowlist(args.allowlist or default_al)
    if args.threat_intel:
        os.environ["AH_THREAT_INTEL"] = "1"

    # ── Watch mode ────────────────────────────────────────────────────────────
    if args.watch:
        from integrations.watch_mode import start_watch_mode
        overrides   = load_field_map_overrides(args.field_map) if args.field_map else {}
        raw_df      = load_logs(args.log)
        schema_map  = build_schema_map(raw_df, manual_overrides=overrides)
        start_watch_mode(args.log, process_fn=None, schema_map=schema_map)
        return

    # ── Load ──────────────────────────────────────────────────────────────────
    raw_df = load_logs(args.log)

    # ── Schema ───────────────────────────────────────────────────────────────
    overrides  = load_field_map_overrides(args.field_map) if args.field_map else {}
    schema_map = build_schema_map(raw_df, manual_overrides=overrides)
    print("\nSCHEMA DETECTION")
    print("=" * 55)
    print(schema_map.summary())
    print("=" * 55 + "\n")
    if args.show_schema:
        print("Use --field-map to override. Exiting.")
        return

    norm_df = normalise_dataframe(raw_df, schema_map)

    # ── Persistence init ──────────────────────────────────────────────────────
    db_path = args.db or str(Path(__file__).resolve().parent / "anomaly_hunter.db")
    db = PersistenceLayer(db_path)
    run_id = db.start_run(args.log, schema_map.log_source)
    logger.info("Run ID: %s", run_id)

    # ── Threat feeds ──────────────────────────────────────────────────────────
    feed_mgr = None
    if args.threat_feeds:
        print("[Feeds] Loading threat intel feeds...")
        feed_mgr = get_feed_manager(offline=False)

    # ── Phase 1: Detection ────────────────────────────────────────────────────
    print("[Phase 1] Running detection engine...")
    core_alerts  = _step("Vectorised Detectors (18 rules)",run_vectorised_detectors, norm_df, schema_map)
    sigma_alerts = _step("Sigma Engine (15 rules)",        run_sigma_engine,          norm_df, schema_map)
    beacon_df    = _step("Beaconing Engine",               analyse_beaconing,         norm_df, schema_map)

    # Optional ML
    ml_alerts = pd.DataFrame()
    if args.ml:
        print("[Phase 1b] Running ML anomaly detection...")
        ml_alerts = _step("ML Engine (IF + UEBA + Burst + DGA)", run_ml_engine, norm_df, schema_map)

    all_raw_alerts = _merge_alert_frames([core_alerts, sigma_alerts, beacon_df, ml_alerts])
    logger.info("Total raw alerts: %d", len(all_raw_alerts))

    # ── Phase 2: Scoring ──────────────────────────────────────────────────────
    print("\n[Phase 2] Scoring and enrichment...")
    alerts_df = _step("Risk Engine",          enrich_alerts,           all_raw_alerts)
    queue_df  = _step("Investigation Queue",  get_investigation_queue, alerts_df)

    # Incremental mode: filter to new-only alerts
    if args.incremental and not alerts_df.empty:
        original_count = len(alerts_df)
        alerts_df = db.get_new_alerts_since_last_run(alerts_df, run_id)
        queue_df  = get_investigation_queue(alerts_df)
        logger.info("Incremental: %d new (suppressed %d seen before)",
                    len(alerts_df), original_count - len(alerts_df))

    logger.info("Enriched: %d | Queue: %d", len(alerts_df), len(queue_df))

    # ── Phase 3: Threat Intelligence ─────────────────────────────────────────
    print("\n[Phase 3] IOC extraction and threat intelligence...")
    ioc_df = _step("IOC Extraction", extract_all_iocs, norm_df, schema_map)
    ioc_df = _step("TI Enrichment",  enrich_iocs,      ioc_df)

    # Feed-based enrichment
    if feed_mgr and ioc_df is not None and not ioc_df.empty:
        ioc_df = _step("Feed Enrichment", feed_mgr.enrich_ioc_df, ioc_df)

    # ── Phase 4: Correlation ──────────────────────────────────────────────────
    print("\n[Phase 4] Correlation and attack chain analysis...")
    incidents_df  = _step("Correlation Engine",  correlate_alerts,          alerts_df)
    chain_df      = _step("Attack Chain",         build_attack_chain_report, alerts_df, raw_df)
    kill_chain_df = _step("Kill Chain Narrative", build_full_kill_chain,     alerts_df, raw_df)

    # ── Phase 5: Investigation ────────────────────────────────────────────────
    print("\n[Phase 5] Investigation analysis...")
    tree_df     = _step("Process Tree",    build_process_tree,    norm_df, alerts_df, schema_map)
    timeline_df = _step("Attack Timeline", build_staged_timeline, alerts_df)
    investigation = _step(
        "Investigation Report",
        build_investigation_report,
        raw_df, alerts_df, queue_df, incidents_df,
        kill_chain_df, timeline_df, ioc_df, tree_df, beacon_df,
    )

    # ── Phase 6: Persist ─────────────────────────────────────────────────────
    print("\n[Phase 6] Saving to database...")
    db.save_alerts(alerts_df, run_id)
    db.save_iocs(ioc_df, run_id)
    db.save_incidents(incidents_df, run_id)
    stats = investigation.get("stats", {}) if isinstance(investigation, dict) else {}
    sev_counts = investigation.get("severity_counts", {}) if isinstance(investigation, dict) else {}
    db.finish_run(run_id, {**stats, **sev_counts})

    # ── Phase 7: Reports ──────────────────────────────────────────────────────
    print("\n[Phase 7] Generating reports...")
    out_dir = args.output
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    csv_files = save_all_csv(
        out_dir, alerts_df, queue_df, chain_df,
        timeline_df, kill_chain_df, incidents_df,
        ioc_df, tree_df, beacon_df,
    )
    exec_path = build_executive_csv(investigation, out_dir)

    # MITRE Navigator
    nav_path = str(Path(out_dir) / "navigator_layer.json")
    _step("MITRE Navigator Export", build_navigator_layer, alerts_df, nav_path)

    html_path = ""
    if not args.no_html:
        html_path = generate_html_report(
            investigation,
            str(Path(out_dir) / OUTPUT_FILES["html_report"])
        )

    json_path = ""
    if not args.no_json:
        json_path = build_json_report(investigation, out_dir)

    # ── Phase 8: Notifications ────────────────────────────────────────────────
    channels = get_configured_channels()
    if channels:
        print(f"\n[Phase 8] Sending notifications → {', '.join(channels)}...")
        send_all_notifications(alerts_df, incidents_df, run_id)

    # ── Terminal output ───────────────────────────────────────────────────────
    print("\n[Summary]")
    if isinstance(tree_df, pd.DataFrame) and not tree_df.empty:
        print(render_ascii_tree(tree_df, max_rows=35))
    if isinstance(timeline_df, pd.DataFrame) and not timeline_df.empty:
        print(render_timeline_text(timeline_df.head(12)))
    if isinstance(investigation, dict):
        print_terminal_summary(investigation)

    # DB summary
    db_summary = db.get_summary()
    print(f"\n  Database: {db_path}")
    print(f"  Total runs stored:   {db_summary.get('Total Runs',0)}")
    print(f"  Total alerts stored: {db_summary.get('Total Alerts (all)',0)}")
    print(f"  Open alerts:         {db_summary.get('Open Alerts',0)}")

    # ── File list ─────────────────────────────────────────────────────────────
    elapsed = (datetime.now() - t_start).total_seconds()
    print()
    print("=" * 68)
    print("  OUTPUT FILES")
    print("=" * 68)
    all_files = {**csv_files, "executive_summary": exec_path,
                 "navigator_layer": nav_path}
    if html_path: all_files["html_report"] = html_path
    if json_path: all_files["json_report"]  = json_path
    for name, path in all_files.items():
        size_kb = Path(path).stat().st_size // 1024 if Path(path).exists() else 0
        print(f"  {name:<26}  {path}  ({size_kb}KB)")
    print()
    print(f"  Run ID:       {run_id}")
    print(f"  Total time:   {elapsed:.1f}s")
    print("=" * 68)
    print()


if __name__ == "__main__":
    main()
