"""
main.py  -  Anomaly Hunter Universal
======================================
Universal threat hunting platform.
Accepts ANY log CSV (or JSON/XLSX) regardless of field names.

Auto-detects: Elastic ECS, Sysmon, Windows EventLog, AWS CloudTrail,
              Zeek, Suricata, Apache/Nginx, CEF, Palo Alto, Fortinet,
              CrowdStrike, and any generic CSV.

Usage:
  python main.py --log logs.csv
  python main.py --log /path/to/any_log.csv --output ./results
  python main.py --log logs.csv --field-map field_map.json
  python main.py --log logs.csv --threat-intel --verbose
  python main.py --log logs.csv --no-html --no-json
"""
import os, sys, logging, argparse, re
from datetime import datetime
from pathlib import Path

import pandas as pd

def setup_logging(verbose=False):
    level   = logging.DEBUG if verbose else logging.INFO
    fmt     = "%(asctime)s [%(levelname)-8s] %(name)-30s  %(message)s"
    logging.basicConfig(level=level, format=fmt, datefmt="%H:%M:%S")
    for lib in ("urllib3","requests","chardet"):
        logging.getLogger(lib).setLevel(logging.WARNING)

sys.path.insert(0, str(Path(__file__).resolve().parent))

from schema_mapper import (
    build_schema_map, normalise_dataframe,
    load_field_map_overrides, SchemaMap
)
from config.config import (
    DEFAULT_OUTPUT_DIR, OUTPUT_FILES,
    load_allowlist, load_external_config, apply_overrides,
)
from detection.detectors        import run_all_detectors
from detection.sigma_engine     import run_sigma_engine
from detection.beaconing_engine import analyse_beaconing
from intelligence.ioc_extractor import extract_all_iocs
from intelligence.threat_intel  import enrich_iocs
from correlation.risk_engine    import enrich_alerts, get_investigation_queue
from correlation.attack_chain   import build_attack_chain_report, build_full_kill_chain, build_attack_timeline
from correlation.correlation_engine import correlate_alerts
from investigation.process_tree    import build_process_tree, render_ascii_tree
from investigation.timeline_engine import build_staged_timeline, render_timeline_text
from investigation.investigation_engine import build_investigation_report
from reporting.reports          import save_all_csv
from reporting.html_report      import generate_html_report
from reporting.executive_report import build_executive_csv, build_json_report, print_terminal_summary

log = logging.getLogger("AnomalyHunter.Main")
VERSION = "Universal 1.0"

SUPPORTED_FORMATS = [".csv", ".json", ".jsonl", ".ndjson", ".xls", ".xlsx", ".tsv", ".log"]

def banner():
    print()
    print("=" * 65)
    print("  ANOMALY HUNTER  —  Universal Edition")
    print(f"  Version {VERSION}")
    print("  Supports: CSV  JSON  XLSX  Syslog  ECS  Sysmon  CloudTrail")
    print("            Zeek  Suricata  CEF  Apache  Nginx  and more")
    print("=" * 65)
    print()

def load_logs(log_file: str) -> pd.DataFrame:
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
        elif ext in (".log",".txt"):
            # Try CSV first, then JSON lines
            try:   df = pd.read_csv(log_file, low_memory=False)
            except:
                try: df = pd.read_json(log_file, lines=True)
                except: raise ValueError(f"Cannot parse {ext} file — try converting to CSV")
        else:
            df = pd.read_csv(log_file, low_memory=False)
    except Exception as e:
        raise ValueError(f"Failed to load {log_file}: {e}")

    df = df.fillna("")
    log.info("Loaded %d rows × %d columns from %s", len(df), len(df.columns), log_file)
    return df

def _step(name, fn, *args, **kwargs):
    t0 = datetime.now()
    log.info("▶ %s", name)
    try:
        result  = fn(*args, **kwargs)
        elapsed = (datetime.now() - t0).total_seconds()
        rows    = len(result) if isinstance(result, pd.DataFrame) else "ok"
        log.info("  ✓ %-35s [%s rows, %.2fs]", name, rows, elapsed)
        return result
    except Exception as e:
        log.error("  ✗ %s failed: %s", name, e, exc_info=True)
        return pd.DataFrame()

def parse_args():
    p = argparse.ArgumentParser(
        description="Anomaly Hunter — Universal Threat Hunting Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --log logs.csv
  python main.py --log sysmon_events.csv --output ./hunt_results
  python main.py --log cloudtrail.json --verbose
  python main.py --log apache_access.log --field-map my_fields.json
  python main.py --log events.csv --threat-intel

Field map JSON format (to manually map columns):
  {
    "_ts":      "log_time",
    "_process": "app_name",
    "_dst_ip":  "remote_host",
    "_cmdline": "query_text"
  }
        """,
    )
    p.add_argument("--log",          default="logs.csv",
                   help="Path to log file (CSV/JSON/XLSX/TSV/LOG)")
    p.add_argument("--output",       default=DEFAULT_OUTPUT_DIR,
                   help="Output directory (default: ./output)")
    p.add_argument("--field-map",    default="",
                   help="JSON file with manual field-name overrides")
    p.add_argument("--config",       default="",
                   help="Path to ah_config.json override file")
    p.add_argument("--allowlist",    default="",
                   help="Path to allowlist.json")
    p.add_argument("--threat-intel", action="store_true",
                   help="Enable live threat intel (requires API keys)")
    p.add_argument("--no-html",      action="store_true",
                   help="Skip HTML report")
    p.add_argument("--no-json",      action="store_true",
                   help="Skip JSON report")
    p.add_argument("--verbose",      action="store_true",
                   help="Debug logging")
    p.add_argument("--show-schema",  action="store_true",
                   help="Print detected field mapping and exit")
    return p.parse_args()

def main():
    args = parse_args()
    setup_logging(args.verbose)
    banner()
    t_start = datetime.now()

    # ── Config ──────────────────────────────────────────────────────────────
    if args.config:
        apply_overrides(load_external_config(args.config))
    default_al = str(Path(__file__).resolve().parent / "config" / "allowlist.json")
    load_allowlist(args.allowlist or default_al)
    if args.threat_intel:
        os.environ["AH_THREAT_INTEL"] = "1"
        log.info("Live threat intelligence ENABLED")

    # ── Load logs ────────────────────────────────────────────────────────────
    raw_df = load_logs(args.log)

    # ── Schema auto-detection ─────────────────────────────────────────────────
    overrides  = load_field_map_overrides(args.field_map) if args.field_map else {}
    schema_map = build_schema_map(raw_df, manual_overrides=overrides)

    print()
    print("SCHEMA DETECTION RESULTS")
    print("=" * 55)
    print(schema_map.summary())
    print("=" * 55)
    print()

    if args.show_schema:
        print("Use --field-map to override any incorrect mappings.")
        sys.exit(0)

    # ── Normalise ─────────────────────────────────────────────────────────────
    norm_df = normalise_dataframe(raw_df, schema_map)

    # ── Phase 1: Detection ────────────────────────────────────────────────────
    print("[Phase 1] Running detection engine...")
    core_alerts  = _step("Core Detectors (21 rules)", run_all_detectors,  norm_df, schema_map)
    sigma_alerts = _step("Sigma Engine   (15 rules)", run_sigma_engine,    norm_df, schema_map)
    beacon_df    = _step("Beaconing Engine",          analyse_beaconing,   norm_df, schema_map)

    # Merge all alert streams
    alert_frames = [f for f in [core_alerts, sigma_alerts, beacon_df]
                    if f is not None and not f.empty]
    if alert_frames:
        # Align columns across all frames
        all_cols = set()
        for f in alert_frames: all_cols.update(f.columns)
        aligned  = []
        for f in alert_frames:
            for col in all_cols:
                if col not in f.columns: f[col] = ""
            aligned.append(f)
        all_raw_alerts = pd.concat(aligned, ignore_index=True)
    else:
        all_raw_alerts = pd.DataFrame()

    log.info("Total raw alerts: %d", len(all_raw_alerts))

    # ── Phase 2: Scoring & Enrichment ─────────────────────────────────────────
    print("\n[Phase 2] Scoring and enrichment...")
    alerts_df = _step("Risk Engine / Enrichment", enrich_alerts,            all_raw_alerts)
    queue_df  = _step("Investigation Queue",       get_investigation_queue,  alerts_df)
    log.info("Enriched: %d alerts | Queue: %d", len(alerts_df), len(queue_df))

    # ── Phase 3: Threat Intelligence ──────────────────────────────────────────
    print("\n[Phase 3] IOC extraction and threat intelligence...")
    ioc_df = _step("IOC Extraction", extract_all_iocs, norm_df, schema_map)
    ioc_df = _step("TI Enrichment",  enrich_iocs,      ioc_df)

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

    # ── Phase 6: Reporting ────────────────────────────────────────────────────
    print("\n[Phase 6] Generating reports...")
    out_dir = args.output
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    csv_files  = save_all_csv(out_dir, alerts_df, queue_df, chain_df,
                               timeline_df, kill_chain_df, incidents_df,
                               ioc_df, tree_df, beacon_df)
    exec_path  = build_executive_csv(investigation, out_dir)

    html_path = ""
    if not args.no_html:
        html_path = generate_html_report(
            investigation,
            str(Path(out_dir) / OUTPUT_FILES["html_report"])
        )

    json_path = ""
    if not args.no_json:
        json_path = build_json_report(investigation, out_dir)

    # ── Phase 7: Terminal summary ─────────────────────────────────────────────
    print("\n[Phase 7] Summary...")
    if isinstance(tree_df, pd.DataFrame) and not tree_df.empty:
        print(render_ascii_tree(tree_df, max_rows=40))
    if isinstance(timeline_df, pd.DataFrame) and not timeline_df.empty:
        print(render_timeline_text(timeline_df.head(15)))
    if isinstance(investigation, dict):
        print_terminal_summary(investigation)

    # ── File listing ──────────────────────────────────────────────────────────
    elapsed = (datetime.now() - t_start).total_seconds()
    print()
    print("=" * 65)
    print("  OUTPUT FILES")
    print("=" * 65)
    all_files = {**csv_files, "executive_summary": exec_path}
    if html_path: all_files["html_report"] = html_path
    if json_path: all_files["json_report"]  = json_path
    for name, path in all_files.items():
        print(f"  {name:<25}  {path}")
    print()
    print(f"  Total analysis time: {elapsed:.1f}s")
    print("=" * 65)
    print()

if __name__ == "__main__":
    main()
