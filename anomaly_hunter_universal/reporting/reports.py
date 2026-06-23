"""
reporting/reports.py  -  Anomaly Hunter v3
===========================================
CSV report writer. Saves all DataFrames to the output directory.
Every save is safe — empty DataFrames write an empty file with headers.
"""

import logging
from pathlib import Path

import pandas as pd

from config.config import OUTPUT_FILES

log = logging.getLogger("AnomalyHunter.Reports")


def _safe_save(df: pd.DataFrame, path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    if df is None or df.empty:
        pd.DataFrame().to_csv(path, index=False)
    else:
        df.to_csv(path, index=False)
    log.debug("Saved: %s  (%d rows)", path, 0 if (df is None or df.empty) else len(df))


def save_all_csv(
    output_dir:    str,
    alerts_df:     pd.DataFrame,
    queue_df:      pd.DataFrame,
    chain_df:      pd.DataFrame,
    timeline_df:   pd.DataFrame,
    kill_chain_df: pd.DataFrame,
    incidents_df:  pd.DataFrame,
    ioc_df:        pd.DataFrame,
    tree_df:       pd.DataFrame,
    beacon_df:     pd.DataFrame,
) -> dict:
    """
    Write all DataFrames to <output_dir>/<filename>.csv.
    Returns a dict mapping report name → full file path.
    """
    d = Path(output_dir)
    d.mkdir(parents=True, exist_ok=True)

    files = {}

    def _out(key: str) -> str:
        return str(d / OUTPUT_FILES[key])

    # Anomaly report (all enriched alerts, sorted by risk)
    anomaly_sorted = (
        alerts_df.sort_values("Risk Score", ascending=False)
        if not alerts_df.empty else alerts_df
    )
    _safe_save(anomaly_sorted, _out("anomaly_report"))
    files["anomaly_report"] = _out("anomaly_report")

    # Investigation queue (MEDIUM+ only, no FP-suppressed)
    queue_sorted = (
        queue_df.sort_values("Risk Score", ascending=False)
        if not queue_df.empty else queue_df
    )
    _safe_save(queue_sorted, _out("investigation_queue"))
    files["investigation_queue"] = _out("investigation_queue")

    # Attack chain
    chain_sorted = (
        chain_df.sort_values("Chain Risk Score", ascending=False)
        if (not chain_df.empty and "Chain Risk Score" in chain_df.columns) else chain_df
    )
    _safe_save(chain_sorted, _out("attack_chain"))
    files["attack_chain"] = _out("attack_chain")

    # Timeline
    _safe_save(timeline_df, _out("timeline"))
    files["timeline"] = _out("timeline")

    # Kill chain narrative
    _safe_save(kill_chain_df, _out("kill_chain"))
    files["kill_chain"] = _out("kill_chain")

    # Correlated incidents
    _safe_save(incidents_df, _out("correlation"))
    files["correlation"] = _out("correlation")

    # IOC summary
    _safe_save(ioc_df, _out("ioc_summary"))
    files["ioc_summary"] = _out("ioc_summary")

    # Process tree
    _safe_save(tree_df, _out("process_tree"))
    files["process_tree"] = _out("process_tree")

    # Sigma alerts (filtered from anomaly report)
    if not alerts_df.empty and "Detection Type" in alerts_df.columns:
        sigma_df = alerts_df[
            alerts_df["Detection Type"].str.contains("Sigma", na=False)
        ]
        _safe_save(sigma_df, _out("sigma_alerts"))
        files["sigma_alerts"] = _out("sigma_alerts")

    # Beaconing
    if beacon_df is not None and not beacon_df.empty:
        beacon_path = str(d / "beaconing_report.csv")
        _safe_save(beacon_df, beacon_path)
        files["beaconing"] = beacon_path

    log.info("CSV reports written to: %s", output_dir)
    return files
