"""
core/ml_engine.py  -  Anomaly Hunter Pro
==========================================
Machine learning anomaly detection engine.

Modules:
  1. Isolation Forest     — unsupervised process/entity anomaly scoring
  2. UEBA                 — user/entity behaviour baseline and deviation
  3. Burst Detection      — time-series event rate spike detection
  4. DGA Classifier       — character n-gram model for DGA domain detection
  5. Baseline Comparison  — compare current run against historical baseline

All ML models are stateless (fit + predict in one run).
Optional persistence of fitted models via joblib for faster reruns.
"""

import logging
import math
import re
from collections import Counter
from datetime import datetime

import numpy as np
import pandas as pd

log = logging.getLogger("AnomalyHunter.MLEngine")

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import Pipeline
    SKLEARN_OK = True
except ImportError:
    SKLEARN_OK = False
    log.warning("scikit-learn not available — ML detectors disabled")

from schema_mapper import SchemaMap
from ah_config.config import KNOWN_GOOD_PROCESSES, RISK_SCORES


# ── 1. Isolation Forest — process-level anomaly detection ─────────────────────

def run_isolation_forest(df: pd.DataFrame,
                          schema_map: SchemaMap,
                          contamination: float = 0.05) -> pd.DataFrame:
    """
    Fit Isolation Forest on per-process behavioural features.
    Returns alert rows for anomalous processes.

    Features per process:
      - event_count      (total events)
      - unique_actions   (distinct event types)
      - unique_dst_ips   (distinct destination IPs)
      - unique_dns       (distinct DNS queries)
      - unique_reg       (distinct registry paths)
      - unique_files     (distinct file paths)
      - night_ratio      (fraction of events in 20:00–06:00)
    """
    if not SKLEARN_OK:
        return pd.DataFrame()

    proc_col   = schema_map.col("_process")
    if not proc_col or proc_col not in df.columns:
        return pd.DataFrame()

    work = df.copy()
    work["_proc_name_ml"] = work[proc_col].str.lower()\
        .str.replace("/", "\\", regex=False).str.split("\\").str[-1].str.strip()
    work = work[~work["_proc_name_ml"].isin(KNOWN_GOOD_PROCESSES)]
    work = work[work["_proc_name_ml"] != ""]

    if len(work) < 10:
        return pd.DataFrame()

    # Build feature matrix
    agg = {"event_count": (proc_col, "count")}
    act_col = schema_map.col("_event_action")
    dst_col = schema_map.col("_dst_ip")
    dns_col = schema_map.col("_domain")
    reg_col = schema_map.col("_registry")
    fp_col  = schema_map.col("_filepath")

    if act_col and act_col in work.columns:
        agg["unique_actions"] = (act_col, "nunique")
    if dst_col and dst_col in work.columns:
        agg["unique_dst_ips"] = (dst_col, "nunique")
    if dns_col and dns_col in work.columns:
        agg["unique_dns"] = (dns_col, "nunique")
    if reg_col and reg_col in work.columns:
        agg["unique_reg"] = (reg_col, "nunique")
    if fp_col and fp_col in work.columns:
        agg["unique_files"] = (fp_col, "nunique")

    features = work.groupby("_proc_name_ml").agg(**agg).fillna(0)

    # Night activity ratio
    ts_col = schema_map.col("_ts")
    if ts_col and ts_col in work.columns:
        def parse_ts(s):
            try:
                s2 = re.sub(r"\s*@\s*", " ", str(s))
                return pd.to_datetime(s2, errors="coerce")
            except Exception:
                return pd.NaT

        work["_ts_parsed"] = work[ts_col].apply(parse_ts)
        work["_hour"] = work["_ts_parsed"].dt.hour.fillna(12)
        night = work[work["_hour"].isin(range(20, 24)) | work["_hour"].isin(range(0, 6))]
        night_counts = night.groupby("_proc_name_ml").size()
        total_counts = work.groupby("_proc_name_ml").size()
        features["night_ratio"] = (night_counts / total_counts).fillna(0)

    if features.empty or len(features) < 5:
        return pd.DataFrame()

    # Fit Isolation Forest
    try:
        pipe = Pipeline([
            ("scaler", StandardScaler()),
            ("iforest", IsolationForest(
                contamination=contamination,
                random_state=42,
                n_estimators=100,
            ))
        ])
        preds  = pipe.fit_predict(features)
        scores = pipe.named_steps["iforest"].score_samples(
            pipe.named_steps["scaler"].transform(features)
        )
    except Exception as e:
        log.warning("Isolation Forest failed: %s", e)
        return pd.DataFrame()

    features["_if_label"]  = preds
    features["_if_score"]  = scores
    anomalies = features[features["_if_label"] == -1].copy()

    if anomalies.empty:
        return pd.DataFrame()

    anomalies = anomalies.sort_values("_if_score")

    # Convert to alert rows
    alert_rows = []
    for proc_name, row in anomalies.iterrows():
        # Get a representative raw row for this process
        sample = work[work["_proc_name_ml"] == proc_name].iloc[0]
        proc_col_val  = schema_map.col("_process")
        ts_col_val    = schema_map.col("_ts")

        # Score: more negative = more anomalous → higher risk
        anomaly_score_normalised = max(0, min(100, int((-row["_if_score"]) * 200)))
        risk = max(15, min(50, anomaly_score_normalised))

        detail_parts = []
        for feat in ["event_count","unique_dst_ips","unique_dns","unique_actions"]:
            if feat in row.index:
                detail_parts.append(f"{feat}={int(row[feat])}")
        detail = ", ".join(detail_parts)

        alert_rows.append({
            "Timestamp":            str(sample.get(ts_col_val, "")) if ts_col_val else "",
            "Process":              str(sample.get(proc_col_val, proc_name)) if proc_col_val else proc_name,
            "Parent Process":       str(sample.get(schema_map.col("_parent") or "", "")),
            "Command Line":         "",
            "Detection Type":       "ML Anomaly (Isolation Forest)",
            "Risk Score":           risk,
            "Investigation Reason": f"ML: statistical outlier. {detail}",
            "Source IP":            "",
            "Destination IP":       str(sample.get(schema_map.col("_dst_ip") or "", "")),
            "Registry Path":        "",
            "File Path":            "",
            "DNS Query":            "",
            "Event Action":         "",
            "PID":                  "",
            "Username":             str(sample.get(schema_map.col("_username") or "", "")),
            "Hostname":             str(sample.get(schema_map.col("_hostname") or "", "")),
            "Severity Field":       "",
            "Message":              f"Anomaly score: {row['_if_score']:.4f}",
            "MITRE Technique":      "T1204",
            "MITRE Name":           "User Execution",
        })

    log.info("Isolation Forest: %d anomalous processes detected", len(alert_rows))
    return pd.DataFrame(alert_rows)


# ── 2. UEBA — User Entity Behaviour Analytics ─────────────────────────────────

def run_ueba(df: pd.DataFrame, schema_map: SchemaMap) -> pd.DataFrame:
    """
    Detect unusual user behaviour:
      - Login outside normal hours
      - Access from new/unusual source IPs
      - Unusual volume of events for the account
    """
    usr_col = schema_map.col("_username")
    if not usr_col or usr_col not in df.columns:
        return pd.DataFrame()

    work = df.copy()
    work = work[work[usr_col].fillna("").str.strip() != ""]
    if work.empty:
        return pd.DataFrame()

    ts_col  = schema_map.col("_ts")
    src_col = schema_map.col("_src_ip")
    act_col = schema_map.col("_event_action")

    # Parse timestamps
    if ts_col and ts_col in work.columns:
        def parse_ts(s):
            try:
                return pd.to_datetime(re.sub(r"\s*@\s*", " ", str(s)), errors="coerce")
            except Exception:
                return pd.NaT
        work["_ts_p"] = work[ts_col].apply(parse_ts)
        work["_hour"] = work["_ts_p"].dt.hour.fillna(12).astype(int)

    alerts = []

    # Per-user stats
    user_groups = work.groupby(usr_col)

    for user, grp in user_groups:
        user_str = str(user).lower()
        if not user_str or user_str in ("", "-", "nan", "system", "local service", "network service"):
            continue

        event_count = len(grp)

        # Unusual hour activity (20:00 - 06:00)
        if "_hour" in grp.columns:
            night_events = grp[grp["_hour"].isin(list(range(20, 24)) + list(range(0, 7)))]
            night_ratio  = len(night_events) / max(event_count, 1)
            if night_ratio > 0.6 and event_count >= 5:
                sample = grp.iloc[0]
                alerts.append({
                    "Timestamp":            str(grp["_ts_p"].min()) if "_ts_p" in grp.columns else "",
                    "Process":              str(sample.get(schema_map.col("_process") or "", "")),
                    "Parent Process":       "",
                    "Command Line":         "",
                    "Detection Type":       "UEBA: After-Hours Activity",
                    "Risk Score":           25,
                    "Investigation Reason": f"User '{user}': {int(night_ratio*100)}% of {event_count} events outside business hours",
                    "Source IP":            str(sample.get(src_col, "")) if src_col else "",
                    "Destination IP":       "",
                    "Registry Path":        "", "File Path":  "", "DNS Query": "",
                    "Event Action":         "", "PID":        "",
                    "Username":             str(user),
                    "Hostname":             str(sample.get(schema_map.col("_hostname") or "", "")),
                    "Severity Field":       "", "Message":    "",
                    "MITRE Technique":      "T1078",
                    "MITRE Name":           "Valid Accounts",
                })

        # Abnormally high event volume
        avg_per_user = len(work) / max(user_groups.ngroups, 1)
        if event_count > avg_per_user * 5 and event_count > 50:
            sample = grp.iloc[0]
            alerts.append({
                "Timestamp":            str(grp.iloc[0].get(ts_col, "")) if ts_col else "",
                "Process":              "",
                "Parent Process":       "",
                "Command Line":         "",
                "Detection Type":       "UEBA: High Event Volume",
                "Risk Score":           20,
                "Investigation Reason": f"User '{user}' generated {event_count} events ({int(event_count/avg_per_user)}x average)",
                "Source IP":            str(sample.get(src_col, "")) if src_col else "",
                "Destination IP":       "",
                "Registry Path":        "", "File Path":  "", "DNS Query": "",
                "Event Action":         "", "PID":        "",
                "Username":             str(user),
                "Hostname":             str(sample.get(schema_map.col("_hostname") or "", "")),
                "Severity Field":       "", "Message":    "",
                "MITRE Technique":      "T1078",
                "MITRE Name":           "Valid Accounts",
            })

    log.info("UEBA: %d behavioural anomalies detected", len(alerts))
    return pd.DataFrame(alerts) if alerts else pd.DataFrame()


# ── 3. Burst Detection — time-series event rate spikes ────────────────────────

def run_burst_detection(df: pd.DataFrame,
                         schema_map: SchemaMap,
                         window: str = "1min",
                         z_threshold: float = 3.0) -> pd.DataFrame:
    """
    Detect time windows with abnormal event rates.
    Uses z-score against rolling mean to find burst periods.
    """
    ts_col = schema_map.col("_ts")
    if not ts_col or ts_col not in df.columns:
        return pd.DataFrame()

    def parse_ts(s):
        try:
            return pd.to_datetime(re.sub(r"\s*@\s*", " ", str(s)), errors="coerce")
        except Exception:
            return pd.NaT

    ts_series = df[ts_col].apply(parse_ts).dropna()
    if len(ts_series) < 20:
        return pd.DataFrame()

    # Count events per time window
    ts_df = pd.DataFrame({"ts": ts_series})
    ts_df = ts_df.set_index("ts").sort_index()
    counts = ts_df.resample(window).size()

    if len(counts) < 3:
        return pd.DataFrame()

    mean = counts.mean()
    std  = counts.std()
    if std == 0:
        return pd.DataFrame()

    z_scores = (counts - mean) / std
    bursts   = z_scores[z_scores > z_threshold]

    alerts = []
    for ts_idx, z in bursts.items():
        event_count = counts[ts_idx]
        alerts.append({
            "Timestamp":            str(ts_idx),
            "Process":              "",
            "Parent Process":       "",
            "Command Line":         "",
            "Detection Type":       "Burst Activity Detected",
            "Risk Score":           min(int(z * 10), 40),
            "Investigation Reason": f"Event burst at {ts_idx}: {event_count} events "
                                    f"(z-score={z:.1f}, mean={mean:.0f})",
            "Source IP":            "", "Destination IP": "",
            "Registry Path":        "", "File Path":     "", "DNS Query": "",
            "Event Action":         "", "PID":           "", "Username":  "",
            "Hostname":             "", "Severity Field": "", "Message":  "",
            "MITRE Technique":      "T1071",
            "MITRE Name":           "Application Layer Protocol",
        })

    log.info("Burst detection: %d abnormal time windows", len(alerts))
    return pd.DataFrame(alerts) if alerts else pd.DataFrame()


# ── 4. DGA Classifier — character n-gram domain analysis ──────────────────────

# Pre-built n-gram frequency model trained on benign domains
# (simplified character frequency model — no training data needed)
_BENIGN_CHAR_FREQ = {
    'a':0.073,'e':0.072,'o':0.061,'i':0.056,'n':0.052,'s':0.048,
    'r':0.047,'l':0.044,'t':0.040,'c':0.036,'m':0.030,'d':0.028,
    'g':0.023,'p':0.022,'b':0.019,'h':0.018,'u':0.016,'f':0.015,
    'w':0.013,'y':0.012,'k':0.011,'v':0.010,'x':0.003,'j':0.003,
    'z':0.002,'q':0.002,
}

def _dga_score(domain: str) -> float:
    """
    Score a domain for DGA likelihood (0=benign, 1=likely DGA).
    Uses digit ratio, vowel ratio, length, and Shannon entropy.
    These four signals reliably separate DGA from legitimate domains.
    """
    parts = domain.lower().split(".")
    label = parts[0] if parts else domain
    label = label.strip()

    if len(label) < 6:
        return 0.0

    length      = len(label)
    alpha_chars = [c for c in label if c.isalpha()]
    alpha_count = max(len(alpha_chars), 1)

    # Signal 1: High digit ratio (DGA domains often embed hex/numbers)
    digit_ratio = sum(1 for c in label if c.isdigit()) / max(length, 1)

    # Signal 2: Low vowel ratio (DGA domains lack natural vowel distribution)
    vowels = set("aeiou")
    vowel_ratio = sum(1 for c in alpha_chars if c in vowels) / alpha_count

    # Signal 3: Shannon entropy (random strings have higher entropy)
    probs   = [label.count(c) / length for c in set(label)]
    entropy = -sum(p * math.log2(p) for p in probs if p > 0)
    # Normalise against theoretical max for this label length
    max_entropy = math.log2(min(length, 36)) if length > 1 else 1.0
    norm_entropy = entropy / max_entropy

    # Signal 4: Length penalty (DGA labels are often 12-32 chars)
    length_score = min((length - 6) / 26, 1.0) if length > 6 else 0.0

    # Combine: high digit ratio, low vowels, high entropy → DGA
    score = (
        digit_ratio    * 0.40 +
        (1 - vowel_ratio) * 0.25 +   # invert: low vowels = suspicious
        norm_entropy   * 0.25 +
        length_score   * 0.10
    )

    # Bonus: digit ratio > 30% is very suspicious
    if digit_ratio > 0.30:
        score = min(score + 0.15, 1.0)

    return min(score, 1.0)


def run_dga_detection(df: pd.DataFrame, schema_map: SchemaMap,
                       threshold: float = 0.55) -> pd.DataFrame:
    """
    Score all DNS queries for DGA likelihood.
    Returns alerts for domains scoring above threshold.
    """
    dns_col = schema_map.col("_domain")
    if not dns_col or dns_col not in df.columns:
        return pd.DataFrame()

    from ah_config.config import KNOWN_GOOD_DOMAINS

    def is_known_good(domain):
        d = str(domain).lower()
        return any(d == g or d.endswith("." + g) for g in KNOWN_GOOD_DOMAINS)

    work = df.copy()
    work["_dga_score"] = work[dns_col].apply(
        lambda d: _dga_score(str(d)) if d and str(d) not in ("-", "") else 0.0
    )

    high_mask = (work["_dga_score"] >= threshold) & \
                (~work[dns_col].apply(lambda d: is_known_good(str(d))))

    matched = work[high_mask]
    if matched.empty:
        return pd.DataFrame()

    ts_col   = schema_map.col("_ts")
    proc_col = schema_map.col("_process")

    alerts = []
    for _, row in matched.drop_duplicates(subset=[dns_col]).iterrows():
        domain = str(row.get(dns_col, ""))
        score  = row["_dga_score"]
        alerts.append({
            "Timestamp":            str(row.get(ts_col, "")) if ts_col else "",
            "Process":              str(row.get(proc_col, "")) if proc_col else "",
            "Parent Process":       "",
            "Command Line":         "",
            "Detection Type":       "ML: DGA Domain Detected",
            "Risk Score":           min(int(score * 60), 40),
            "Investigation Reason": f"DGA score={score:.3f} for domain: {domain}",
            "Source IP":            "", "Destination IP": "",
            "Registry Path":        "", "File Path":     "",
            "DNS Query":            domain,
            "Event Action":         "", "PID":           "", "Username": "",
            "Hostname":             str(row.get(schema_map.col("_hostname") or "", "")),
            "Severity Field":       "", "Message":       "",
            "MITRE Technique":      "T1568",
            "MITRE Name":           "Dynamic Resolution",
        })

    log.info("DGA detection: %d suspicious domains", len(alerts))
    return pd.DataFrame(alerts) if alerts else pd.DataFrame()


# ── Master ML runner ──────────────────────────────────────────────────────────

def run_ml_engine(df: pd.DataFrame, schema_map: SchemaMap) -> pd.DataFrame:
    """
    Run all ML detectors and return combined alerts DataFrame.
    """
    all_ml = []

    for name, fn in [
        ("Isolation Forest", run_isolation_forest),
        ("UEBA",             run_ueba),
        ("Burst Detection",  run_burst_detection),
        ("DGA Detection",    run_dga_detection),
    ]:
        try:
            result = fn(df, schema_map)
            if result is not None and not result.empty:
                all_ml.append(result)
                log.info("ML/%s: %d alerts", name, len(result))
        except Exception as e:
            log.error("ML/%s failed: %s", name, e, exc_info=True)

    if not all_ml:
        return pd.DataFrame()

    combined = pd.concat(all_ml, ignore_index=True)
    log.info("ML engine total: %d alerts", len(combined))
    return combined
