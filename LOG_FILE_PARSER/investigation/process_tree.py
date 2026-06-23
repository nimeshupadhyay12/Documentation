"""
investigation/process_tree.py  -  Anomaly Hunter Universal
============================================================
PID-based process tree builder using schema_map.
Works with any log that has process + parent fields.
Falls back to name-based tree when PID is unavailable.
"""
import logging
from collections import defaultdict
import pandas as pd
from schema_mapper import SchemaMap, rget
from ah_config.config import KNOWN_GOOD_PROCESSES

log = logging.getLogger("AnomalyHunter.ProcessTree")

def _norm(v):
    return str(v).lower().replace("/","\\").split("\\")[-1].strip()

def _clean_pid(v):
    try: return int(str(v).replace(",",""))
    except: return 0

def build_process_tree(raw_df: pd.DataFrame, alerts_df: pd.DataFrame,
                       schema_map: SchemaMap) -> pd.DataFrame:
    df = raw_df.fillna("").copy()

    has_pid    = schema_map.has("_pid")
    has_parent = schema_map.has("_parent")
    has_proc   = schema_map.has("_process")

    if not has_proc:
        log.info("Process tree: no process field detected — skipping")
        return pd.DataFrame()

    proc_col   = schema_map.col("_process")
    parent_col = schema_map.col("_parent") if has_parent else None
    pid_col    = schema_map.col("_pid")    if has_pid    else None

    # Build (pid → info) mapping
    pid_info = {}
    for _, row in df.iterrows():
        pid    = _clean_pid(rget(row, "_pid", schema_map)) if has_pid else 0
        proc   = rget(row, "_process", schema_map)
        parent = rget(row, "_parent", schema_map) if has_parent else ""
        if not proc: continue
        key = pid if pid else proc.lower()
        if key not in pid_info:
            pid_info[key] = {"PID": pid, "Process": proc, "Parent": parent, "Events": 0}
        pid_info[key]["Events"] += 1

    # Build parent→children adjacency
    children_of = defaultdict(list)
    for key, info in pid_info.items():
        parent_name = info["Parent"].lower()
        parent_key  = next(
            (k for k, pi in pid_info.items()
             if pi["Process"].lower() == parent_name and k != key),
            0
        )
        children_of[parent_key].append(key)

    # BFS assign depth
    rows, visited = [], set()
    queue = [(0, 0)]
    while queue:
        parent_key, depth = queue.pop(0)
        for child_key in children_of.get(parent_key, []):
            if child_key in visited: continue
            visited.add(child_key)
            info = pid_info[child_key]
            rows.append({
                "Depth":        depth,
                "PID":          info["PID"],
                "Process":      info["Process"],
                "Process Name": _norm(info["Process"]),
                "Parent":       info["Parent"],
                "Parent Name":  _norm(info["Parent"]),
                "Event Count":  info["Events"],
            })
            queue.append((child_key, depth + 1))

    for key, info in pid_info.items():
        if key not in visited:
            rows.append({
                "Depth":0,"PID":info["PID"],"Process":info["Process"],
                "Process Name":_norm(info["Process"]),"Parent":info["Parent"],
                "Parent Name":_norm(info["Parent"]),"Event Count":info["Events"],
            })

    if not rows: return pd.DataFrame()

    tree_df = pd.DataFrame(rows)

    # Annotate with alert data
    alert_lookup = {}
    if alerts_df is not None and not alerts_df.empty and "Process" in alerts_df.columns:
        for _, ar in alerts_df.iterrows():
            pl = str(ar.get("Process","")).lower()
            if ar.get("Risk Score",0) > alert_lookup.get(pl,{}).get("score",0):
                alert_lookup[pl] = {
                    "score":    ar.get("Risk Score",0),
                    "severity": ar.get("Severity",""),
                    "det_type": ar.get("Detection Type",""),
                }

    tree_df["Alert Severity"]  = tree_df["Process"].apply(lambda p: alert_lookup.get(p.lower(),{}).get("severity",""))
    tree_df["Alert Score"]     = tree_df["Process"].apply(lambda p: alert_lookup.get(p.lower(),{}).get("score",0))
    tree_df["Detection Types"] = tree_df["Process"].apply(lambda p: alert_lookup.get(p.lower(),{}).get("det_type",""))
    tree_df["Suspicious"]      = tree_df["Alert Score"].apply(lambda s: "YES" if s>0 else "")

    return tree_df.sort_values(["Depth","Alert Score"], ascending=[True,False]).reset_index(drop=True)

def render_ascii_tree(tree_df: pd.DataFrame, max_rows: int = 60) -> str:
    if tree_df.empty: return "(no process tree data)"
    lines = ["", "PROCESS TREE", "=" * 70]
    seen = set()
    for _, row in tree_df.head(max_rows).iterrows():
        depth  = int(row.get("Depth",0))
        pname  = str(row.get("Process Name",row.get("Process",""))).split("\\")[-1]
        events = row.get("Event Count",0)
        sev    = row.get("Alert Severity","")
        score  = row.get("Alert Score",0)
        key    = f"{pname}_{depth}"
        if key in seen: continue
        seen.add(key)
        indent = "    " * depth
        marker = "└── " if depth > 0 else ""
        flag   = f"  ◄ [{sev}] score={score}" if sev else ""
        lines.append(f"{indent}{marker}{pname}  ({events} events){flag}")
    lines.append("=" * 70)
    return "\n".join(lines)
