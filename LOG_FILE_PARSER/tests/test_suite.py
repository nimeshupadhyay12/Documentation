"""
tests/test_suite.py  -  Anomaly Hunter Pro
============================================
Unit test suite.

Run with:
  pytest tests/test_suite.py -v
  pytest tests/test_suite.py -v --tb=short

Tests cover:
  - Schema mapper auto-detection
  - All vectorised detectors
  - Risk engine (scoring, aggregation, severity)
  - IOC extractor
  - ML engine (isolation forest, DGA, UEBA)
  - Persistence layer (SQLite)
  - MITRE Navigator export
  - Correlation engine
  - Notifier payload building
"""

import sys
import os
import json
import tempfile
from pathlib import Path

import pytest
import pandas as pd
import numpy as np

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def ecs_log():
    """Elastic ECS format log — matches the schema_mapper ECS detection."""
    return pd.DataFrame([
        {
            "@timestamp":               "Jun 1, 2026 @ 14:21:01.000",
            "process.executable":       "C:\\Windows\\System32\\powershell.exe",
            "process.parent.executable":"C:\\Windows\\System32\\cmd.exe",
            "process.command_line":     "powershell -enc SGVsbG8gV29ybGQ=",
            "process.pid":              "1234",
            "source.ip":                "192.168.1.10",
            "destination.ip":           "103.243.115.105",
            "dns.question.name":        "ipinfo.io",
            "registry.path":            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware",
            "file.path":                "C:\\Users\\Public\\Pictures\\evil.exe",
            "event.action":             "rule_detection",
        },
        {
            "@timestamp":               "Jun 1, 2026 @ 14:21:05.000",
            "process.executable":       "C:\\Users\\Public\\uusd.exe",
            "process.parent.executable":"C:\\Windows\\System32\\wscript.exe",
            "process.command_line":     "C:\\Users\\Public\\uusd.exe",
            "process.pid":              "5678",
            "source.ip":                "192.168.1.10",
            "destination.ip":           "206.189.137.60",
            "dns.question.name":        "-",
            "registry.path":            "-",
            "file.path":                "-",
            "event.action":             "connection_attempted",
        },
        {
            "@timestamp":               "Jun 1, 2026 @ 14:21:10.000",
            "process.executable":       "C:\\Windows\\System32\\svchost.exe",
            "process.parent.executable":"C:\\Windows\\System32\\services.exe",
            "process.command_line":     "svchost -k netsvcs",
            "process.pid":              "800",
            "source.ip":                "",
            "destination.ip":           "8.8.8.8",
            "dns.question.name":        "microsoft.com",
            "registry.path":            "",
            "file.path":                "",
            "event.action":             "lookup_requested",
        },
    ]).fillna("")


@pytest.fixture
def sysmon_log():
    """Sysmon-style log with Image/ParentImage columns."""
    return pd.DataFrame([
        {
            "UtcTime":      "2026-06-01 14:21:01.000",
            "Image":        "C:\\Windows\\System32\\powershell.exe",
            "ParentImage":  "C:\\Program Files\\Microsoft Office\\winword.exe",
            "CommandLine":  "powershell -enc dGVzdA==",
            "ProcessId":    "9999",
            "SourceIp":     "10.0.0.5",
            "DestinationIp":"185.220.101.1",
            "QueryName":    "xn--gkd6a0b7a.xyz",
            "TargetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\backdoor",
            "EventID":      "1",
            "User":         "DOMAIN\\jdoe",
            "Computer":     "WORKSTATION01",
            "Hashes":       "SHA256=abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
        },
    ]).fillna("")


@pytest.fixture
def schema_map_ecs(ecs_log):
    from schema_mapper import build_schema_map, normalise_dataframe
    sm = build_schema_map(ecs_log)
    return sm, normalise_dataframe(ecs_log, sm)


@pytest.fixture
def schema_map_sysmon(sysmon_log):
    from schema_mapper import build_schema_map, normalise_dataframe
    sm = build_schema_map(sysmon_log)
    return sm, normalise_dataframe(sysmon_log, sm)


@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    yield db_path
    try:
        os.unlink(db_path)
    except Exception:
        pass


# ── Schema Mapper Tests ───────────────────────────────────────────────────────

class TestSchemaMapper:

    def test_ecs_detection(self, ecs_log):
        from schema_mapper import build_schema_map
        sm = build_schema_map(ecs_log)
        assert sm.log_source == "Elastic ECS"
        assert sm.has("_ts")
        assert sm.has("_process")
        assert sm.has("_dst_ip")
        assert sm.has("_domain")
        assert sm.has("_registry")

    def test_sysmon_detection(self, sysmon_log):
        from schema_mapper import build_schema_map
        sm = build_schema_map(sysmon_log)
        assert sm.log_source == "Sysmon"
        assert sm.has("_process")
        assert sm.has("_parent")
        assert sm.has("_cmdline")
        assert sm.has("_hash")

    def test_manual_override(self, ecs_log):
        from schema_mapper import build_schema_map
        sm = build_schema_map(ecs_log, manual_overrides={
            "_process": "process.executable",
            "_dst_ip":  "destination.ip",
        })
        assert sm.col("_process") == "process.executable"
        assert sm.col("_dst_ip")  == "destination.ip"

    def test_normalise_adds_internal_cols(self, schema_map_ecs):
        sm, norm_df = schema_map_ecs
        assert "_proc_name"   in norm_df.columns
        assert "_parent_name" in norm_df.columns
        assert "_ts"          in norm_df.columns

    def test_proc_name_normalised(self, schema_map_ecs):
        sm, norm_df = schema_map_ecs
        # powershell.exe should be normalised to basename
        assert "powershell.exe" in norm_df["_proc_name"].values

    def test_rget_fallback(self, schema_map_ecs):
        from schema_mapper import rget
        sm, norm_df = schema_map_ecs
        row = norm_df.iloc[0]
        # Should return value via internal field
        val = rget(row, "_process", sm)
        assert "powershell" in val.lower()

    def test_unknown_columns_reported(self):
        from schema_mapper import build_schema_map
        df = pd.DataFrame([{"weird_col_xyz": "val", "another_odd": "val2"}])
        sm = build_schema_map(df)
        assert len(sm.unmapped_cols) > 0


# ── Vectorised Detector Tests ─────────────────────────────────────────────────

class TestVectorisedDetectors:

    def test_lolbin_detected(self, schema_map_ecs):
        from core.vectorised_detectors import vdetect_lolbins
        sm, norm_df = schema_map_ecs
        alerts = vdetect_lolbins(norm_df, sm)
        assert not alerts.empty
        assert any("powershell" in str(p).lower()
                   for p in alerts["Process"].values)

    def test_encoded_payload_detected(self, schema_map_ecs):
        from core.vectorised_detectors import vdetect_encoded_payloads
        sm, norm_df = schema_map_ecs
        alerts = vdetect_encoded_payloads(norm_df, sm)
        assert not alerts.empty
        assert alerts.iloc[0]["MITRE Technique"] == "T1027"

    def test_persistence_detected(self, schema_map_ecs):
        from core.vectorised_detectors import vdetect_persistence_registry
        sm, norm_df = schema_map_ecs
        alerts = vdetect_persistence_registry(norm_df, sm)
        assert not alerts.empty
        assert alerts.iloc[0]["Risk Score"] > 0

    def test_edr_rule_detected(self, schema_map_ecs):
        from core.vectorised_detectors import vdetect_edr_rule
        sm, norm_df = schema_map_ecs
        alerts = vdetect_edr_rule(norm_df, sm)
        assert not alerts.empty
        assert alerts.iloc[0]["Detection Type"] == "EDR Rule Detection"

    def test_external_comm_detected(self, schema_map_ecs):
        from core.vectorised_detectors import vdetect_external_communication
        sm, norm_df = schema_map_ecs
        alerts = vdetect_external_communication(norm_df, sm)
        # 103.243.115.105 is external — should be detected
        assert not alerts.empty
        assert any("103.243" in str(ip) for ip in alerts["Destination IP"].values)

    def test_known_good_ip_not_alerted(self, schema_map_ecs):
        from core.vectorised_detectors import vdetect_external_communication
        sm, norm_df = schema_map_ecs
        alerts = vdetect_external_communication(norm_df, sm)
        # 8.8.8.8 should NOT appear in alerts
        assert not any("8.8.8.8" in str(ip) for ip in alerts["Destination IP"].values)

    def test_malware_staging_detected(self, schema_map_ecs):
        from core.vectorised_detectors import vdetect_malware_staging
        sm, norm_df = schema_map_ecs
        alerts = vdetect_malware_staging(norm_df, sm)
        assert not alerts.empty

    def test_no_crash_missing_field(self):
        """Detectors must not crash when a required field is absent."""
        from core.vectorised_detectors import run_vectorised_detectors
        from schema_mapper import build_schema_map, normalise_dataframe
        # Minimal DataFrame — only timestamp
        minimal = pd.DataFrame([{"timestamp": "2026-01-01", "message": "hello"}])
        sm = build_schema_map(minimal)
        norm_df = normalise_dataframe(minimal, sm)
        # Should not raise
        alerts = run_vectorised_detectors(norm_df, sm)
        assert isinstance(alerts, pd.DataFrame)

    def test_sysmon_lolbin(self, schema_map_sysmon):
        from core.vectorised_detectors import vdetect_lolbins
        sm, norm_df = schema_map_sysmon
        alerts = vdetect_lolbins(norm_df, sm)
        assert not alerts.empty

    def test_alert_has_required_columns(self, schema_map_ecs):
        from core.vectorised_detectors import run_vectorised_detectors
        sm, norm_df = schema_map_ecs
        alerts = run_vectorised_detectors(norm_df, sm)
        required = ["Timestamp","Process","Detection Type","Risk Score",
                    "MITRE Technique","Investigation Reason"]
        for col in required:
            assert col in alerts.columns, f"Missing column: {col}"


# ── Risk Engine Tests ─────────────────────────────────────────────────────────

class TestRiskEngine:

    def _make_alerts(self):
        return pd.DataFrame([
            {"Timestamp":"t1","Process":"evil.exe","Parent Process":"cmd.exe",
             "Detection Type":"LOLBin Abuse","Risk Score":25,
             "Investigation Reason":"lolbin","Source IP":"","Destination IP":"1.2.3.4",
             "Registry Path":"","File Path":"","DNS Query":"","Event Action":"",
             "PID":"","Username":"","Hostname":"","Severity Field":"","Message":"",
             "MITRE Technique":"T1218","MITRE Name":"","Command Line":""},
            {"Timestamp":"t1","Process":"evil.exe","Parent Process":"cmd.exe",
             "Detection Type":"Encoded Payload","Risk Score":40,
             "Investigation Reason":"base64","Source IP":"","Destination IP":"1.2.3.4",
             "Registry Path":"","File Path":"","DNS Query":"","Event Action":"",
             "PID":"","Username":"","Hostname":"","Severity Field":"","Message":"",
             "MITRE Technique":"T1027","MITRE Name":"","Command Line":""},
        ])

    def test_aggregation_merges_same_event(self):
        from correlation.risk_engine import aggregate_alerts
        alerts = self._make_alerts()
        agg = aggregate_alerts(alerts)
        # Both rows have same Timestamp+Process — should merge to 1 row
        assert len(agg) == 1
        assert agg.iloc[0]["Risk Score"] == 65   # 25+40

    def test_score_capped_at_100(self):
        from correlation.risk_engine import aggregate_alerts
        big_alerts = pd.DataFrame([
            {"Timestamp":"t1","Process":"evil.exe","Parent Process":"",
             "Detection Type":f"Type{i}","Risk Score":40,
             "Investigation Reason":"","Source IP":"","Destination IP":"",
             "Registry Path":"","File Path":"","DNS Query":"","Event Action":"",
             "PID":"","Username":"","Hostname":"","Severity Field":"","Message":"",
             "MITRE Technique":"","MITRE Name":"","Command Line":""}
            for i in range(10)
        ])
        agg = aggregate_alerts(big_alerts)
        assert agg.iloc[0]["Risk Score"] <= 100

    def test_severity_assignment(self):
        from correlation.risk_engine import calculate_severity
        assert calculate_severity(95)  == "CRITICAL"
        assert calculate_severity(70)  == "HIGH"
        assert calculate_severity(50)  == "MEDIUM"
        assert calculate_severity(25)  == "LOW"
        assert calculate_severity(5)   == "INFO"

    def test_alert_id_generated(self):
        from correlation.risk_engine import enrich_alerts
        alerts = self._make_alerts()
        enriched = enrich_alerts(alerts)
        assert "Alert ID" in enriched.columns
        assert enriched["Alert ID"].str.startswith("AH-").all()

    def test_investigation_queue_excludes_fp(self):
        from correlation.risk_engine import enrich_alerts, get_investigation_queue
        alerts = self._make_alerts()
        enriched = enrich_alerts(alerts)
        queue = get_investigation_queue(enriched)
        assert "FP-SUPPRESSED" not in queue["Severity"].values


# ── IOC Extractor Tests ───────────────────────────────────────────────────────

class TestIOCExtractor:

    def test_ip_extracted(self, schema_map_ecs):
        from intelligence.ioc_extractor import extract_all_iocs
        sm, norm_df = schema_map_ecs
        # Pass raw ecs_log as df (extractor uses schema_map to resolve fields)
        from schema_mapper import build_schema_map
        raw = norm_df
        iocs = extract_all_iocs(raw, sm)
        ip_iocs = iocs[iocs["IOC Type"] == "IP"]
        assert not ip_iocs.empty
        assert any("103.243" in str(v) for v in ip_iocs["IOC Value"].values)

    def test_known_good_ip_excluded(self, schema_map_ecs):
        from intelligence.ioc_extractor import extract_all_iocs
        sm, norm_df = schema_map_ecs
        iocs = extract_all_iocs(norm_df, sm)
        ip_iocs = iocs[iocs["IOC Type"] == "IP"]
        # 8.8.8.8 should not appear
        assert not any("8.8.8.8" in str(v) for v in ip_iocs["IOC Value"].values)

    def test_domain_extracted(self, schema_map_ecs):
        from intelligence.ioc_extractor import extract_all_iocs
        sm, norm_df = schema_map_ecs
        iocs = extract_all_iocs(norm_df, sm)
        domain_iocs = iocs[iocs["IOC Type"] == "Domain"]
        assert not domain_iocs.empty
        assert any("ipinfo" in str(v) for v in domain_iocs["IOC Value"].values)

    def test_registry_extracted(self, schema_map_ecs):
        from intelligence.ioc_extractor import extract_all_iocs
        sm, norm_df = schema_map_ecs
        iocs = extract_all_iocs(norm_df, sm)
        reg_iocs = iocs[iocs["IOC Type"] == "Registry Key"]
        assert not reg_iocs.empty

    def test_hash_extracted(self, schema_map_sysmon):
        from intelligence.ioc_extractor import extract_all_iocs
        sm, norm_df = schema_map_sysmon
        iocs = extract_all_iocs(norm_df, sm)
        hash_iocs = iocs[iocs["IOC Type"] == "Hash"]
        assert not hash_iocs.empty


# ── ML Engine Tests ───────────────────────────────────────────────────────────

class TestMLEngine:

    def _make_large_log(self, n=100):
        """Create synthetic log large enough for ML."""
        import random
        rows = []
        processes = ["chrome.exe","svchost.exe","notepad.exe","evil.exe","explorer.exe"]
        for i in range(n):
            rows.append({
                "@timestamp":       f"2026-06-01 14:{i//60:02d}:{i%60:02d}",
                "process.executable": random.choice(processes),
                "process.parent.executable": "explorer.exe",
                "process.command_line": "normal command",
                "destination.ip":   f"192.168.1.{i % 50 + 1}",
                "dns.question.name": f"site{i % 20}.com",
                "event.action":     "connection_attempted",
            })
        # Make evil.exe very noisy (anomalous)
        for i in range(30):
            rows.append({
                "@timestamp":       f"2026-06-01 14:30:{i:02d}",
                "process.executable": "evil.exe",
                "process.parent.executable": "cmd.exe",
                "process.command_line": "evil command",
                "destination.ip":   f"10.{i}.{i}.{i}",
                "dns.question.name": f"malicious{i}.xyz",
                "event.action":     "connection_attempted",
            })
        return pd.DataFrame(rows).fillna("")

    def test_isolation_forest_runs(self):
        from core.ml_engine import run_isolation_forest
        from schema_mapper import build_schema_map, normalise_dataframe
        df = self._make_large_log(150)
        sm = build_schema_map(df)
        norm_df = normalise_dataframe(df, sm)
        result = run_isolation_forest(norm_df, sm)
        assert isinstance(result, pd.DataFrame)

    def test_dga_detects_high_entropy(self):
        from core.ml_engine import _dga_score
        # Real DGA-style domain (high entropy, consonant clusters)
        assert _dga_score("xn5v9kp2j1mq7.xyz") > 0.4
        # Normal domain
        assert _dga_score("microsoft.com") < 0.45
        assert _dga_score("google.com") < 0.4

    def test_dga_engine_runs(self, schema_map_ecs):
        from core.ml_engine import run_dga_detection
        sm, norm_df = schema_map_ecs
        result = run_dga_detection(norm_df, sm)
        assert isinstance(result, pd.DataFrame)

    def test_burst_detection_runs(self):
        from core.ml_engine import run_burst_detection
        from schema_mapper import build_schema_map, normalise_dataframe
        df = self._make_large_log(200)
        sm = build_schema_map(df)
        norm_df = normalise_dataframe(df, sm)
        result = run_burst_detection(norm_df, sm)
        assert isinstance(result, pd.DataFrame)


# ── Persistence Tests ─────────────────────────────────────────────────────────

class TestPersistence:

    def _make_alerts_df(self):
        return pd.DataFrame([{
            "Alert ID":    "AH-TESTAAAA",
            "Timestamp":   "2026-06-01 14:21:00",
            "Process":     "evil.exe",
            "Parent Process": "cmd.exe",
            "Detection Type": "LOLBin Abuse",
            "Risk Score":  25,
            "Severity":    "LOW",
            "MITRE Technique": "T1218",
            "MITRE Name":  "Signed Binary Proxy",
            "Destination IP": "1.2.3.4",
            "Investigation Reason": "test",
            "Recommendation": "review",
        }])

    def test_run_lifecycle(self, temp_db):
        from core.persistence import PersistenceLayer
        db = PersistenceLayer(temp_db)
        run_id = db.start_run("test.csv", "Generic")
        assert run_id.startswith("RUN-")
        db.finish_run(run_id, {"Total Events":100,"Unique Alerts":5,
                                "CRITICAL":1,"HIGH":2,"MEDIUM":2,"FP-SUPPRESSED":0})
        runs = db.get_runs()
        assert len(runs) == 1
        assert runs.iloc[0]["status"] == "complete"

    def test_alert_save_and_retrieve(self, temp_db):
        from core.persistence import PersistenceLayer
        db = PersistenceLayer(temp_db)
        run_id = db.start_run("test.csv")
        alerts = self._make_alerts_df()
        saved = db.save_alerts(alerts, run_id)
        assert saved == 1
        history = db.get_alert_history(process="evil.exe")
        assert len(history) == 1

    def test_alert_deduplication(self, temp_db):
        from core.persistence import PersistenceLayer
        db = PersistenceLayer(temp_db)
        run_id1 = db.start_run("test.csv")
        run_id2 = db.start_run("test.csv")
        alerts = self._make_alerts_df()
        db.save_alerts(alerts, run_id1)
        db.save_alerts(alerts, run_id2)   # same alert_id
        history = db.get_alert_history(process="evil.exe")
        assert len(history) == 1          # deduplicated

    def test_new_alerts_detection(self, temp_db):
        from core.persistence import PersistenceLayer
        db = PersistenceLayer(temp_db)
        run_id1 = db.start_run("r1.csv")
        alerts = self._make_alerts_df()
        db.save_alerts(alerts, run_id1)

        # Second run with new alert
        run_id2 = db.start_run("r2.csv")
        new_alerts = pd.DataFrame([{
            "Alert ID":    "AH-NEWBBBBB",
            "Timestamp":   "2026-06-01 15:00:00",
            "Process":     "new_evil.exe",
            "Parent Process":"","Detection Type":"Persistence",
            "Risk Score":40,"Severity":"MEDIUM","MITRE Technique":"T1547",
            "MITRE Name":"","Destination IP":"","Investigation Reason":"",
            "Recommendation":"",
        }])
        # Check new_only BEFORE saving run_id2 alerts to DB
        # (run_id1 alerts already in DB — they should be filtered out)
        all_alerts = pd.concat([alerts, new_alerts])
        new_only = db.get_new_alerts_since_last_run(all_alerts, run_id2)
        assert len(new_only) == 1
        assert new_only.iloc[0]["Process"] == "new_evil.exe"

    def test_analyst_verdict_update(self, temp_db):
        from core.persistence import PersistenceLayer
        db = PersistenceLayer(temp_db)
        run_id = db.start_run("test.csv")
        db.save_alerts(self._make_alerts_df(), run_id)
        ok = db.update_analyst_verdict("AH-TESTAAAA", "true_positive", "Confirmed malware")
        assert ok
        history = db.get_alert_history(process="evil.exe")
        assert history.iloc[0]["analyst_status"] == "true_positive"

    def test_ioc_save_and_dedup(self, temp_db):
        from core.persistence import PersistenceLayer
        db = PersistenceLayer(temp_db)
        run_id = db.start_run("test.csv")
        ioc_df = pd.DataFrame([{
            "IOC Type":"IP","IOC Value":"1.2.3.4",
            "TI Verdict":"Malicious","TI Tags":"C2","TI Confidence":95
        }])
        db.save_iocs(ioc_df, run_id)
        db.save_iocs(ioc_df, run_id)   # second save same IOC
        known_bad = db.get_known_bad_iocs()
        assert ("IP","1.2.3.4") in known_bad

    def test_summary(self, temp_db):
        from core.persistence import PersistenceLayer
        db = PersistenceLayer(temp_db)
        summary = db.get_summary()
        assert "Total Runs" in summary
        assert "Total Alerts (all)" in summary


# ── MITRE Navigator Tests ─────────────────────────────────────────────────────

class TestMITRENavigator:

    def _make_alert_df(self):
        return pd.DataFrame([
            {"MITRE Technique":"T1059.001","Severity":"CRITICAL",
             "Risk Score":90,"Process":"powershell.exe","Detection Type":"PowerShell Payload"},
            {"MITRE Technique":"T1547.001","Severity":"HIGH",
             "Risk Score":70,"Process":"reg.exe","Detection Type":"Persistence"},
            {"MITRE Technique":"T1059.001","Severity":"HIGH",
             "Risk Score":65,"Process":"powershell.exe","Detection Type":"Encoded Payload"},
        ])

    def test_layer_structure(self):
        from core.mitre_navigator import build_navigator_layer
        alerts = self._make_alert_df()
        layer = build_navigator_layer(alerts)
        assert layer["domain"] == "enterprise-attack"
        assert "techniques" in layer
        assert len(layer["techniques"]) > 0

    def test_technique_counts(self):
        from core.mitre_navigator import build_navigator_layer
        alerts = self._make_alert_df()
        layer = build_navigator_layer(alerts)
        t1059 = next((t for t in layer["techniques"]
                      if t["techniqueID"] == "T1059.001"), None)
        assert t1059 is not None
        assert t1059["score"] == 2   # 2 alerts for T1059.001

    def test_json_output(self):
        from core.mitre_navigator import build_navigator_layer
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_path = f.name
        try:
            alerts = self._make_alert_df()
            build_navigator_layer(alerts, output_path=out_path)
            with open(out_path) as f:
                data = json.load(f)
            assert "techniques" in data
        finally:
            os.unlink(out_path)


# ── Notifier Tests (no actual sending) ───────────────────────────────────────

class TestNotifiers:

    def _make_alerts(self):
        return pd.DataFrame([{
            "Process":"evil.exe","Severity":"CRITICAL","Risk Score":100,
            "Detection Type":"Beaconing","Destination IP":"1.2.3.4",
        }])

    def test_slack_payload_structure(self):
        from integrations.notifiers import _build_slack_payload
        payload = _build_slack_payload(self._make_alerts(), "RUN-001")
        assert "blocks" in payload
        assert "text" in payload
        assert len(payload["blocks"]) > 0

    def test_teams_payload_structure(self):
        from integrations.notifiers import _build_teams_payload
        payload = _build_teams_payload(self._make_alerts())
        assert "@type" in payload
        assert payload["@type"] == "MessageCard"
        assert "sections" in payload

    def test_no_notify_below_threshold(self):
        from integrations.notifiers import _should_notify
        assert _should_notify("CRITICAL") is True
        assert _should_notify("HIGH")     is True
        assert _should_notify("LOW")      is False
        assert _should_notify("INFO")     is False

    def test_get_channels_empty(self):
        from integrations.notifiers import get_configured_channels
        # With no env vars set, should return empty list
        channels = get_configured_channels()
        assert isinstance(channels, list)


# ── Chart Tests ───────────────────────────────────────────────────────────────

class TestCharts:

    def _make_alerts(self):
        return pd.DataFrame([
            {"Severity":"CRITICAL","Risk Score":90,"Process":"evil.exe",
             "Detection Type":"LOLBin Abuse","Timestamp":"2026-06-01 14:21:00",
             "MITRE Technique":"T1059.001"},
            {"Severity":"HIGH","Risk Score":70,"Process":"powershell.exe",
             "Detection Type":"PowerShell Payload","Timestamp":"2026-06-01 14:21:05",
             "MITRE Technique":"T1059.001"},
            {"Severity":"MEDIUM","Risk Score":45,"Process":"reg.exe",
             "Detection Type":"Persistence","Timestamp":"2026-06-01 14:22:00",
             "MITRE Technique":"T1547.001"},
        ])

    def test_severity_pie_returns_string(self):
        from reporting.charts import chart_severity_pie
        b64 = chart_severity_pie(self._make_alerts())
        assert isinstance(b64, str)
        if b64:   # matplotlib may not be available in all envs
            assert len(b64) > 100

    def test_build_all_charts(self):
        from reporting.charts import build_all_charts
        charts = build_all_charts(self._make_alerts())
        assert isinstance(charts, dict)

    def test_chart_img_tag(self):
        from reporting.charts import chart_img_tag
        tag = chart_img_tag("abc123", alt="test")
        assert 'data:image/png;base64,abc123' in tag
        assert 'alt="test"' in tag


# ── Integration Test ──────────────────────────────────────────────────────────

class TestEndToEnd:

    def test_full_pipeline_ecs(self, ecs_log):
        """Full pipeline from raw log → enriched alerts."""
        from schema_mapper import build_schema_map, normalise_dataframe
        from core.vectorised_detectors import run_vectorised_detectors
        from correlation.risk_engine import enrich_alerts, get_investigation_queue

        sm      = build_schema_map(ecs_log)
        norm_df = normalise_dataframe(ecs_log, sm)
        raw     = run_vectorised_detectors(norm_df, sm)

        assert not raw.empty, "Should produce at least one alert"

        enriched = enrich_alerts(raw)
        assert "Severity" in enriched.columns
        assert "Alert ID" in enriched.columns
        assert "Analyst Verdict" in enriched.columns

        queue = get_investigation_queue(enriched)
        assert isinstance(queue, pd.DataFrame)

    def test_full_pipeline_sysmon(self, sysmon_log):
        """Same pipeline works on Sysmon-format log."""
        from schema_mapper import build_schema_map, normalise_dataframe
        from core.vectorised_detectors import run_vectorised_detectors
        from correlation.risk_engine import enrich_alerts

        sm      = build_schema_map(sysmon_log)
        norm_df = normalise_dataframe(sysmon_log, sm)
        raw     = run_vectorised_detectors(norm_df, sm)
        enriched = enrich_alerts(raw)
        assert isinstance(enriched, pd.DataFrame)

    def test_minimal_log_no_crash(self):
        """Framework must not crash on a log with only one column."""
        from schema_mapper import build_schema_map, normalise_dataframe
        from core.vectorised_detectors import run_vectorised_detectors
        df = pd.DataFrame([{"message": "hello world"}, {"message": "another line"}])
        sm = build_schema_map(df)
        norm_df = normalise_dataframe(df, sm)
        result = run_vectorised_detectors(norm_df, sm)
        assert isinstance(result, pd.DataFrame)
