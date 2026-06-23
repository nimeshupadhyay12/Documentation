# Anomaly Hunter — Universal Edition

**Advanced open-source threat hunting platform for any log format.**

Automatically detects field names, maps them to a standard schema,
and runs 21 detectors + 15 Sigma rules across your logs — regardless
of whether they come from Elastic, Sysmon, AWS CloudTrail, Zeek,
Suricata, Apache, or any CSV export.

---

## Quick Start

```bash
# 1. Unzip and enter the folder
cd anomaly_hunter_universal

# 2. Create and activate virtual environment
python -m venv venv
source venv/bin/activate          # Linux / Mac
venv\Scripts\activate             # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run against your log file
python main.py --log logs.csv

# 5. Open the HTML report
open output/investigation_report.html
```

---

## Supported Log Formats

| Format | Auto-detected? | Notes |
|---|---|---|
| Elastic ECS (CSV export) | ✅ Yes | Full support |
| Sysmon (CSV/XML export) | ✅ Yes | Image, ParentImage, CommandLine |
| Windows Event Log (CSV) | ✅ Yes | EventID, SubjectUserName, ProcessName |
| AWS CloudTrail (JSON) | ✅ Yes | eventName, sourceIPAddress |
| Zeek / Bro (TSV/CSV) | ✅ Yes | id.orig_h, id.resp_h, proto |
| Suricata EVE (JSON) | ✅ Yes | src_ip, dest_ip, alert.signature |
| Apache / Nginx (CSV) | ✅ Yes | clientip, request, status |
| Palo Alto (CSV) | ✅ Yes | Source address, Destination address |
| Fortinet / FortiGate (CSV) | ✅ Yes | srcip, dstip, action |
| CrowdStrike (CSV) | ✅ Yes | ComputerName, ImageFileName |
| CEF / LEEF (CSV) | ✅ Yes | src, dst, act, msg |
| Any generic CSV | ✅ Yes | Field names auto-matched |
| JSON / JSONL / NDJSON | ✅ Yes | Flat JSON records |
| Excel (.xlsx / .xls) | ✅ Yes | First sheet used |
| TSV | ✅ Yes | Tab-separated values |

---

## Usage

### Basic run
```bash
python main.py --log /path/to/your_logs.csv
```

### Custom output directory
```bash
python main.py --log logs.csv --output /results/hunt_20240601
```

### See what fields were detected (no analysis)
```bash
python main.py --log logs.csv --show-schema
```

### Override field mappings manually
```bash
python main.py --log logs.csv --field-map config/field_maps/sysmon.json
```

### Enable live threat intel (VirusTotal / AbuseIPDB)
```bash
export VT_API_KEY="your_virustotal_api_key"
export ABUSEIPDB_KEY="your_abuseipdb_key"
python main.py --log logs.csv --threat-intel
```

### Debug mode
```bash
python main.py --log logs.csv --verbose
```

### Skip HTML/JSON reports (CSV only, faster)
```bash
python main.py --log logs.csv --no-html --no-json
```

---

## Field Mapping

Anomaly Hunter auto-detects field names using pattern matching.
If a field is incorrectly mapped or missing, create a JSON file:

```json
{
  "_ts":       "log_time",
  "_process":  "app_name",
  "_parent":   "caller_process",
  "_cmdline":  "query_text",
  "_dst_ip":   "remote_host",
  "_src_ip":   "client_ip",
  "_domain":   "dns_query",
  "_registry": "reg_path",
  "_filepath": "object_name",
  "_username": "account",
  "_hostname": "computer",
  "_pid":      "process_id",
  "_event_action": "event_type",
  "_severity": "level",
  "_message":  "description"
}
```

Use any subset — unmapped fields are simply skipped by the relevant detectors.
Pre-built field maps for common sources are in `config/field_maps/`.

---

## Output Files

All files are written to the `output/` directory.

| File | Description |
|---|---|
| `investigation_report.html` | **Full interactive HTML report** — open in any browser |
| `investigation_queue.csv` | High/critical alerts for immediate investigation |
| `anomaly_report.csv` | All alerts, sorted by risk score |
| `correlation_report.csv` | Correlated incidents (multi-alert chains) |
| `kill_chain_report.csv` | MITRE-tactic-staged kill chain narrative |
| `attack_chain_report.csv` | Process parent→child chain summary |
| `timeline.csv` | Chronological MITRE-staged event timeline |
| `ioc_summary.csv` | All extracted IOCs with TI enrichment |
| `process_tree.csv` | PID-based process hierarchy |
| `sigma_alerts.csv` | Sigma rule match results |
| `executive_summary.csv` | One-page metrics for management reporting |
| `report.json` | Machine-readable report for SIEM/SOAR ingestion |

---

## Detectors (21 core + 15 Sigma rules)

| Detector | MITRE Technique |
|---|---|
| EDR Rule Detection | — |
| High Severity Log | — |
| Rare Process | T1204 |
| Rare Parent-Child | T1059 |
| LOLBin Abuse | T1218 |
| PowerShell Payload | T1059.001 |
| Download Execute | T1105 |
| Encoded Payload | T1027 |
| Defense Evasion | T1562.001 |
| Malware Staging | T1036 |
| Persistence (Registry) | T1547.001 |
| Persistence via Cmdline | T1547.001 |
| Process Injection | T1055 |
| Suspicious Parent-Child | T1059 |
| Svchost Script Spawn | T1059.005 |
| Recon / IP Discovery | T1016 |
| External Communication | T1071 |
| DNS Anomaly | T1568 |
| Network Outlier | T1071 |
| Brute Force / Auth Failure | T1110 |
| Suspicious User-Agent | T1595 |

### Sigma Rules (15 built-in, unlimited YAML)
Drop `.yml` files into `sigma_rules/` to add your own rules.
Built-in rules cover: Office shell spawn, Defender exclusion,
Run key persistence, scheduled task abuse, PowerShell download
cradle, IP recon, WScript user-path execution, Mimikatz,
LSASS access, net.exe enumeration, shadow copy deletion, and more.

---

## Correlation Engine (7 incident rules)

Multiple related alerts are automatically grouped into named incidents:

| Incident Rule | Triggers On |
|---|---|
| Malware Infection Chain | Staging + Persistence + Beaconing |
| Defense Evasion + Persistence | Evasion + Persistence |
| Download-and-Execute Dropper | Download-Execute + LOLBin |
| Recon + C2 Callback | Recon + Beaconing |
| Scheduled Task Persistence Abuse | Svchost Spawn + Persistence |
| LOLBin Execution Chain | LOLBin + Rare Parent-Child |
| Sigma Rule Critical Cluster | 3+ Sigma matches |

---

## Allowlist (False-Positive Suppression)

Edit `config/allowlist.json` to suppress known-benign patterns:

```json
[
  {
    "comment": "Your custom FP suppression rule",
    "pattern": "your_pattern_here"
  }
]
```

Patterns are matched against the `Investigation Reason` field of each alert.
Pre-built entries cover common Windows scheduled task cache updates,
Office ClickToRun zone map modifications, and RuntimeBroker invocations.

---

## Threat Intelligence

### Offline (always on)
Built-in detection of known-bad IP ranges, recon domains,
persistence registry patterns, and malicious file paths.

### Online (optional)
Set environment variables and use `--threat-intel`:

```bash
export VT_API_KEY="..."        # VirusTotal API key (free tier: 500 req/day)
export ABUSEIPDB_KEY="..."     # AbuseIPDB API key (free tier: 1000 req/day)
python main.py --log logs.csv --threat-intel
```

---

## Configuration Override

Create `ah_config.json` to override any threshold:

```json
{
  "BEACON_THRESHOLD": 3,
  "DOMAIN_ENTROPY_THRESHOLD": 4.0,
  "RISK_SCORES": {
    "PERSISTENCE": 50,
    "BEACONING": 35
  }
}
```

```bash
python main.py --log logs.csv --config ah_config.json
```

---

## Project Structure

```
anomaly_hunter_universal/
├── main.py                      ← Entry point
├── schema_mapper.py             ← Universal field auto-detection
├── requirements.txt
├── README.md
│
├── config/
│   ├── config.py                ← All thresholds, IOC lists, MITRE mappings
│   ├── allowlist.json           ← FP suppression rules
│   └── field_maps/              ← Pre-built field maps for common sources
│       ├── sysmon.json
│       ├── windows_eventlog.json
│       ├── aws_cloudtrail.json
│       ├── zeek.json
│       ├── suricata.json
│       └── apache_nginx.json
│
├── detection/
│   ├── detectors.py             ← 21 core detection rules
│   ├── sigma_engine.py          ← Sigma rule engine (15 built-in + YAML)
│   └── beaconing_engine.py      ← C2 beaconing analysis
│
├── intelligence/
│   ├── ioc_extractor.py         ← IOC extraction from all fields
│   └── threat_intel.py          ← TI enrichment (offline + optional live)
│
├── correlation/
│   ├── risk_engine.py           ← Scoring, aggregation, FP suppression
│   ├── correlation_engine.py    ← 7 incident correlation rules
│   └── attack_chain.py          ← Kill chain + process chain + timeline
│
├── investigation/
│   ├── process_tree.py          ← PID-based process hierarchy
│   ├── timeline_engine.py       ← MITRE-tactic-staged timeline
│   └── investigation_engine.py  ← Patient zero, coverage, affected assets
│
├── reporting/
│   ├── reports.py               ← CSV report writer
│   ├── html_report.py           ← Self-contained HTML report
│   └── executive_report.py      ← Executive CSV + JSON
│
├── sigma_rules/                 ← Drop .yml Sigma rules here
│   └── office_shell_spawn.yml   ← Example YAML rule
│
└── output/                      ← All reports written here
```

---

