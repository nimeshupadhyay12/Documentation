# 🔍 Anomaly Hunter v2.1

<div align="center">

### Advanced Threat Hunting • Detection Engineering • DFIR Investigation • Attack Chain Reconstruction Platform

Transform raw security telemetry into actionable threat intelligence through behavioral analytics, MITRE ATT&CK mapping, risk scoring, attack correlation, and automated kill-chain reconstruction.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![MITRE ATT\&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Threat Hunting](https://img.shields.io/badge/Threat-Hunting-orange)
![DFIR](https://img.shields.io/badge/DFIR-Incident_Response-green)
![Version](https://img.shields.io/badge/Version-v2.1-success)
![License](https://img.shields.io/badge/License-MIT-yellow)

</div>

---

# 📖 Executive Summary

Modern cyber attacks rarely consist of a single malicious event.

Attackers typically combine:

* Malware staging
* Living-off-the-Land Binary (LOLBin) abuse
* PowerShell payload execution
* Registry persistence
* Scheduled task abuse
* Process injection
* DNS-based command-and-control communication
* Beaconing activity
* Network reconnaissance

These activities are often scattered across thousands of log events, making manual investigation difficult and time-consuming.

**Anomaly Hunter v2.1** was developed to solve this problem by automatically identifying suspicious behaviors, correlating related events, reconstructing attack timelines, mapping activity to the MITRE ATT&CK framework, prioritizing incidents based on risk, and generating analyst-ready investigation reports.

Instead of manually reviewing thousands of security events, analysts receive a condensed, prioritized investigation workflow that significantly reduces incident response time.

---

# 🎯 Project Goals

The primary objectives of Anomaly Hunter are:

* Detect malicious behaviors hidden within endpoint and network telemetry
* Reduce analyst workload through automated triage
* Correlate isolated events into attack chains
* Reconstruct attacker kill chains
* Prioritize incidents using risk-based scoring
* Reduce false positives
* Map detections to MITRE ATT&CK techniques
* Generate investigation-ready reports
* Support SOC, DFIR, and Threat Hunting workflows

---

# 🚀 Core Capabilities

## Threat Hunting

Identify attacker behaviors through behavioral analytics rather than signatures alone.

### Capabilities

✔ Rare Process Detection

✔ Rare Parent-Child Relationship Detection

✔ LOLBin Abuse Detection

✔ Malware Staging Detection

✔ PowerShell Payload Detection

✔ Encoded Payload Detection

✔ Registry Persistence Detection

✔ Beaconing Detection

✔ DNS Anomaly Detection

✔ Network Outlier Detection

✔ Process Injection Detection

✔ Suspicious Parent-Child Process Relationships

✔ Reconnaissance Tool Detection

✔ EDR Rule Correlation

---

## Detection Engineering

The platform implements multiple behavioral detection mechanisms designed to uncover attacker techniques commonly observed during real-world intrusions.

### Detection Categories

| Category          | Description                                  |
| ----------------- | -------------------------------------------- |
| Execution         | PowerShell, LOLBins, Script Execution        |
| Persistence       | Run Keys, Startup Locations, Scheduled Tasks |
| Defense Evasion   | Encoded Commands, LOLBin Abuse               |
| Discovery         | Reconnaissance Activities                    |
| Command & Control | Beaconing, External Communications           |
| Credential Access | Process Injection Indicators                 |
| Malware Delivery  | Download-Execute Chains                      |
| Initial Access    | Malware Staging Events                       |

---

# 🏗 Architecture

```text
┌──────────────────────────────────────────────┐
│             Security Telemetry               │
├──────────────────────────────────────────────┤
│ Process Events                               │
│ Registry Events                              │
│ DNS Requests                                 │
│ Network Connections                          │
│ EDR Detection Events                         │
│ File Activity                                │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│             Detection Engine                 │
├──────────────────────────────────────────────┤
│ 18+ Behavioral Detectors                     │
│ Threat Analytics                             │
│ Anomaly Detection                            │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│         Risk Scoring & Enrichment            │
├──────────────────────────────────────────────┤
│ Alert Aggregation                            │
│ Severity Assignment                          │
│ Confidence Rating                            │
│ False Positive Suppression                   │
│ MITRE ATT&CK Mapping                         │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│         Correlation & Investigation          │
├──────────────────────────────────────────────┤
│ Attack Chain Reconstruction                  │
│ Timeline Generation                          │
│ Kill Chain Reconstruction                    │
│ IOC Identification                           │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│            Investigation Reports             │
├──────────────────────────────────────────────┤
│ Anomaly Report                               │
│ Investigation Queue                          │
│ Attack Chain Report                          │
│ Timeline Report                              │
│ Kill Chain Report                            │
│ Executive Summary                            │
└──────────────────────────────────────────────┘
```

---

# 🔬 Detection Coverage

## Rare Process Detection

Detects processes that rarely appear within the dataset.

Useful for:

* Malware discovery
* Unknown executables
* Suspicious tooling

---

## LOLBin Abuse Detection

Detects abuse of legitimate Windows binaries.

Examples:

```text
powershell.exe
rundll32.exe
regsvr32.exe
mshta.exe
certutil.exe
bitsadmin.exe
wmic.exe
wscript.exe
cscript.exe
curl.exe
reg.exe
```

---

## PowerShell Payload Detection

Identifies malicious PowerShell execution patterns.

Examples:

```powershell
Invoke-WebRequest
DownloadString
Invoke-Expression
Net.WebClient
Invoke-Mimikatz
Invoke-Shellcode
```

---

## Download → Execute Detection

Detects malware delivery chains.

Example:

```powershell
Invoke-WebRequest → Download → Execute
Certutil → Download → Execute
Bitsadmin → Download → Execute
```

MITRE Technique:

```text
T1105 - Ingress Tool Transfer
```

---

## Encoded Payload Detection

Detects:

```text
-enc
EncodedCommand
Base64
PowerShell -e
```

MITRE:

```text
T1027
```

---

## Malware Staging Detection

Identifies executables launched from:

```text
Downloads
Desktop
Temp
AppData
Public
ProgramData
User Directories
```

---

## Persistence Detection

Detects:

```text
Run Keys
RunOnce
Startup Folders
Services
Scheduled Tasks
Winlogon
Userinit
```

MITRE:

```text
T1547.001
```

---

## Beaconing Detection

Detects repeated communication patterns commonly associated with Command-and-Control traffic.

Indicators:

* Repeated connection attempts
* Periodic callbacks
* Consistent external destinations

MITRE:

```text
T1071
```

---

## Process Injection Detection

Monitors access to high-value processes:

```text
lsass.exe
explorer.exe
svchost.exe
services.exe
winlogon.exe
```

MITRE:

```text
T1055
```

---

# 🧠 Risk Scoring Engine

Every detection contributes to a cumulative risk score.

### Severity Classification

| Score Range | Severity |
| ----------- | -------- |
| 0 - 19      | INFO     |
| 20 - 39     | LOW      |
| 40 - 59     | MEDIUM   |
| 60 - 79     | HIGH     |
| 80 - 100    | CRITICAL |

### Risk Aggregation

Instead of producing duplicate alerts, Anomaly Hunter:

* Correlates related detections
* Merges alerts for identical events
* Calculates cumulative risk
* Caps scores at 100

This significantly reduces alert fatigue.

---

# 🎯 False Positive Reduction

One of the major design goals of the platform is reducing false positives.

### Techniques Used

* Known-Good Process Whitelisting
* Known-Good Domain Filtering
* Known-Good IP Filtering
* Alert Aggregation
* Risk Thresholding
* Context-Aware Detection Logic

This helps focus analyst attention on genuinely suspicious activity.

---

# 🗺 MITRE ATT&CK Coverage

The platform automatically maps detections to ATT&CK techniques.

### Supported Techniques

| ATT&CK ID | Technique                  |
| --------- | -------------------------- |
| T1059.001 | PowerShell                 |
| T1059.003 | Windows Command Shell      |
| T1059.005 | Visual Basic               |
| T1105     | Ingress Tool Transfer      |
| T1218.005 | MSHTA                      |
| T1218.010 | Regsvr32                   |
| T1218.011 | Rundll32                   |
| T1547.001 | Registry Run Keys          |
| T1053.005 | Scheduled Tasks            |
| T1047     | WMI                        |
| T1016     | Network Discovery          |
| T1071     | Application Layer Protocol |

---

# ⛓ Attack Chain Reconstruction

The Attack Chain Engine automatically correlates:

```text
Parent Process
        ↓
Child Process
        ↓
Detection Types
        ↓
MITRE Techniques
        ↓
Risk Scores
```

Result:

```text
AC-0001
winword.exe
     ↓
powershell.exe
     ↓
Download Execute
     ↓
Persistence
     ↓
Beaconing
```

This provides analysts with an attacker-centric investigation view.

---

# ☠ Kill Chain Reconstruction

The platform automatically rebuilds the full attacker lifecycle.

### Supported Stages

```text
Initial Access
        ↓
Execution
        ↓
Persistence
        ↓
Discovery
        ↓
Command & Control
```

### ATT&CK Tactics

```text
TA0001
TA0002
TA0003
TA0007
TA0011
```

This allows investigators to understand how an intrusion unfolded from start to finish.

---

# 📊 Generated Reports

## anomaly_report.csv

Complete detection report.

Contains:

* Detections
* Risk Scores
* MITRE Techniques
* Confidence Ratings
* Analyst Recommendations

---

## investigation_queue.csv

Prioritized analyst queue.

Includes:

* Critical Alerts
* High Alerts
* Medium Alerts

---

## attack_chain_report.csv

Correlated attacker activity chains.

---

## timeline.csv

Chronological event timeline.

---

## kill_chain_report.csv

Full attack lifecycle reconstruction.

---

## executive_summary.csv

Executive-level overview containing:

* Alert Statistics
* IOC Summary
* Suspicious Processes
* C2 Infrastructure
* MITRE Coverage

---

# 📁 Project Structure

```text
Anomaly-Hunter/
│
├── anomaly_hunter_v2.py
├── detectors.py
├── scoring.py
├── attack_chain.py
├── reports.py
├── config.py
│
├── requirements.txt
├── logs.csv
│
├── anomaly_report.csv
├── investigation_queue.csv
├── attack_chain_report.csv
├── timeline.csv
├── kill_chain_report.csv
├── executive_summary.csv
│
└── README.md
```

---

# ⚙ Installation

```bash
git clone https://github.com/nimeshupadhyay12/Anomaly-Hunter.git

cd Anomaly-Hunter
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# ▶ Usage

Default log file:

```bash
python anomaly_hunter_v2.py
```

Custom log file:

```bash
python anomaly_hunter_v2.py --log my_logs.csv
```

---

# 📦 Dependencies

```text
pandas
numpy
python-dateutil
openpyxl
scipy
networkx
scikit-learn
graphviz
matplotlib
```

---

# 🎓 Skills Demonstrated

This project demonstrates practical experience in:

* Threat Hunting
* Detection Engineering
* DFIR
* Incident Response
* MITRE ATT&CK
* Security Automation
* Python Development
* Log Analytics
* SOC Operations
* Threat Intelligence
* Malware Investigation
* Attack Chain Analysis

---

# 🛣 Future Roadmap

### Detection Engineering

* Sigma Rule Integration
* YARA Rule Support
* Threat Intelligence Feeds
* VirusTotal Enrichment

### Visualization

* ATT&CK Navigator Export
* Attack Graph Visualization
* Interactive Dashboard

### Enterprise Features

* Splunk Integration
* ELK Integration
* Microsoft Sentinel Integration
* Real-Time Log Monitoring

---

# 👨‍💻 Author

**Nimesh Upadhyay**

Cybersecurity Researcher | Threat Hunter | Detection Engineering Enthusiast

---

# ⚠ Disclaimer

This project is intended for:

* Threat Hunting
* Security Research
* Defensive Security Operations
* DFIR Training
* Educational Purposes

Use only on systems and datasets that you are authorized to analyze.

---

⭐ If you find this project useful, consider giving it a star and contributing to future improvements.
