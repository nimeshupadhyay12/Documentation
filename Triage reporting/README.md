# Cybersecurity Triage Reporting Guide

## Overview

This repository provides a comprehensive guide to **Cybersecurity Triage Reporting**, a critical process used by Security Operations Centers (SOCs), Incident Response Teams, Threat Hunters, and DFIR analysts to rapidly investigate, prioritize, and document security alerts and incidents.

Triage reporting enables analysts to distinguish real threats from false positives, assess business impact, reconstruct attack timelines, and determine appropriate response actions.

---

## What is Triage Reporting?

Triage Reporting is the process of:

* Analyzing security alerts
* Validating suspicious activity
* Assessing severity and impact
* Prioritizing incidents
* Correlating related events
* Documenting investigation findings
* Escalating confirmed threats

The concept originates from emergency medicine, where patients are prioritized based on urgency. In cybersecurity, alerts are prioritized according to risk and potential organizational impact.

---

## Why Triage Reporting Matters

Modern security platforms generate thousands of alerts every day, making manual investigation of every alert impossible.

### Common Security Platforms

* Elastic Security
* Microsoft Sentinel
* Splunk Enterprise Security
* IBM QRadar
* CrowdStrike Falcon
* Microsoft Defender XDR
* Google Chronicle
* Palo Alto Cortex XDR

Without triage, analysts can become overwhelmed by alert fatigue and miss genuine threats.

### Benefits

* Faster incident detection
* Reduced false positives
* Improved analyst efficiency
* Better incident prioritization
* Faster response and containment
* Improved threat visibility
* Enhanced documentation and reporting

---

# Core Objectives of Triage Reporting

## 1. Alert Validation

Determine whether an alert represents:

### True Positive

A genuine malicious activity requiring investigation.

Example:

```powershell
powershell.exe -enc <base64>
```

### False Positive

Legitimate activity incorrectly flagged as malicious.

Example:

```powershell
Administrator automation script
```

### Benign Positive

Expected activity that triggered a security rule.

Example:

```text
Automated backup process
```

---

## 2. Severity Classification

| Severity      | Description                           |
| ------------- | ------------------------------------- |
| Critical      | Active compromise detected            |
| High          | Strong evidence of malicious activity |
| Medium        | Suspicious behavior requiring review  |
| Low           | Minor anomaly                         |
| Informational | No immediate threat                   |

---

## 3. Impact Assessment

Determine:

* Affected hosts
* Affected users
* Privilege level
* Business impact
* Data exposure risk
* Lateral movement potential

Example:

```yaml
Affected Host: WIN-DC01
Affected User: administrator
Impact: Potential Domain Compromise
```

---

## 4. Incident Prioritization

Not all alerts require immediate response.

| Alert Type             | Priority  |
| ---------------------- | --------- |
| Ransomware             | Immediate |
| Credential Theft       | Critical  |
| Malware Staging        | High      |
| PowerShell Obfuscation | High      |
| Network Anomaly        | Medium    |
| Failed Login           | Low       |

---

# Triage Reporting Workflow

## Step 1: Alert Intake

Security alert enters the SIEM platform.

Example:

```yaml
Rule Name: Suspicious PowerShell Execution
Timestamp: 01-Jun-2026 14:24:52 UTC
Host: WORKSTATION-01
```

---

## Step 2: Initial Investigation

Collect evidence from:

### Process Activity

```text
powershell.exe
 └── cmd.exe
      └── rundll32.exe
```

### User Activity

```yaml
User: john.doe
```

### Network Activity

```yaml
Destination IP: 185.199.110.153
Port: 443
```

---

## Step 3: Threat Hunting

Investigate activity before, during, and after the alert.

### Before Event

```text
14:20 - 14:24
```

### During Event

```text
14:24:52
```

### After Event

```text
14:25 - 14:35
```

Goals:

* Identify initial access
* Detect lateral movement
* Discover persistence mechanisms
* Identify data exfiltration

---

## Step 4: Alert Correlation

Individual alerts rarely tell the full story.

Example:

### Alert 1

```text
Encoded PowerShell Execution
```

### Alert 2

```text
Outbound Connection to Suspicious IP
```

### Alert 3

```text
Scheduled Task Creation
```

Combined they form an:

```text
Attack Chain
```

---

## Step 5: Classification

### True Positive

```text
Mimikatz Execution
Credential Dumping
```

### False Positive

```text
Authorized Administrator Script
```

### Benign Positive

```text
Enterprise Backup Software
```

---

# Professional Triage Report Structure

## Executive Summary

A concise overview of the investigation.

Example:

> A suspicious PowerShell execution was detected on WORKSTATION-01. Investigation revealed execution of an encoded PowerShell payload followed by outbound communication to an external IP address. The activity was classified as a True Positive and indicates malware staging activity.

---

## Alert Information

```yaml
Alert Name: Suspicious PowerShell Execution
Severity: High
Timestamp: 01-Jun-2026 14:24:52 UTC
Host: WORKSTATION-01
User: john.doe
```

---

## Investigation Findings

### Process Analysis

```text
powershell.exe
 └── cmd.exe
      └── rundll32.exe
```

### Network Analysis

```yaml
Destination IP: 185.199.110.153
Port: 443
```

### File Analysis

```yaml
Downloaded Payload: update.exe
```

---

## Attack Timeline Reconstruction

| Timestamp | Activity                       |
| --------- | ------------------------------ |
| 14:21:06  | Initial PowerShell Execution   |
| 14:22:15  | Encoded Command Detected       |
| 14:24:52  | Payload Download               |
| 14:25:10  | Network Connection Established |
| 14:26:40  | Persistence Mechanism Created  |

---

## MITRE ATT&CK Mapping

| Tactic            | Technique                        |
| ----------------- | -------------------------------- |
| Execution         | T1059.001 PowerShell             |
| Persistence       | T1053 Scheduled Task             |
| Defense Evasion   | T1027 Obfuscated Files           |
| Command & Control | T1071 Application Layer Protocol |

---

## Indicators of Compromise (IoCs)

### IP Addresses

```text
185.199.110.153
```

### Domains

```text
malicious-domain.com
```

### File Hashes

```text
SHA256:
8d3a8dxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

---

## Impact Assessment

```yaml
Affected Systems: 2
Affected Users: 1
Privilege Level: Administrator
Potential Risk: Credential Theft
```

---

## Recommendations

1. Isolate affected endpoints.
2. Reset compromised credentials.
3. Block malicious IP addresses.
4. Remove persistence mechanisms.
5. Conduct malware scans.
6. Review related user activity.
7. Monitor for recurring indicators.
8. Update detection rules.

---

# Triage Report vs Incident Report

| Feature      | Triage Report      | Incident Report            |
| ------------ | ------------------ | -------------------------- |
| Purpose      | Initial Assessment | Full Investigation         |
| Duration     | Minutes to Hours   | Hours to Days              |
| Detail Level | Moderate           | Extensive                  |
| Audience     | SOC Analysts       | IR Teams & Management      |
| Goal         | Determine Priority | Document Complete Incident |

---

# SOC Use Cases

Triage reporting is commonly used for:

* Malware Investigations
* Threat Hunting
* Phishing Incidents
* Insider Threat Detection
* Ransomware Analysis
* Privilege Escalation Events
* PowerShell Abuse
* LOLBin Detection
* Lateral Movement Analysis
* Data Exfiltration Investigations

---

# Example SOC Investigation Metrics

| Metric                     | Count |
| -------------------------- | ----- |
| Total Alerts               | 911   |
| Investigation Queue Alerts | 208   |
| Correlated Attack Chains   | 59    |
| Critical Alerts            | 72    |
| High Severity Alerts       | 27    |
| PowerShell Alerts          | 149   |
| LOLBin Alerts              | 300+  |
| Malware Staging Alerts     | 142   |
| Network Outlier Alerts     | 236   |
| Persistence Alerts         | 74    |

---

# Key Takeaway

Effective triage reporting allows security analysts to rapidly identify genuine threats, reconstruct attack chains, prioritize incidents, and provide actionable intelligence to incident response teams.

A well-written triage report answers five critical questions:

1. What happened?
2. When did it happen?
3. How did it happen?
4. How severe is it?
5. What should be done next?

These reports form the foundation of modern Security Operations Center (SOC) investigations and incident response workflows.
