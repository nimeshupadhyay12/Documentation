<img width="2720" height="3440" alt="soc_automation_pipeline" src="https://github.com/user-attachments/assets/031cae1b-dab7-42dd-9c4e-7807d65c6988" />

## Explaination 
The one-liner (lead with this)

"I built an automated SOC pipeline that detects Microsoft 365 rare location logins from Elastic Security, investigates the user's full sign-in history, and delivers a formatted alert report to analysts — all without manual intervention."


The problem it solves

"Previously, when Elastic fired a rare location login alert, an analyst would have to manually open Kibana, find the alert, pivot to the O365 audit logs, filter by that user, pull their sign-in history, and write up a summary. That takes 15–30 minutes per alert and is fully repetitive. This tool does all of that automatically in under a minute."


How it works (the 3-layer explanation)
Layer 1 — Detection

"The script polls Elastic Security every 15 minutes, querying the alerts index for our rule — Microsoft 365 Portal Login from Rare Location. Any new alerts that haven't been processed before are picked up."

Layer 2 — Investigation

"For each alerted user, it automatically pulls their complete 7-day sign-in history from the O365 audit logs using Elasticsearch's scroll API, so there's no record limit. It extracts IP addresses, geolocation, browser, OS, ASN organisation, and login outcomes — cleans the data and builds a statistical summary: unique countries, most common login location, first and last seen timestamps, and so on."

Layer 3 — Notification

"It sends one consolidated HTML email per user to the SOC team. The email contains individual alert cards with MITRE ATT&CK mapping, VirusTotal links for each IP, and a full 7-day investigation summary. The complete sign-in history is attached as a CSV for deeper analysis."


Key engineering decisions (shows you thought it through)

"A few design choices I made deliberately:

1-hour lookback with deduplication — wide enough to catch indexing-delayed alerts, but the JSON dedup database ensures we never send duplicate emails regardless of how many times an alert appears in the window.
Consolidated emails — if one user triggers 5 alerts in 15 minutes, analysts get one structured email, not five. Reduces alert fatigue.
Scroll API for O365 history — a regular search caps at 10,000 hits. Scroll retrieves everything, no matter how active the user is.
Self-looping daemon — start it once, it runs forever. No Task Scheduler complexity."



What it covers from a security perspective

"The alert maps to MITRE ATT&CK T1078.004 — Valid Accounts, Cloud Accounts — under the Initial Access tactic. The tool surfaces everything an analyst needs for triage: the triggering IP and location, the user's normal login patterns over 7 days, and a direct VirusTotal link to check if the IP is known-malicious."


Current status and what's left

"The core pipeline is complete and tested. Before full production deployment, three things need to be done:

Move the SMTP credentials to environment variables — right now they're in the config file which is a security gap.
Update the API key path to a relative path so it works on any machine, not just my local setup.
Update the email recipients list to the full SOC distribution list."

## Feature-by-Feature Breakdown- 
Feature-by-feature breakdown
Detection engine (Stages 1–2)
The tool queries Elastic Security's internal alerts index (.alerts-security.alerts-default*) for any alerts matching the rule [Algosmic]Microsoft 365 Portal Login from Rare Location within a 5-hour lookback window. The 5-hour window is intentionally wide — even if Elastic indexing lags or a poll cycle runs late, every alert will be caught in at least one cycle. Duplicate suppression is handled entirely by the dedup DB, so the wide window is safe.
After fetching, alerts are grouped by user email so one user triggering 5 alerts in 15 minutes gets a single consolidated email, not 5 separate ones.
Deduplication system (Stage 2 + 12)
ProcessedAlertsDB is a JSON file (processed_alerts.json) that stores every alert UUID that has already been processed. Before doing any work on an alert, the tool checks this DB. After sending an email, it writes all UUIDs for that user in a single batch write. This means the system is idempotent — you can restart it, rerun it, or let it loop — and it will never send duplicate emails.
Investigation engine (Stages 3–7)
For each user with new alerts:

Context extraction pulls ~25 fields per alert: UUID, rule name, severity, risk score, source IP, full geo (country, city, region, continent), ASN organisation, browser, OS, user agent string, tenant namespace.
O365 history fetch runs a scroll query (not a simple search) against logs-o365.audit-* to retrieve all UserLoggedIn events for that user over the past 7 days — no 10,000-hit limits, no pagination gaps.
Data cleaning deduplicates rows, strips whitespace, normalises country names to title case, fills missing values with "N/A", and sorts by timestamp descending.

Investigation summary (Stage 9)
A statistical summary is built from the cleaned dataframe covering: total login events, unique country/city/IP/browser/OS counts, first and last seen timestamps, most common values for country/IP/browser/OS/ASN, and a link back to the triggering alert's country and IP.
Email reporting (Stages 10–11)
One consolidated HTML email per user per cycle containing:

A header with alert count badge and top severity colour-coded by risk (critical red → high orange → medium yellow → low green)
A user/tenant info block (email, username, domain, namespace, rule name)
Individual alert cards — one card per alert, each showing UUID, timestamp, risk score, source IP, full geo, ASN, browser, OS, user agent, a live VirusTotal link for the IP, and the MITRE ATT&CK mapping (T1078 / T1078.004 — Valid Accounts · Cloud Accounts, tactic: Initial Access)
A 7-day investigation summary table
The CSV attached directly to the email

CSV generation (Stage 8)
A UTF-8 BOM CSV (Excel-compatible) is written to output/csv_files/ with a timestamped filename. It contains all 21 parsed fields from every sign-in event across the 7-day window. Files older than 48 hours are automatically deleted at the start of each poll cycle.
Logging
A rotating file logger writes to output/logs/soc_automation.log with a 10 MB file cap and 5 backup files. Every function logs its own progress — alert counts, scroll pagination, email send status, CSV sizes, cleanup results — at INFO level, with DEBUG available for scroll page counts.


The bottom line

"This removes a fully manual, repetitive investigation task from the analyst workflow. Every rare location login now gets a structured investigation report automatically, within one poll cycle of the alert firing."
