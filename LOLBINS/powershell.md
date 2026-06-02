# PowerShell (powershell.exe)

## 1. What is it?
PowerShell is Microsoft's command-line shell and scripting framework built on .NET. It provides administrative, automation, and configuration management capabilities.

## 2. Legitimate Use
- System administration
- Active Directory management
- Software deployment
- Automation scripting
- Cloud administration

## 3. Why Attackers Abuse It
PowerShell is installed by default on Windows and can execute commands directly in memory, making it ideal for fileless attacks and post-exploitation activities.

## 4. Common Attack Techniques
- Fileless Malware
- Payload Downloading
- Command Execution
- Credential Access
- Reconnaissance
- Lateral Movement

## 5. MITRE ATT&CK Mapping

| Technique ID | Technique |
|-------------|-----------|
| T1059.001 | PowerShell |
| T1082 | System Information Discovery |
| T1083 | File and Directory Discovery |
| T1105 | Ingress Tool Transfer |
| T1003 | OS Credential Dumping |

## 6. Detection Opportunities
- PowerShell Event ID 4103
- PowerShell Event ID 4104
- Sysmon Event ID 1
- Encoded Commands
- Download Cradles

## 7. Red Flags
- -EncodedCommand usage
- Base64 encoded strings
- Office spawning PowerShell
- External URL downloads
- Hidden PowerShell windows

## 8. Blue Team Takeaway
PowerShell is one of the most abused LOLBins. Script Block Logging, AMSI monitoring, and EDR telemetry are critical for detecting malicious PowerShell activity.
