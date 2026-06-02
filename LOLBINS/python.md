# Python (python.exe)

## 1. What is it?
Python is a widely used programming language interpreter capable of running scripts, applications, and automation tasks.

## 2. Legitimate Use
- Software Development
- Automation
- Data Analysis
- Security Tooling
- System Administration

## 3. Why Attackers Abuse It
Python allows attackers to rapidly develop and execute custom malware, scanners, and post-exploitation tools.

## 4. Common Attack Techniques
- Custom Malware Execution
- Reconnaissance
- Network Scanning
- Data Exfiltration
- Reverse Shells

## 5. MITRE ATT&CK Mapping

| Technique ID | Technique |
|-------------|-----------|
| T1059.006 | Python |
| T1046 | Network Service Discovery |
| T1082 | System Information Discovery |
| T1041 | Exfiltration Over C2 Channel |

## 6. Detection Opportunities
- Sysmon Event ID 1
- Script Execution Monitoring
- Network Monitoring
- Child Process Analysis

## 7. Red Flags
- Python on non-developer systems
- Reverse shell behavior
- Python spawning PowerShell
- Scripts executing from Temp folders
- Suspicious outbound connections

## 8. Blue Team Takeaway
Python itself is not malicious, but its flexibility makes it a popular choice for attackers developing custom tools and malware.
