# MSDT (msdt.exe)

## 1. What is it?
MSDT (Microsoft Support Diagnostic Tool) is a Windows troubleshooting utility used to collect diagnostic information and resolve system issues.

## 2. Legitimate Use
- System Diagnostics
- Troubleshooting
- Technical Support
- Automated Problem Resolution

## 3. Why Attackers Abuse It
MSDT has been abused through vulnerabilities such as Follina to achieve code execution without requiring macros.

## 4. Common Attack Techniques
- Remote Code Execution
- Phishing-Based Exploitation
- Payload Execution
- Defense Evasion

## 5. MITRE ATT&CK Mapping

| Technique ID | Technique |
|-------------|-----------|
| T1203 | Exploitation for Client Execution |
| T1218 | Signed Binary Proxy Execution |
| T1204 | User Execution |

## 6. Detection Opportunities
- Process Creation Monitoring
- Office Application Relationships
- Command Line Analysis
- EDR Behavioral Alerts

## 7. Red Flags
- Word spawning MSDT
- Office documents triggering MSDT
- Remote template exploitation
- Unexpected diagnostic execution
- External network activity

## 8. Blue Team Takeaway
MSDT became a major attack vector during the Follina vulnerability campaign and should be monitored when launched by Office applications.
