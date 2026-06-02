# MSHTA (mshta.exe)

## 1. What is it?
MSHTA is a Microsoft-signed Windows binary used to execute HTML Applications (HTA files). HTA files can contain HTML, JavaScript, and VBScript code and run outside normal browser security restrictions.

## 2. Legitimate Use
- Legacy administrative tools
- Internal enterprise applications
- HTA-based automation
- Script execution

## 3. Why Attackers Abuse It
MSHTA can execute scripts directly from local files or remote URLs without requiring PowerShell, making it useful for malware delivery and fileless attacks.

## 4. Common Attack Techniques
- Remote Script Execution
- Malware Delivery
- Fileless Attacks
- Payload Downloading
- Defense Evasion

## 5. MITRE ATT&CK Mapping

| Technique ID | Technique |
|-------------|-----------|
| T1218.005 | Mshta |
| T1059.007 | JavaScript |
| T1059.005 | VBScript |
| T1204 | User Execution |

## 6. Detection Opportunities
- Sysmon Event ID 1
- Process Creation Event ID 4688
- HTA File Execution
- Network Connections
- URL Monitoring

## 7. Red Flags
- MSHTA executing from Office applications
- Remote HTTP/HTTPS URLs
- HTA files in Temp folders
- Encoded JavaScript execution
- Downloads immediately after execution

## 8. Blue Team Takeaway
MSHTA is heavily abused in phishing campaigns because it can execute malicious scripts while appearing as a legitimate Microsoft binary.
