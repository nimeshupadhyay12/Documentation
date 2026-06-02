# WScript (wscript.exe)

## 1. What is it?
WScript is the Windows Script Host executable used to run VBScript (.vbs) and JScript (.js) files.

## 2. Legitimate Use
- Administrative automation
- Login scripts
- System management
- Enterprise scripting

## 3. Why Attackers Abuse It
WScript provides a native scripting environment that can execute malicious scripts without requiring PowerShell.

## 4. Common Attack Techniques
- Script Execution
- Malware Launching
- Persistence
- Payload Delivery
- Defense Evasion

## 5. MITRE ATT&CK Mapping

| Technique ID | Technique |
|-------------|-----------|
| T1059.005 | VBScript |
| T1059.007 | JavaScript |
| T1204 | User Execution |
| T1547 | Boot or Logon Autostart Execution |

## 6. Detection Opportunities
- Sysmon Event ID 1
- Script File Monitoring
- Command Line Analysis
- Parent-Child Relationships

## 7. Red Flags
- VBS files in Downloads folder
- Scripts launched from Temp directories
- Office spawning WScript
- Encoded script execution
- Network activity from WScript

## 8. Blue Team Takeaway
WScript is commonly observed in phishing attacks and malware droppers that use VBScript or JavaScript to launch additional payloads.
