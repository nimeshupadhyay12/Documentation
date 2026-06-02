# Rundll32 (rundll32.exe)

## 1. What is it?
Rundll32 is a Windows utility used to execute exported functions from Dynamic Link Libraries (DLLs).

## 2. Legitimate Use
- Running Control Panel applets
- Executing DLL-based Windows functions
- Loading Windows components

## 3. Why Attackers Abuse It
Rundll32 allows attackers to execute malicious DLLs while appearing as a legitimate Microsoft process.

## 4. Common Attack Techniques
- DLL Execution
- Proxy Execution
- Defense Evasion
- Remote Payload Execution

## 5. MITRE ATT&CK Mapping

| Technique ID | Technique |
|-------------|-----------|
| T1218.011 | Rundll32 |
| T1574 | DLL Search Order Hijacking |
| T1055 | Process Injection |

## 6. Detection Opportunities
- Sysmon Event ID 1
- DLL Load Monitoring
- Network Connections
- Command-Line Analysis

## 7. Red Flags
- DLLs loaded from Temp directories
- Network activity from Rundll32
- User profile paths in command line
- Suspicious DLL exports

## 8. Blue Team Takeaway
Rundll32 is a common defense-evasion LOLBin because attackers can run malicious code under a trusted Windows binary.
