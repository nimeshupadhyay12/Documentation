# Command Prompt (cmd.exe)

## 1. What is it?
CMD is the traditional Windows command interpreter used to execute commands and batch scripts.

## 2. Legitimate Use
- Administrative tasks
- Batch automation
- Troubleshooting
- Script execution

## 3. Why Attackers Abuse It
CMD provides a simple method to execute commands, chain operations, and launch other tools or payloads.

## 4. Common Attack Techniques
- Command Execution
- Batch Script Execution
- Payload Staging
- Process Launching

## 5. MITRE ATT&CK Mapping

| Technique ID | Technique |
|-------------|-----------|
| T1059.003 | Windows Command Shell |
| T1204 | User Execution |
| T1105 | Ingress Tool Transfer |

## 6. Detection Opportunities
- Sysmon Event ID 1
- Process Creation Event ID 4688
- Parent-Child Process Analysis
- Suspicious Command Lines

## 7. Red Flags
- Office → CMD
- Browser → CMD
- Long chained commands
- CMD spawning PowerShell
- CMD spawning Certutil

## 8. Blue Team Takeaway
CMD is commonly used as an execution bridge between initial access and malware execution. Context is critical when investigating CMD activity.
