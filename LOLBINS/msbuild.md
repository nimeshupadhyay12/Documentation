# MSBuild (msbuild.exe)

## 1. What is it?
MSBuild is Microsoft's build platform used to compile and build .NET applications from project files.

## 2. Legitimate Use
- Software Development
- Application Compilation
- Build Automation
- CI/CD Pipelines

## 3. Why Attackers Abuse It
MSBuild can execute embedded code inside project files without requiring traditional executable files, enabling fileless execution.

## 4. Common Attack Techniques
- Inline Code Execution
- Fileless Malware
- Payload Execution
- Defense Evasion
- Proxy Execution

## 5. MITRE ATT&CK Mapping

| Technique ID | Technique |
|-------------|-----------|
| T1127.001 | MSBuild |
| T1059 | Command and Scripting Interpreter |
| T1218 | Signed Binary Proxy Execution |

## 6. Detection Opportunities
- Sysmon Event ID 1
- Project File Monitoring
- Parent-Child Process Analysis
- Command Line Inspection

## 7. Red Flags
- MSBuild on non-developer systems
- Project files executing from Temp directories
- Office spawning MSBuild
- Encoded payloads inside XML project files
- Network activity from MSBuild

## 8. Blue Team Takeaway
MSBuild is a powerful LOLBin capable of executing malicious code through project files, making it a valuable tool for fileless attacks and defense evasion.
