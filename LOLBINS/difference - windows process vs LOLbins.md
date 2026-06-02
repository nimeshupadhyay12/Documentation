# Windows Processes vs LOLBins (Living Off The Land Binaries)

| Aspect | Windows Processes | LOLBins (Living Off The Land Binaries) |
|----------|----------|----------|
| **Definition** | A running instance of a program, service, or operating system component. Every executable running in memory becomes a process. | Legitimate executables already present on a system that attackers abuse to perform malicious actions. |
| **Primary Objective** | Provide core operating system functionality and application execution. | Provide administrative, automation, troubleshooting, scripting, or development functionality. |
| **Designed For** | Operating system operation and application execution. | System administration, automation, development, and maintenance tasks. |
| **Created By** | Microsoft, software vendors, drivers, services, and applications. | Primarily Microsoft and trusted software vendors. |
| **Dependency on Windows** | Most core processes are required for Windows to function properly. | Usually not required for Windows operation. Windows can function normally without actively running them. |
| **Examples** | lsass.exe, svchost.exe, winlogon.exe, csrss.exe, smss.exe, services.exe. | powershell.exe, cmd.exe, certutil.exe, rundll32.exe, mshta.exe, wscript.exe, msbuild.exe. |
| **Role in the System** | Perform operating system functions, manage resources, provide services, and support applications. | Execute administrative tasks, scripts, commands, automation, development, and troubleshooting operations. |
| **Execution Frequency** | Usually always running after boot. | Executed only when required by users, administrators, or applications. |
| **Process Lifetime** | Often long-running and persistent throughout the system session. | Typically short-lived and terminate after completing their task. |
| **Trust Level** | Highly trusted because they are essential OS components. | Highly trusted because they are Microsoft-signed administrative utilities. |
| **Visibility in Enterprise Environments** | Seen constantly on all Windows systems. | Frequently observed in IT, development, and administration environments. |
| **Attacker Relationship** | Usually targeted by attackers. | Usually abused directly by attackers. |
| **Attacker Objective** | Compromise, inject into, manipulate, or extract data from them. | Use them to execute malicious commands while appearing legitimate. |
| **Typical Abuse Method** | Process injection, credential theft, process hollowing, token theft, persistence. | Fileless execution, payload delivery, script execution, defense evasion, lateral movement. |
| **MITRE ATT&CK Relationship** | Often the target or victim of ATT&CK techniques. | Often the execution mechanism for ATT&CK techniques. |
| **Examples of MITRE Mapping** | LSASS → T1003.001 (OS Credential Dumping), SVCHOST → T1055 (Process Injection). | PowerShell → T1059.001, Rundll32 → T1218.011, MSHTA → T1218.005. |
| **Disk Presence** | May be system binaries, applications, or services installed on the machine. | Already installed and trusted by default. |
| **Execution Context** | System, service, user, or application context. | Usually user or administrator context. |
| **Privileges** | Often SYSTEM-level or service-level privileges. | Usually inherit the privileges of the user executing them. |
| **Common Attack Use Cases** | Credential dumping, privilege escalation, persistence, process injection. | Malware execution, payload downloads, fileless attacks, remote script execution. |
| **Persistence Usage** | Attackers may modify or inject into them to maintain persistence. | Attackers often use them to create persistence mechanisms. |
| **Credential Access** | Frequently targeted (e.g., LSASS). | Frequently used to launch credential theft tools. |
| **Defense Evasion** | Attackers inject into trusted processes to evade detection. | Attackers use trusted binaries to blend into normal activity. |
| **Lateral Movement** | May host attacker tools after compromise. | Used directly to perform remote execution and administration. |
| **Command & Control (C2)** | Sometimes used as injection targets for malware. | Frequently used to establish C2 communications. |
| **Fileless Attack Capability** | Not typically designed for fileless execution. | Many LOLBins support direct fileless execution. |
| **Network Activity** | Usually limited to their intended functionality. | Often abused to download payloads and communicate externally. |
| **Monitoring Focus** | Integrity, injection attempts, memory access, abnormal child processes. | Command-line arguments, parent-child relationships, script execution, network activity. |
| **Blue Team Question** | "What happened to this process?" | "How was this LOLBin used?" |
| **Threat Hunting Focus** | Process injection, credential access, process abuse. | Execution chains, LOLBin abuse, suspicious command lines. |
| **Detection Strategy** | Monitor access, memory manipulation, token abuse, process injection. | Monitor command execution, downloads, encoded commands, script activity. |
| **Common EDR Alerts** | LSASS access, DLL injection, process hollowing, token manipulation. | Encoded PowerShell, Certutil downloads, MSHTA execution, Rundll32 abuse. |
| **Examples of Malicious Activity** | Mimikatz accessing LSASS, malware injecting into SVCHOST. | PowerShell downloading malware, Certutil transferring payloads, MSHTA launching scripts. |
| **SOC Priority** | Critical for detecting post-exploitation activities. | Critical for detecting initial execution and attacker tradecraft. |
| **Forensic Value** | Reveals attacker objectives and targets. | Reveals attacker execution methods and techniques. |
| **Blue Team Goal** | Protect and monitor critical system processes. | Detect and investigate abuse of legitimate administrative tools. |
