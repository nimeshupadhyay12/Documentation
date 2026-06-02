## 1.System Idle Process

### 1. Process Overview
- **Process Name:** System Idle Process
- **PID:** 0
- **Purpose:** Represents the percentage of CPU time that is currently unused by the system.
- **Legitimate Use:** Windows uses it as a bookkeeping mechanism to track idle CPU cycles. It is **not a real executable process**.

### 2. Attacker Abuse
- **Direct Abuse:** ❌ Not possible
- Since it is a kernel-generated pseudo-process and has no executable image, attackers cannot execute code through it.
- Malware cannot inject into or launch the System Idle Process itself.

### 3. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique |
|---------|-------------|-----------|
| N/A | N/A | No direct ATT&CK mapping |

**Analysis:**  
The System Idle Process is not associated with attacker activity and does not implement any MITRE ATT&CK techniques.

### 4. Common Attacks

| Attack | Possible? |
|----------|----------|
| Command Execution | ❌ |
| DLL Injection | ❌ |
| Shellcode Injection | ❌ |
| Process Hollowing | ❌ |
| Persistence | ❌ |
| Credential Theft | ❌ |

### 5. Detection Opportunities
- No security monitoring is generally required.
- A high System Idle Process percentage (90–99%) usually indicates normal system operation and low CPU utilization.

### 6. Red Flags
Investigate if:
- PID 0 appears with an executable path.
- A process named `System Idle Process.exe` exists.
- An EDR solution reports code execution originating from PID 0.

These situations may indicate process masquerading, malware deception, or telemetry issues.

### 7. SOC Verdict
✅ **Benign Windows Component**

The System Idle Process is a kernel accounting mechanism used to measure unused CPU resources. It is not a real executable process, cannot be abused directly by attackers, and generally requires no investigation unless its behavior appears abnormal or spoofed.

--------------------------------------------------------------------

## 2.System

### 1. Process Overview
- **Process Name:** System
- **PID:** 4
- **Parent Process:** None
- **Child Process:** `smss.exe`
- **Image:** `%SystemRoot%\System32\ntoskrnl.exe`
- **Purpose:** Represents the Windows Kernel and Executive. It hosts kernel-mode threads responsible for core operating system functionality.
- **Legitimate Use:** Handles low-level system operations such as memory management, process scheduling, hardware communication, and driver interactions.

### 2. Attacker Abuse
- **Direct Abuse:** ❌ Not directly possible
- Attackers cannot launch the System process because it is created by the Windows kernel during boot.
- Malware often interacts with kernel drivers associated with the System process to gain elevated privileges or hide malicious activity.
- Rootkits frequently target kernel structures managed by the System process.

### 3. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique |
|---------|-------------|-----------|
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation |
| Defense Evasion | T1014 | Rootkit |
| Persistence | T1542 | Pre-OS Boot |
| Defense Evasion | T1562 | Impair Defenses |

**Analysis:**  
The System process itself is not malicious, but attackers may exploit kernel vulnerabilities, load malicious drivers, or deploy rootkits that execute within kernel space and appear associated with PID 4 activity.

### 4. Common Attacks

| Attack | Possible? |
|----------|----------|
| Command Execution | ❌ |
| DLL Injection | ❌ |
| Shellcode Injection | ❌ |
| Kernel Driver Abuse | ✅ |
| Rootkit Installation | ✅ |
| Privilege Escalation | ✅ |
| Persistence | ✅ |

### 5. Detection Opportunities
- Monitor unsigned or suspicious kernel drivers.
- Monitor driver loading events.
- Detect abnormal kernel memory modifications.
- Investigate rootkit-related alerts from EDR solutions.

**Useful Logs:**
- Sysmon Event ID 6 (Driver Loaded)
- Sysmon Event ID 7 (Image Loaded)
- Windows Security Event ID 4697 (Service Installation)

### 6. Red Flags
Investigate if:
- Unsigned drivers are loaded.
- Unknown kernel drivers appear.
- PID 4 establishes unusual network connections.
- EDR reports rootkit behavior.
- Kernel memory modifications are detected.

### 7. SOC Verdict
✅ **Critical Windows Kernel Component**

The System process represents the Windows kernel and is essential for operating system functionality. While the process itself is legitimate, attackers frequently target the kernel through vulnerable drivers, rootkits, and privilege escalation exploits. Any suspicious activity involving PID 4 should be treated as a high-priority investigation.


-----------------------------------------------------------------------------------------------------------------------------------------


## 3.Memory Compression

### 1. Process Overview
- **Process Name:** Memory Compression
- **PID:** Dynamic (varies by system)
- **Parent Process:** System (PID 4)
- **User:** NT AUTHORITY\SYSTEM
- **Purpose:** Compresses memory pages in RAM instead of writing them to disk, improving system performance and reducing paging activity.
- **Legitimate Use:** Part of the Windows Memory Manager introduced in Windows 10 and later.

### 2. Attacker Abuse
- **Direct Abuse:** ❌ Not possible
- Memory Compression is a kernel-managed Windows component and is not directly executable by users or attackers.
- Malware may indirectly affect it by consuming excessive memory or attempting to hide malicious code in memory, but the process itself is not commonly abused.

### 3. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique |
|---------|-------------|-----------|
| N/A | N/A | No direct ATT&CK mapping |

**Analysis:**  
Memory Compression is a legitimate Windows memory management component and is not associated with attacker techniques. However, abnormal memory behavior may indicate malware operating elsewhere in the system.

### 4. Common Attacks

| Attack | Possible? |
|----------|----------|
| Command Execution | ❌ |
| DLL Injection | ❌ |
| Shellcode Injection | ❌ |
| Process Hollowing | ❌ |
| Persistence | ❌ |
| Credential Theft | ❌ |

### 5. Detection Opportunities
- Monitor for unusually high memory consumption.
- Investigate sudden spikes in compressed memory usage.
- Correlate memory anomalies with suspicious processes.

**Useful Logs:**
- Sysmon Event ID 1 (Process Creation)
- Sysmon Event ID 10 (Process Access)
- EDR Memory Analysis Alerts

### 6. Red Flags
Investigate if:
- Memory Compression consumes unusually high CPU for extended periods.
- System performance degrades significantly.
- EDR detects suspicious in-memory malware activity.
- Memory exhaustion occurs without a clear cause.

### 7. SOC Verdict
✅ **Benign Windows Component**

Memory Compression is a legitimate Windows memory management feature that improves performance by compressing memory pages in RAM. It is not directly exploitable or abused by attackers, though abnormal memory usage patterns may warrant investigation of other processes on the system.


-----------------------------------------------------------------------------------------------------------------------------------------

## 4.Registry

### 1. Process Overview
- **Process Name:** Registry
- **PID:** Dynamic (varies by system)
- **Parent Process:** None
- **User:** NT AUTHORITY\SYSTEM
- **Purpose:** Stores and manages Windows Registry hive data, including HKLM (HKEY_LOCAL_MACHINE) and HKCU (HKEY_CURRENT_USER).
- **Legitimate Use:** Improves registry performance and memory efficiency by managing registry hives as a dedicated kernel-managed process.

### 2. Attacker Abuse
- **Direct Abuse:** ❌ Not possible
- The Registry process itself cannot be executed or abused directly.
- Attackers frequently modify registry keys to establish persistence, disable security tools, execute malware at startup, or store configuration data.

### 3. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique |
|---------|-------------|-----------|
| Persistence | T1547.001 | Registry Run Keys / Startup Folder |
| Defense Evasion | T1112 | Modify Registry |
| Persistence | T1546.001 | Change Default File Association |
| Credential Access | T1003.002 | Security Account Manager (SAM) |

**Analysis:**  
While the Registry process itself is legitimate, attackers commonly abuse the Windows Registry for persistence, defense evasion, and storing malicious configurations.

### 4. Common Attacks

| Attack | Possible? |
|----------|----------|
| Command Execution | ❌ |
| DLL Injection | ❌ |
| Shellcode Injection | ❌ |
| Registry Persistence | ✅ |
| Defense Evasion | ✅ |
| Credential Theft | ✅ |

### 5. Detection Opportunities
- Monitor registry modifications to startup locations.
- Detect changes to security-related registry keys.
- Monitor access to SAM, SECURITY, and SYSTEM hives.

**Useful Logs:**
- Sysmon Event ID 12 (Registry Object Create/Delete)
- Sysmon Event ID 13 (Registry Value Set)
- Sysmon Event ID 14 (Registry Key Rename)
- Windows Security Event ID 4657 (Registry Modification)

### 6. Red Flags
Investigate if:
- New Run or RunOnce keys are created.
- Security tools are disabled through registry modifications.
- Unknown applications modify registry startup entries.
- Registry keys are modified shortly before malware execution.

### 7. SOC Verdict
✅ **Benign Windows Component**

The Registry process is a legitimate Windows component responsible for managing registry hive data. Although the process itself is not directly exploitable, the Windows Registry is one of the most common persistence and defense-evasion mechanisms used by attackers, making registry monitoring a critical blue-team activity.


-----------------------------------------------------------------------------------------------------------------------------------------


## 5.Session Manager Subsystem (SMSS.EXE)

### 1. Process Overview
- **Process Name:** SMSS.EXE (Session Manager Subsystem)
- **PID:** Dynamic
- **Parent Process:** System (PID 4)
- **Image:** `%SystemRoot%\System32\smss.exe`
- **Purpose:** First user-mode process started by Windows. Responsible for session creation, environment initialization, registry initialization, and launching core Windows processes.
- **Legitimate Use:** Creates `csrss.exe`, `wininit.exe`, `winlogon.exe`, and additional sessions for logged-on users.

### 2. Attacker Abuse
- **Direct Abuse:** ⚠️ Rare
- Attackers rarely abuse the legitimate SMSS process directly.
- Malware may attempt to masquerade as `smss.exe`.
- Suspicious child processes spawned by SMSS can indicate process injection, malware, or boot-time persistence.

### 3. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique |
|---------|-------------|-----------|
| Defense Evasion | T1036 | Masquerading |
| Persistence | T1542 | Pre-OS Boot |
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation |
| Defense Evasion | T1014 | Rootkit |

**Analysis:**  
SMSS is a critical Windows startup component. Attackers typically target the boot process, kernel, or masquerade as `smss.exe` rather than abusing the legitimate process itself.

### 4. Common Attacks

| Attack | Possible? |
|----------|----------|
| Command Execution | ❌ |
| DLL Injection | ⚠️ Rare |
| Shellcode Injection | ⚠️ Rare |
| Process Masquerading | ✅ |
| Rootkit Activity | ✅ |
| Boot Persistence | ✅ |

### 5. Detection Opportunities
- Monitor unexpected instances of `smss.exe`.
- Verify execution path is `%SystemRoot%\System32\smss.exe`.
- Investigate unusual child processes spawned by SMSS.

**Useful Logs:**
- Sysmon Event ID 1 (Process Creation)
- Sysmon Event ID 7 (Image Load)
- Sysmon Event ID 10 (Process Access)

### 6. Red Flags
Investigate if:
- Multiple persistent `smss.exe` processes exist after boot.
- `smss.exe` runs from a non-System32 directory.
- `smss.exe` is spawned by any process other than System (PID 4).
- Network activity originates from `smss.exe`.
- Unsigned binaries masquerade as `smss.exe`.

### 7. SOC Verdict
✅ **Critical Windows Process**

SMSS.EXE is the first user-mode process launched during system startup and is essential for Windows operation. The legitimate process is rarely abused directly, but attackers often masquerade as `smss.exe` or target the boot process for persistence and privilege escalation. Any deviation from normal SMSS behavior should be considered highly suspicious.


-----------------------------------------------------------------------------------------------------------------------------------------

## 6.Windows Subsystem Process (CSRSS.EXE)

### 1. Process Overview
- **Process Name:** CSRSS.EXE (Client Server Runtime Subsystem)
- **PID:** Dynamic
- **Parent Process:** Orphan Process (original parent SMSS.EXE exits after startup)
- **Image:** `%SystemRoot%\System32\csrss.exe`
- **Purpose:** Manages console windows, thread creation, process shutdown operations, and portions of the Windows subsystem.
- **Legitimate Use:** Essential Windows user-mode subsystem process created during system startup.

### 2. Attacker Abuse
- **Direct Abuse:** ⚠️ Rare
- Attackers rarely inject into CSRSS because it is a highly protected and monitored process.
- Malware commonly masquerades as `csrss.exe` to evade detection.
- Privileged malware and rootkits may target CSRSS for process manipulation or stealth.

### 3. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique |
|---------|-------------|-----------|
| Defense Evasion | T1036 | Masquerading |
| Defense Evasion | T1055 | Process Injection |
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation |
| Defense Evasion | T1014 | Rootkit |

**Analysis:**  
The legitimate CSRSS process is a critical Windows component. Most attacker activity involves masquerading as `csrss.exe` or attempting process injection into privileged system processes.

### 4. Common Attacks

| Attack | Possible? |
|----------|----------|
| Command Execution | ❌ |
| DLL Injection | ⚠️ Rare |
| Shellcode Injection | ⚠️ Rare |
| Process Injection | ✅ |
| Process Masquerading | ✅ |
| Privilege Escalation | ✅ |

### 5. Detection Opportunities
- Monitor execution paths for `csrss.exe`.
- Detect attempts to access or inject into CSRSS memory.
- Investigate duplicate or unexpected CSRSS instances.

**Useful Logs:**
- Sysmon Event ID 1 (Process Creation)
- Sysmon Event ID 8 (CreateRemoteThread)
- Sysmon Event ID 10 (Process Access)
- Sysmon Event ID 7 (Image Load)

### 6. Red Flags
Investigate if:
- `csrss.exe` runs outside `%SystemRoot%\System32\`.
- Multiple abnormal CSRSS instances exist.
- A user process attempts to access CSRSS memory.
- Network connections originate from `csrss.exe`.
- Unsigned binaries masquerade as `csrss.exe`.

### 7. SOC Verdict
✅ **Critical Windows Process**

CSRSS.EXE is a core Windows subsystem process required for normal operating system functionality. The legitimate process is rarely abused directly, but attackers frequently use process masquerading and injection techniques involving CSRSS-related activity. Any abnormal execution path, memory access, or network activity associated with CSRSS should be treated as highly suspicious.

-----------------------------------------------------------------------------------------------------------------------------------------


## 7.Windows Initialization Process (WININIT.EXE)

### 1. Process Overview
- **Process Name:** WININIT.EXE
- **PID:** Dynamic
- **Parent Process:** Orphan Process (original Session 0 SMSS.EXE exits after startup)
- **Child Processes:** `services.exe`, `lsass.exe`, `fontdrvhost.exe`
- **Image:** `%SystemRoot%\System32\wininit.exe`
- **Purpose:** Initializes critical Windows system components during boot.
- **Legitimate Use:** Creates the Service Control Manager, Local Security Authority (LSASS), font driver host, system environment variables, and other core operating system resources.

### 2. Attacker Abuse
- **Direct Abuse:** ⚠️ Rare
- Attackers rarely target the legitimate WININIT process directly.
- Malware may masquerade as `wininit.exe`.
- Compromising WININIT child processes (`lsass.exe` and `services.exe`) is a common attacker objective.

### 3. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique |
|---------|-------------|-----------|
| Defense Evasion | T1036 | Masquerading |
| Credential Access | T1003.001 | LSASS Memory |
| Persistence | T1543.003 | Windows Service |
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation |

**Analysis:**  
WININIT itself is rarely abused, but it launches several high-value targets frequently attacked by adversaries, particularly `lsass.exe` for credential theft and `services.exe` for persistence.

### 4. Common Attacks

| Attack | Possible? |
|----------|----------|
| Command Execution | ❌ |
| DLL Injection | ⚠️ Rare |
| Shellcode Injection | ⚠️ Rare |
| Process Masquerading | ✅ |
| Service Persistence | ✅ |
| Credential Theft (via LSASS) | ✅ |

### 5. Detection Opportunities
- Monitor for fake `wininit.exe` binaries.
- Verify execution path and digital signature.
- Investigate suspicious activity involving child processes such as `lsass.exe` and `services.exe`.

**Useful Logs:**
- Sysmon Event ID 1 (Process Creation)
- Sysmon Event ID 7 (Image Load)
- Sysmon Event ID 10 (Process Access)
- Windows Security Event ID 4697 (Service Installation)

### 6. Red Flags
Investigate if:
- `wininit.exe` runs outside `%SystemRoot%\System32\`.
- Multiple WININIT instances exist.
- WININIT initiates network connections.
- Unsigned binaries masquerade as `wininit.exe`.
- Unexpected child processes are spawned.

### 7. SOC Verdict
✅ **Critical Windows Process**

WININIT.EXE is a core Windows startup process responsible for initializing critical system services and security components. The legitimate process is rarely malicious, but attackers often target its child processes for credential theft, persistence, and privilege escalation. Any abnormal WININIT behavior should be considered highly suspicious.

-----------------------------------------------------------------------------------------------------------------------------------------

## 8.Service Control Manager (SERVICES.EXE)

### 1. Process Overview
- **Process Name:** SERVICES.EXE
- **PID:** Dynamic
- **Parent Process:** `wininit.exe`
- **Child Processes:** Windows Services (e.g., `svchost.exe`, third-party services)
- **Image:** `%SystemRoot%\System32\services.exe`
- **Purpose:** Manages the lifecycle of Windows services, including starting, stopping, and monitoring them.
- **Legitimate Use:** Loads services defined in `HKLM\SYSTEM\CurrentControlSet\Services\` during system startup and runtime.

### 2. Attacker Abuse
- **Direct Abuse:** ⚠️ Common
- Attackers frequently create malicious services to achieve persistence.
- Malware often installs itself as a Windows service.
- Threat actors use services to execute payloads with SYSTEM privileges.

### 3. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique |
|---------|-------------|-----------|
| Persistence | T1543.003 | Create or Modify System Process: Windows Service |
| Privilege Escalation | T1543.003 | Create or Modify System Process: Windows Service |
| Defense Evasion | T1036 | Masquerading |
| Execution | T1569.002 | Service Execution |

**Analysis:**  
SERVICES.EXE is one of the most commonly abused Windows components because services can provide persistence, privilege escalation, and stealthy execution of malicious code.

### 4. Common Attacks

| Attack | Possible? |
|----------|----------|
| Command Execution | ✅ |
| DLL Injection | ⚠️ Possible |
| Shellcode Injection | ⚠️ Possible |
| Service Persistence | ✅ |
| Privilege Escalation | ✅ |
| Process Masquerading | ✅ |

### 5. Detection Opportunities
- Monitor creation of new services.
- Investigate modifications to existing service configurations.
- Monitor services executing from unusual directories.

**Useful Logs:**
- Sysmon Event ID 1 (Process Creation)
- Sysmon Event ID 13 (Registry Value Set)
- Windows Security Event ID 4697 (Service Installation)
- System Event ID 7045 (New Service Installed)

### 6. Red Flags
Investigate if:
- A new service is installed unexpectedly.
- Service binaries execute from `Temp`, `Downloads`, or user-writable directories.
- Unsigned executables are configured as services.
- Services are created shortly before suspicious activity.
- `services.exe` launches unusual child processes.

### 7. SOC Verdict
⚠️ **High-Value Monitoring Target**

SERVICES.EXE is a legitimate and critical Windows process, but it is one of the most frequently abused components for persistence and privilege escalation. Blue teams should closely monitor service creation, modification, and execution activity, as malicious services are a common technique used by malware, ransomware, and advanced threat actors.

-----------------------------------------------------------------------------------------------------------------------------------------

## WINDOWS CORE PROECESS MAP - 
Windows Core Processes
│
├── System Idle Process (PID 0)
│   ├── Purpose
│   │   └── Tracks unused CPU cycles
│   ├── Attacker Abuse
│   │   └── None (Pseudo Process)
│   └── MITRE ATT&CK
│       └── No Direct Mapping
│
├── System (PID 4)
│   ├── Purpose
│   │   └── Windows Kernel & Executive
│   ├── Attacker Abuse
│   │   ├── Rootkits
│   │   ├── Malicious Drivers
│   │   └── Kernel Exploits
│   └── MITRE ATT&CK
│       ├── T1068 - Exploitation for Privilege Escalation
│       ├── T1014 - Rootkit
│       ├── T1542 - Pre-OS Boot
│       └── T1562 - Impair Defenses
│
├── Memory Compression
│   ├── Purpose
│   │   └── Compresses RAM pages
│   ├── Attacker Abuse
│   │   └── None Directly
│   └── MITRE ATT&CK
│       └── No Direct Mapping
│
├── Registry
│   ├── Purpose
│   │   └── Stores Registry Hive Data
│   ├── Attacker Abuse
│   │   ├── Persistence
│   │   ├── Security Tool Bypass
│   │   └── Credential Storage Access
│   └── MITRE ATT&CK
│       ├── T1547.001 - Registry Run Keys
│       ├── T1112 - Modify Registry
│       ├── T1546.001 - File Association Hijacking
│       └── T1003.002 - SAM Database Access
│
├── SMSS.EXE (Session Manager)
│   ├── Purpose
│   │   ├── Creates Sessions
│   │   ├── Starts WININIT
│   │   ├── Starts WINLOGON
│   │   └── Starts CSRSS
│   ├── Attacker Abuse
│   │   ├── Masquerading
│   │   ├── Boot Persistence
│   │   └── Rootkits
│   └── MITRE ATT&CK
│       ├── T1036 - Masquerading
│       ├── T1542 - Pre-OS Boot
│       ├── T1068 - Privilege Escalation
│       └── T1014 - Rootkit
│
├── CSRSS.EXE (Client Server Runtime Subsystem)
│   ├── Purpose
│   │   ├── Console Windows
│   │   ├── Thread Creation
│   │   └── Process Shutdown Handling
│   ├── Attacker Abuse
│   │   ├── Process Injection
│   │   ├── Masquerading
│   │   └── Privileged Process Access
│   └── MITRE ATT&CK
│       ├── T1055 - Process Injection
│       ├── T1036 - Masquerading
│       ├── T1014 - Rootkit
│       └── T1068 - Privilege Escalation
│
├── WININIT.EXE (Windows Initialization Process)
│   ├── Purpose
│   │   ├── Creates SERVICES.EXE
│   │   ├── Creates LSASS.EXE
│   │   └── Creates FONTDRVHOST.EXE
│   ├── Attacker Abuse
│   │   ├── LSASS Targeting
│   │   ├── Service Persistence
│   │   └── Masquerading
│   └── MITRE ATT&CK
│       ├── T1003.001 - LSASS Memory
│       ├── T1543.003 - Windows Service
│       ├── T1036 - Masquerading
│       └── T1068 - Privilege Escalation
│
└── SERVICES.EXE (Service Control Manager)
    ├── Purpose
    │   ├── Start Services
    │   ├── Stop Services
    │   └── Manage Windows Services
    ├── Attacker Abuse
    │   ├── Persistence
    │   ├── SYSTEM Privilege Execution
    │   ├── Malware Services
    │   └── Service-Based Backdoors
    └── MITRE ATT&CK
        ├── T1543.003 - Create/Modify Windows Service
        ├── T1569.002 - Service Execution
        ├── T1036 - Masquerading
        └── T1543 - System Process Manipulation
        System (PID 4)
│
└── SMSS.EXE (Master Session Manager)
    │
    ├── SMSS.EXE (Session 0)
    │   │
    │   ├── WININIT.EXE
    │   │   │
    │   │   ├── SERVICES.EXE
    │   │   ├── LSASS.EXE
    │   │   └── FONTDRVHOST.EXE
    │   │
    │   └── CSRSS.EXE (Session 0)
    │
    └── SMSS.EXE (Session 1)
        │
        ├── WINLOGON.EXE
        │
        └── CSRSS.EXE (Session 1)


