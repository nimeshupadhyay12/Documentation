# LOLBins → MITRE ATT&CK Detailed Mapping

---

# PowerShell (powershell.exe)

## Primary Abuse
**Fileless Execution**

## ATT&CK Technique ID
**T1059.001**

## ATT&CK Technique Name
**Command and Scripting Interpreter: PowerShell**

## How Attackers Use It
- Execute malicious PowerShell scripts
- Download payloads from remote servers
- Perform reconnaissance
- Execute fileless malware
- Dump credentials
- Establish persistence

## Example Attack Scenario

```text
Phishing Email
      ↓
Word Document
      ↓
PowerShell Executes
      ↓
Downloads Payload
      ↓
Establishes C2 Connection
```

## Why It Is Dangerous
PowerShell is installed by default on Windows systems, highly powerful, and trusted by administrators, making malicious activity difficult to distinguish from legitimate use.

---

# CMD (cmd.exe)

## Primary Abuse
**Command Execution**

## ATT&CK Technique ID
**T1059.003**

## ATT&CK Technique Name
**Command and Scripting Interpreter: Windows Command Shell**

## How Attackers Use It
- Execute batch scripts
- Launch malware
- Execute system commands
- Run reconnaissance commands
- Spawn other LOLBins

## Example Attack Scenario

```text
Malware Execution
      ↓
cmd.exe
      ↓
whoami
ipconfig
net user
      ↓
Reconnaissance
```

## Why It Is Dangerous
CMD is available on every Windows system and often acts as the bridge between initial compromise and further attacker activity.

---

# Rundll32 (rundll32.exe)

## Primary Abuse
**DLL Execution**

## ATT&CK Technique ID
**T1218.011**

## ATT&CK Technique Name
**Signed Binary Proxy Execution: Rundll32**

## How Attackers Use It
- Execute malicious DLLs
- Execute remote scriptlets
- Evade application controls
- Bypass security monitoring

## Example Attack Scenario

```text
Malicious DLL
      ↓
rundll32.exe
      ↓
DLL Export Function
      ↓
Payload Execution
```

## Why It Is Dangerous
Because Rundll32 is a trusted Microsoft binary, malicious activity can appear legitimate to security controls.

---

# MSHTA (mshta.exe)

## Primary Abuse
**Script Execution**

## ATT&CK Technique ID
**T1218.005**

## ATT&CK Technique Name
**Signed Binary Proxy Execution: Mshta**

## How Attackers Use It
- Execute malicious HTA files
- Execute remote scripts
- Deliver malware
- Launch fileless attacks

## Example Attack Scenario

```text
Phishing Email
      ↓
HTA File
      ↓
mshta.exe
      ↓
JavaScript Execution
      ↓
Malware Download
```

## Why It Is Dangerous
MSHTA can execute scripts from remote URLs and bypass many traditional security controls.

---

# WScript (VBScript)

## Primary Abuse
**VBScript Execution**

## ATT&CK Technique ID
**T1059.005**

## ATT&CK Technique Name
**Command and Scripting Interpreter: Visual Basic**

## How Attackers Use It
- Execute VBS malware
- Run login script abuse
- Establish persistence
- Download payloads

## Example Attack Scenario

```text
Malicious VBS File
      ↓
wscript.exe
      ↓
Payload Download
      ↓
Malware Execution
```

## Why It Is Dangerous
VBScript remains common in phishing attachments and malware droppers.

---

# WScript (JavaScript)

## Primary Abuse
**JScript Execution**

## ATT&CK Technique ID
**T1059.007**

## ATT&CK Technique Name
**Command and Scripting Interpreter: JavaScript**

## How Attackers Use It
- Execute malicious JavaScript
- Download malware
- Perform reconnaissance
- Execute payloads

## Example Attack Scenario

```text
Malicious JS File
      ↓
wscript.exe
      ↓
JavaScript Execution
      ↓
Payload Download
```

## Why It Is Dangerous
JavaScript-based malware remains one of the most common initial access mechanisms.

---

# Python (python.exe)

## Primary Abuse
**Custom Malware Execution**

## ATT&CK Technique ID
**T1059.006**

## ATT&CK Technique Name
**Command and Scripting Interpreter: Python**

## How Attackers Use It
- Build malware
- Execute ransomware
- Perform scanning
- Establish reverse shells
- Exfiltrate data

## Example Attack Scenario

```text
python.exe
      ↓
Custom Script
      ↓
Reverse Shell
      ↓
Command & Control
```

## Why It Is Dangerous
Python provides attackers with an extremely flexible development and execution platform.

---

# Certutil (Payload Downloading)

## Primary Abuse
**Payload Downloading**

## ATT&CK Technique ID
**T1105**

## ATT&CK Technique Name
**Ingress Tool Transfer**

## How Attackers Use It
- Download malware
- Transfer payloads
- Retrieve tools
- Stage attacks

## Example Attack Scenario

```text
certutil.exe
      ↓
Download Payload
      ↓
Save To Disk
      ↓
Execute Malware
```

## Why It Is Dangerous
Certutil is signed by Microsoft and commonly bypasses security restrictions.

---

# Certutil (Payload Decoding)

## Primary Abuse
**Payload Decoding**

## ATT&CK Technique ID
**T1140**

## ATT&CK Technique Name
**Deobfuscate/Decode Files or Information**

## How Attackers Use It
- Decode malware
- Decode scripts
- Unpack payloads
- Evade detection

## Example Attack Scenario

```text
Encoded Payload
      ↓
certutil -decode
      ↓
Executable Created
      ↓
Malware Execution
```

## Why It Is Dangerous
Allows attackers to hide malicious content until execution time.

---

# MSDT (msdt.exe)

## Primary Abuse
**Exploitation**

## ATT&CK Technique ID
**T1203**

## ATT&CK Technique Name
**Exploitation for Client Execution**

## How Attackers Use It
- Exploit Office documents
- Trigger remote code execution
- Launch payloads
- Execute commands

## Example Attack Scenario

```text
Malicious Word Document
      ↓
MSDT Triggered
      ↓
Code Execution
      ↓
Payload Deployment
```

## Why It Is Dangerous
Can lead to code execution without requiring macros or significant user interaction.

---

# MSBuild (msbuild.exe)

## Primary Abuse
**Fileless Execution**

## ATT&CK Technique ID
**T1127.001**

## ATT&CK Technique Name
**Trusted Developer Utilities Proxy Execution: MSBuild**

## How Attackers Use It
- Execute inline C# code
- Execute fileless malware
- Bypass application controls
- Launch payloads

## Example Attack Scenario

```text
Malicious XML Project File
      ↓
msbuild.exe
      ↓
Embedded C# Code
      ↓
Payload Execution
```

## Why It Is Dangerous
MSBuild is a trusted Microsoft developer utility capable of executing malicious code without dropping a conventional executable, making it highly effective for defense evasion and fileless attacks.

---

# Quick Comparison

| LOLBin | ATT&CK ID | ATT&CK Name | Main Abuse |
|----------|----------|----------|----------|
| PowerShell | T1059.001 | PowerShell | Fileless Execution |
| CMD | T1059.003 | Windows Command Shell | Command Execution |
| Rundll32 | T1218.011 | Signed Binary Proxy Execution: Rundll32 | DLL Execution |
| MSHTA | T1218.005 | Signed Binary Proxy Execution: Mshta | Script Execution |
| WScript | T1059.005 | Visual Basic | VBScript Execution |
| WScript | T1059.007 | JavaScript | JScript Execution |
| Python | T1059.006 | Python | Custom Malware |
| Certutil | T1105 | Ingress Tool Transfer | Payload Downloading |
| Certutil | T1140 | Deobfuscate/Decode Files | Payload Decoding |
| MSDT | T1203 | Exploitation for Client Execution | Exploitation |
| MSBuild | T1127.001 | Trusted Developer Utilities Proxy Execution: MSBuild | Fileless Execution |
