# Consolidated Vulnerability Findings — Grouped by Family

This document groups every individual Nessus finding from the source scan into vulnerability **families** (same underlying product/component). 
For each family, the single highest-priority fix is identified — applying it resolves every finding listed underneath it. 
**Total individual findings processed: 1060 — grouped into 49 families. Nothing was dropped.**


## Critical Severity Families (26 families, 993 findings)

### 1. Legacy Windows Server 2012 / 2012 R2 / 8.1 - Monthly & Cumulative Security Updates (OS EOL)
- **Severity level(s) this family appears under:** Critical/High/Medium/Low
- **Individual findings merged into this family:** 396
- **Affected host(s):** 172.16.16.4, 172.16.16.10, 172.16.16.18, 172.16.16.20
- **Fix / remediation:** **OS is End-of-Life (Server 2012/2012 R2/8.1 & IE are no longer patched by Microsoft).** No cumulative update fixes this permanently — remediation requires migrating these hosts off the legacy OS (e.g. upgrade to Windows Server 2019/2022) rather than a single patch.

### 2. Adobe Flash Player (all versions / all vendor patches)
- **Severity level(s) this family appears under:** Critical/High/Medium
- **Individual findings merged into this family:** 157
- **Affected host(s):** 172.16.16.4
- **Fix / remediation:** **End-of-Life / unsupported product.** No further vendor patches exist — the only fix is to fully remove/replace the software (it cannot be brought to a 'fixed' version).

### 3. Mozilla Firefox (mainline)
- **Severity level(s) this family appears under:** Critical/High/Medium
- **Individual findings merged into this family:** 114
- **Affected host(s):** 172.16.16.4, 172.16.16.10
- **Fix / remediation:** Upgrade to the version fixed in: **"Mozilla Firefox < 152.0"** — the highest fix version found in this family; upgrading to it (or later) resolves every other item below.

### 4. Windows 10 (1809) / Windows Server 2019 - Monthly Cumulative Security Updates
- **Severity level(s) this family appears under:** Critical/High/Medium
- **Individual findings merged into this family:** 51
- **Affected host(s):** 172.16.16.71
- **Fix / remediation:** Apply the latest cumulative/monthly security update: **"KB5094123: Windows 10 version 1809 / Windows Server 2019 Security Update (June 2026)"** (and all later ones as they release). Applying the most recent monthly update resolves every dated item below it in this family.

### 5. Microsoft .NET Framework - Monthly Security Updates
- **Severity level(s) this family appears under:** Critical/High/Medium/Low
- **Individual findings merged into this family:** 48
- **Affected host(s):** 172.16.16.4, 172.16.16.10, 172.16.16.18, 172.16.16.20, 172.16.16.71
- **Fix / remediation:** Apply the latest cumulative/monthly security update: **"Security Updates for Microsoft .NET Framework (October 2025)"** (and all later ones as they release). Applying the most recent monthly update resolves every dated item below it in this family.

### 6. Microsoft Visual Studio (Products/Office Tools) - Monthly Security Updates
- **Severity level(s) this family appears under:** Critical/High/Medium
- **Individual findings merged into this family:** 30
- **Affected host(s):** 172.16.16.71
- **Fix / remediation:** Apply the latest cumulative/monthly security update: **"Security Updates for Microsoft Visual Studio Products (May 2026)"** (and all later ones as they release). Applying the most recent monthly update resolves every dated item below it in this family.

### 7. Microsoft .NET Core / ASP.NET Core - Monthly Security Updates (incl. SEoL)
- **Severity level(s) this family appears under:** Critical/High/Medium
- **Individual findings merged into this family:** 28
- **Affected host(s):** 172.16.16.71
- **Fix / remediation:** Apply the latest cumulative/monthly security update: **"Security Update for Microsoft ASP.NET Core (June 2026)"** (and all later ones as they release). Applying the most recent monthly update resolves every dated item below it in this family.

### 8. Microsoft Edge (Chromium)
- **Severity level(s) this family appears under:** Critical/High/Medium/Low
- **Individual findings merged into this family:** 27
- **Affected host(s):** 172.16.16.10
- **Fix / remediation:** Upgrade to the version fixed in: **"Microsoft Edge (Chromium) < 145.0.3800.58 (CVE-2026-0102)"** — the highest fix version found in this family; upgrading to it (or later) resolves every other item below.

### 9. Apache Tomcat 8.5.x branch (incl. SEoL / Spring4Shell)
- **Severity level(s) this family appears under:** Critical/High/Medium/Low
- **Individual findings merged into this family:** 23
- **Affected host(s):** 172.16.16.71
- **Fix / remediation:** **Tomcat 8.5.x branch is End-of-Life.** Latest available 8.5.x patch was 8.5.100, but since the branch itself is EOL, the durable fix is to upgrade to a supported major version (Tomcat 10.1.x / 11.x).

### 10. Oracle MySQL Server (all CPU advisories)
- **Severity level(s) this family appears under:** Critical/High/Medium
- **Individual findings merged into this family:** 21
- **Affected host(s):** 172.16.16.71
- **Fix / remediation:** Upgrade to the version fixed in: **"Oracle MySQL Server 8.0.x < 8.0.46 (April 2026 CPU)"** — the highest fix version found in this family; upgrading to it (or later) resolves every other item below.

### 11. Microsoft SQL Server (incl. OLE DB Driver) - Monthly Security Updates
- **Severity level(s) this family appears under:** Critical/High/Medium
- **Individual findings merged into this family:** 20
- **Affected host(s):** 172.16.16.71
- **Fix / remediation:** Apply the latest cumulative/monthly security update: **"Security Updates for Microsoft SQL Server (May 2026)"** (and all later ones as they release). Applying the most recent monthly update resolves every dated item below it in this family.

### 12. Apache Tomcat 9.0.x branch
- **Severity level(s) this family appears under:** Critical/High
- **Individual findings merged into this family:** 16
- **Affected host(s):** 172.16.16.10
- **Fix / remediation:** Upgrade to the version fixed in: **"Apache Tomcat 9.0.0.M1 < 9.0.118 multiple vulnerabilities"** — the highest fix version found in this family; upgrading to it (or later) resolves every other item below.

### 13. Oracle Java SE (all CPU advisories)
- **Severity level(s) this family appears under:** Critical/High/Medium/Low
- **Individual findings merged into this family:** 12
- **Affected host(s):** 172.16.16.4, 172.16.16.10, 172.16.16.71
- **Fix / remediation:** Update to the latest Oracle Critical Patch Update.

### 14. Oracle MySQL Connectors (ODBC/C++/.NET)
- **Severity level(s) this family appears under:** Critical/High/Medium
- **Individual findings merged into this family:** 11
- **Affected host(s):** 172.16.16.71
- **Fix / remediation:** Update to the latest Oracle Critical Patch Update.

### 15. SSL/TLS Configuration Weaknesses (protocol/cipher/certificate)
- **Severity level(s) this family appears under:** Critical/High/Medium/Low
- **Individual findings merged into this family:** 11
- **Affected host(s):** 172.16.16.4, 172.16.16.10, 172.16.16.18, 172.16.16.20, 172.16.16.38, 172.16.16.71
- **Fix / remediation:** **Configuration/hardening issue — not a version.** Fixed by reconfiguration (disable weak protocol/cipher, enable signing/NLA, replace self-signed/expired cert, etc.), not a patch install.

### 16. Node.js Runtime
- **Severity level(s) this family appears under:** Critical/High
- **Individual findings merged into this family:** 6
- **Affected host(s):** 172.16.16.71
- **Fix / remediation:** Upgrade to the version fixed in: **"Node.js 16.x < 16.20.2 / 18.x < 18.17.1 / 20.x < 20.5.1 Multiple Vulnerabilities (Wednesday August 09 2023 Security Releases)."** — the highest fix version found in this family; upgrading to it (or later) resolves every other item below.

### 17. Node.js Module: axios
- **Severity level(s) this family appears under:** Critical/High
- **Individual findings merged into this family:** 4
- **Affected host(s):** 172.16.16.71
- **Fix / remediation:** Upgrade to the version fixed in: **"Node.js Module axios < 0.32.0 / 1.x < 1.16.0 NO_PROXY Bypass (SSRF)"** — the highest fix version found in this family; upgrading to it (or later) resolves every other item below.

### 18. NFS Share Misconfiguration
- **Severity level(s) this family appears under:** Critical/High/Low
- **Individual findings merged into this family:** 4
- **Affected host(s):** 172.16.16.38
- **Fix / remediation:** **Configuration/hardening issue — not a version.** Fixed by reconfiguration (disable weak protocol/cipher, enable signing/NLA, replace self-signed/expired cert, etc.), not a patch install.

### 19. Apache Log4j 1.x (EOL)
- **Severity level(s) this family appears under:** Critical/High
- **Individual findings merged into this family:** 3
- **Affected host(s):** 172.16.16.71
- **Fix / remediation:** **End-of-Life / unsupported product.** No further vendor patches exist — the only fix is to fully remove/replace the software (it cannot be brought to a 'fixed' version).

### 20. PuTTY
- **Severity level(s) this family appears under:** Critical/High
- **Individual findings merged into this family:** 3
- **Affected host(s):** 172.16.16.4, 172.16.16.71
- **Fix / remediation:** Upgrade to the version fixed in: **"PuTTY < 0.81 Key Recovery Attack Vulnerability"** — the highest fix version found in this family; upgrading to it (or later) resolves every other item below.

### 21. Mozilla Firefox ESR
- **Severity level(s) this family appears under:** Critical/Low
- **Individual findings merged into this family:** 2
- **Affected host(s):** 172.16.16.10
- **Fix / remediation:** Upgrade to the version fixed in: **"Mozilla Firefox ESR < 115.37"** — the highest fix version found in this family; upgrading to it (or later) resolves every other item below.

### 22. WinSCP
- **Severity level(s) this family appears under:** Critical/Medium
- **Individual findings merged into this family:** 2
- **Affected host(s):** 172.16.16.4
- **Fix / remediation:** Upgrade to the version fixed in: **"WinSCP < 6.3.3 Key Recovery Attack Vulnerability"** — the highest fix version found in this family; upgrading to it (or later) resolves every other item below.

### 23. Microsoft Access - Unsupported Version
- **Severity level(s) this family appears under:** Critical
- **Individual findings merged into this family:** 1
- **Affected host(s):** 172.16.16.71
- **Fix / remediation:** **End-of-Life / unsupported product.** No further vendor patches exist — the only fix is to fully remove/replace the software (it cannot be brought to a 'fixed' version).

### 24. Microsoft Message Queuing RCE (QueueJumper)
- **Severity level(s) this family appears under:** Critical
- **Individual findings merged into this family:** 1
- **Affected host(s):** 172.16.16.71
- **Fix / remediation:** Single finding — apply the vendor patch/mitigation referenced in the finding name.

### 25. Microsoft .NET Framework - Unsupported/EOL Version
- **Severity level(s) this family appears under:** Critical
- **Individual findings merged into this family:** 1
- **Affected host(s):** 172.16.16.4, 172.16.16.18, 172.16.16.20
- **Fix / remediation:** **End-of-Life / unsupported product.** No further vendor patches exist — the only fix is to fully remove/replace the software (it cannot be brought to a 'fixed' version).

### 26. AnyDesk
- **Severity level(s) this family appears under:** Critical
- **Individual findings merged into this family:** 1
- **Affected host(s):** 172.16.16.4
- **Fix / remediation:** Upgrade to the version fixed in: **"AnyDesk < 9.0.5 Multiple Vulnerabilities"** — the highest fix version found in this family; upgrading to it (or later) resolves every other item below.


## High Severity Families (13 families, 53 findings)

### 27. 7-Zip
- **Severity level(s) this family appears under:** High/Medium/Low
- **Individual findings merged into this family:** 14
- **Affected host(s):** 172.16.16.4, 172.16.16.10
- **Fix / remediation:** Upgrade to the version fixed in: **"7-Zip >= 9.34 < 26.01 WIM / Ar SYMDEF OOB Read (GHSL-2026-115_GHSL-2026-122)"** — the highest fix version found in this family; upgrading to it (or later) resolves every other item below.

### 28. Microsoft Visual Studio Code - Monthly Security Updates
- **Severity level(s) this family appears under:** High/Medium
- **Individual findings merged into this family:** 12
- **Affected host(s):** 172.16.16.71
- **Fix / remediation:** Apply the latest cumulative/monthly security update: **"Security Update for Microsoft Visual Studio Code (June 2026)"** (and all later ones as they release). Applying the most recent monthly update resolves every dated item below it in this family.

### 29. Notepad++
- **Severity level(s) this family appears under:** High/Medium
- **Individual findings merged into this family:** 7
- **Affected host(s):** 172.16.16.10, 172.16.16.71
- **Fix / remediation:** Upgrade to the version fixed in: **"Notepad++ < 8.9.6.1 Multiple Vulnerabilities"** — the highest fix version found in this family; upgrading to it (or later) resolves every other item below.

### 30. WinRAR / RARLAB WinRAR
- **Severity level(s) this family appears under:** High/Medium
- **Individual findings merged into this family:** 6
- **Affected host(s):** 172.16.16.4, 172.16.16.71
- **Fix / remediation:** Upgrade to the version fixed in: **"RARLAB WinRAR < 7.13 Directory Traversal (CVE-2025-8088)"** — the highest fix version found in this family; upgrading to it (or later) resolves every other item below.

### 31. Oracle MySQL Workbench
- **Severity level(s) this family appears under:** High/Medium
- **Individual findings merged into this family:** 5
- **Affected host(s):** 172.16.16.71
- **Fix / remediation:** Upgrade to the version fixed in: **"Oracle MySQL Workbench < 8.0.36 (January 2024)"** — the highest fix version found in this family; upgrading to it (or later) resolves every other item below.

### 32. Windows Malicious Software Removal Tool
- **Severity level(s) this family appears under:** High/Medium
- **Individual findings merged into this family:** 2
- **Affected host(s):** 172.16.16.10, 172.16.16.71
- **Fix / remediation:** Apply the latest cumulative/monthly security update: **"Security Updates for Windows Malicious Software Removal Tool (January 2023)"** (and all later ones as they release). Applying the most recent monthly update resolves every dated item below it in this family.

### 33. Microsoft Windows SDK
- **Severity level(s) this family appears under:** High
- **Individual findings merged into this family:** 1
- **Affected host(s):** 172.16.16.71
- **Fix / remediation:** Upgrade to the version fixed in: **"Microsoft Windows SDK < 10.0.26100.7463 Inbox COM Objects (Global Memory) RCE (January 2026)"** — the highest fix version found in this family; upgrading to it (or later) resolves every other item below.

### 34. TeamViewer
- **Severity level(s) this family appears under:** High
- **Individual findings merged into this family:** 1
- **Affected host(s):** 172.16.16.4, 172.16.16.71
- **Fix / remediation:** Upgrade to the version fixed in: **"TeamViewer Remote Full Client (Windows) < 11.0.259324 / 12.x < 12.0.259325 / 13.x < 13.2.36227 / 14.x < 14.7.48809 / 15.x < 15.64.5 / 15.65.x < 15.67 Privilege Escalation (TV-2025-1002)"** — the highest fix version found in this family; upgrading to it (or later) resolves every other item below.

### 35. Microsoft Azure Data Studio
- **Severity level(s) this family appears under:** High
- **Individual findings merged into this family:** 1
- **Affected host(s):** 172.16.16.71
- **Fix / remediation:** Upgrade to the version fixed in: **"Microsoft Azure Data Studio < 1.48.0 Elevation of Privilege Vulnerability (CVE-2024-26203)"** — the highest fix version found in this family; upgrading to it (or later) resolves every other item below.

### 36. WinVerifyTrust Signature Validation (CVE-2013-3900)
- **Severity level(s) this family appears under:** High
- **Individual findings merged into this family:** 1
- **Affected host(s):** 172.16.16.4, 172.16.16.10, 172.16.16.18, 172.16.16.20, 172.16.16.71
- **Fix / remediation:** **Configuration/hardening issue — not a version.** Fixed by reconfiguration (disable weak protocol/cipher, enable signing/NLA, replace self-signed/expired cert, etc.), not a patch install.

### 37. Windows Secure Boot Bypass (BootHole)
- **Severity level(s) this family appears under:** High
- **Individual findings merged into this family:** 1
- **Affected host(s):** 172.16.16.71
- **Fix / remediation:** Single finding — apply the vendor patch/mitigation referenced in the finding name.

### 38. Intel Chipset Device Software
- **Severity level(s) this family appears under:** High
- **Individual findings merged into this family:** 1
- **Affected host(s):** 172.16.16.4
- **Fix / remediation:** Upgrade to the version fixed in: **"Intel Chipset Device Software < 10.1.19444.8378 Escalation of Privilege"** — the highest fix version found in this family; upgrading to it (or later) resolves every other item below.

### 39. Insecure Windows Service Permissions
- **Severity level(s) this family appears under:** High
- **Individual findings merged into this family:** 1
- **Affected host(s):** 172.16.16.4
- **Fix / remediation:** **Configuration/hardening issue — not a version.** Fixed by reconfiguration (disable weak protocol/cipher, enable signing/NLA, replace self-signed/expired cert, etc.), not a patch install.


## Medium Severity Families (9 families, 13 findings)

### 40. RDP / Terminal Services Hardening (NLA, Encryption Level, MITM)
- **Severity level(s) this family appears under:** Medium/Low
- **Individual findings merged into this family:** 4
- **Affected host(s):** 172.16.16.4, 172.16.16.18, 172.16.16.20, 172.16.16.71
- **Fix / remediation:** **Configuration/hardening issue — not a version.** Fixed by reconfiguration (disable weak protocol/cipher, enable signing/NLA, replace self-signed/expired cert, etc.), not a patch install.

### 41. Windows Speculative Execution Configuration
- **Severity level(s) this family appears under:** Medium
- **Individual findings merged into this family:** 2
- **Affected host(s):** 172.16.16.4, 172.16.16.10, 172.16.16.18, 172.16.16.20, 172.16.16.71
- **Fix / remediation:** **Configuration/hardening issue — not a version.** Fixed by reconfiguration (disable weak protocol/cipher, enable signing/NLA, replace self-signed/expired cert, etc.), not a patch install.

### 42. SSH Terrapin Prefix Truncation Weakness
- **Severity level(s) this family appears under:** Medium
- **Individual findings merged into this family:** 1
- **Affected host(s):** 172.16.16.38, 172.16.16.71
- **Fix / remediation:** **Configuration/hardening issue — not a version.** Fixed by reconfiguration (disable weak protocol/cipher, enable signing/NLA, replace self-signed/expired cert, etc.), not a patch install.

### 43. SMB Signing Not Required
- **Severity level(s) this family appears under:** Medium
- **Individual findings merged into this family:** 1
- **Affected host(s):** 172.16.16.4, 172.16.16.10, 172.16.16.18, 172.16.16.20, 172.16.16.38, 172.16.16.71
- **Fix / remediation:** **Configuration/hardening issue — not a version.** Fixed by reconfiguration (disable weak protocol/cipher, enable signing/NLA, replace self-signed/expired cert, etc.), not a patch install.

### 44. Web Application Missing Clickjacking Protection (X-Frame-Options)
- **Severity level(s) this family appears under:** Medium
- **Individual findings merged into this family:** 1
- **Affected host(s):** 172.16.16.4, 172.16.16.71
- **Fix / remediation:** **Configuration/hardening issue — not a version.** Fixed by reconfiguration (disable weak protocol/cipher, enable signing/NLA, replace self-signed/expired cert, etc.), not a patch install.

### 45. Curl
- **Severity level(s) this family appears under:** Medium
- **Individual findings merged into this family:** 1
- **Affected host(s):** 172.16.16.71
- **Fix / remediation:** Upgrade to the version fixed in: **"Curl Use-After-Free < 7.87 (CVE-2022-43552)"** — the highest fix version found in this family; upgrading to it (or later) resolves every other item below.

### 46. FileZilla
- **Severity level(s) this family appears under:** Medium
- **Individual findings merged into this family:** 1
- **Affected host(s):** 172.16.16.71
- **Fix / remediation:** Upgrade to the version fixed in: **"FileZilla < 3.67.0 Insecure Key Recovery Vulnerability (CVE-2024-31497)"** — the highest fix version found in this family; upgrading to it (or later) resolves every other item below.

### 47. Node.js Module: node-tar
- **Severity level(s) this family appears under:** Medium
- **Individual findings merged into this family:** 1
- **Affected host(s):** 172.16.16.71
- **Fix / remediation:** Upgrade to the version fixed in: **"Node.js Module node-tar < 6.2.1 DoS"** — the highest fix version found in this family; upgrading to it (or later) resolves every other item below.

### 48. Windows LM / NTLMv1 Authentication Enabled
- **Severity level(s) this family appears under:** Medium
- **Individual findings merged into this family:** 1
- **Affected host(s):** 172.16.16.18
- **Fix / remediation:** **Configuration/hardening issue — not a version.** Fixed by reconfiguration (disable weak protocol/cipher, enable signing/NLA, replace self-signed/expired cert, etc.), not a patch install.


## Low Severity Families (1 families, 1 findings)

### 49. ICMP Timestamp Request Remote Date Disclosure
- **Severity level(s) this family appears under:** Low
- **Individual findings merged into this family:** 1
- **Affected host(s):** 172.16.16.4, 172.16.16.10, 172.16.16.18, 172.16.16.20, 172.16.16.38, 172.16.16.71
- **Fix / remediation:** **Configuration/hardening issue — not a version.** Fixed by reconfiguration (disable weak protocol/cipher, enable signing/NLA, replace self-signed/expired cert, etc.), not a patch install.
