# Infrastructure Engineering Fundamentals

### DNS, Email Security (SPF, DKIM, DMARC), Apache Web Hosting, and Microsoft Entra ID

![Infrastructure](https://img.shields.io/badge/Infrastructure-Engineering-blue)
![DNS](https://img.shields.io/badge/DNS-Networking-green)
![Email Security](https://img.shields.io/badge/Email-Security-orange)
![Apache](https://img.shields.io/badge/Apache-WebServer-red)
![Microsoft Entra ID](https://img.shields.io/badge/Microsoft-Entra_ID-purple)

---

# 📖 Overview

This repository provides a comprehensive beginner-to-advanced guide to modern Infrastructure Engineering concepts used in enterprise environments.

The objective is to explain how websites, email systems, identity management, and security controls work together to form a secure and scalable IT infrastructure.

The topics covered include:

* Domain Name System (DNS)
* Email Authentication & Security

  * SPF
  * DKIM
  * DMARC
* Apache Web Server
* Website Hosting Architecture
* Microsoft Entra ID (Azure AD)
* Microsoft 365 Email Infrastructure
* Enterprise Identity and Access Management
* Infrastructure Security Best Practices

---

# 🏗️ Infrastructure Architecture

```text
Internet
   │
   ▼
Domain Name System (DNS)
   │
   ├── Website Hosting
   │      └── Apache Web Server
   │
   ├── Email Services
   │      ├── SPF
   │      ├── DKIM
   │      └── DMARC
   │
   └── Identity Management
          └── Microsoft Entra ID
```

---

# 🎯 Learning Objectives

After studying this repository, you will understand:

* How DNS works behind the scenes
* How websites are hosted and delivered
* How email authentication prevents spoofing
* How Microsoft 365 email infrastructure operates
* How Microsoft Entra ID manages identities
* How modern organizations secure digital infrastructure
* Enterprise-grade security best practices

---

# 🌐 Domain Name System (DNS)

## What is DNS?

DNS (Domain Name System) is the Internet's directory service that translates human-readable domain names into machine-readable IP addresses.

### Example

```text
google.com
        ↓
142.250.182.46
```

Without DNS, users would need to remember IP addresses for every website.

---

## DNS Resolution Process

```text
User Browser
      │
      ▼
DNS Resolver
      │
      ▼
Root DNS Server
      │
      ▼
Top-Level Domain (TLD) Server
      │
      ▼
Authoritative DNS Server
      │
      ▼
IP Address Returned
```

---

## Common DNS Records

| Record | Purpose                              |
| ------ | ------------------------------------ |
| A      | Maps domain to IPv4 address          |
| AAAA   | Maps domain to IPv6 address          |
| CNAME  | Creates aliases                      |
| MX     | Defines mail servers                 |
| TXT    | Stores SPF, DKIM, DMARC information  |
| NS     | Specifies authoritative name servers |
| PTR    | Reverse DNS lookup                   |

---

## DNS Security Risks

### DNS Spoofing

Attackers provide fake DNS responses.

### DNS Hijacking

Unauthorized modification of DNS records.

### DNS Tunneling

Data exfiltration through DNS queries.

### DDoS Attacks

Overwhelming DNS infrastructure with traffic.

---

# 📧 Email Security

Email remains one of the most targeted attack vectors in cybersecurity.

Common attacks include:

* Phishing
* Spear Phishing
* Business Email Compromise (BEC)
* Email Spoofing
* Domain Impersonation

To mitigate these risks, organizations implement:

```text
SPF
 +
DKIM
 +
DMARC
```

---

# 🛡️ SPF (Sender Policy Framework)

## Purpose

SPF identifies which mail servers are authorized to send emails on behalf of a domain.

### Example SPF Record

```dns
v=spf1 include:spf.protection.outlook.com -all
```

---

## SPF Workflow

```text
Incoming Email
       │
       ▼
Check SPF Record
       │
       ▼
Verify Sender IP
       │
       ▼
Pass / Fail
```

---

## Benefits

* Reduces email spoofing
* Protects domain reputation
* Improves email deliverability

---

## Limitations

SPF does not:

* Verify message integrity
* Protect forwarded emails
* Validate email content

---

# 🔐 DKIM (DomainKeys Identified Mail)

## Purpose

DKIM ensures that an email has not been altered during transmission.

---

## How DKIM Works

```text
Mail Server
      │
      ▼
Sign Email Using Private Key
      │
      ▼
Send Email
      │
      ▼
Recipient Retrieves Public Key
      │
      ▼
Verify Signature
      │
      ▼
Pass / Fail
```

---

## Example DKIM Record

```dns
selector1._domainkey.company.com

v=DKIM1;
k=rsa;
p=PUBLIC_KEY
```

---

## Benefits

* Message integrity verification
* Reduced phishing attacks
* Improved trustworthiness

---

# 🚨 DMARC (Domain-based Message Authentication, Reporting and Conformance)

## Purpose

DMARC defines how receiving mail servers should handle emails that fail SPF or DKIM checks.

---

## Example DMARC Record

```dns
v=DMARC1;
p=reject;
rua=mailto:dmarc@company.com
```

---

## DMARC Policies

### Monitor

```dns
p=none
```

Collect reports only.

### Quarantine

```dns
p=quarantine
```

Move suspicious emails to spam.

### Reject

```dns
p=reject
```

Block malicious emails completely.

---

## DMARC Workflow

```text
Email Received
      │
      ▼
SPF Validation
      │
      ▼
DKIM Validation
      │
      ▼
DMARC Policy Evaluation
      │
      ▼
Deliver / Quarantine / Reject
```

---

# 🌍 Apache Web Server

## What is Apache?

Apache HTTP Server is one of the world's most widely used open-source web servers.

It is responsible for:

* Serving web pages
* Processing HTTP/HTTPS requests
* Hosting websites and web applications

---

## Request Flow

```text
Browser
   │
   ▼
DNS
   │
   ▼
Apache Web Server
   │
   ▼
Website Files
   │
   ▼
HTTP Response
```

---

## Core Apache Components

### Apache Service

```bash
apache2
```

### Configuration Files

```bash
/etc/apache2/apache2.conf
```

### Website Root

```bash
/var/www/html
```

### Virtual Hosts

Used to host multiple websites on one server.

---

## Common Apache Modules

| Module       | Purpose                  |
| ------------ | ------------------------ |
| mod_ssl      | SSL/TLS Support          |
| mod_security | Web Application Firewall |
| mod_rewrite  | URL Rewriting            |
| mod_headers  | Security Headers         |
| mod_proxy    | Reverse Proxy            |

---

## Security Best Practices

* Enable HTTPS
* Disable directory listing
* Configure security headers
* Use ModSecurity WAF
* Regular patch management
* Restrict file permissions

---

# 🌐 Website Hosting on Apache

## Hosting Requirements

```text
Domain Name
DNS Configuration
Public Server
Operating System
Apache Web Server
Website Files
SSL Certificate
```

---

## Website Deployment Workflow

```text
Purchase Domain
        │
        ▼
Configure DNS
        │
        ▼
Provision Server
        │
        ▼
Install Apache
        │
        ▼
Upload Website Files
        │
        ▼
Configure Virtual Host
        │
        ▼
Enable SSL/TLS
        │
        ▼
Website Live
```

---

# ☁️ Microsoft Entra ID

## What is Microsoft Entra ID?

Microsoft Entra ID is Microsoft's cloud Identity and Access Management (IAM) platform.

Formerly known as:

```text
Azure Active Directory (Azure AD)
```

---

## Core Functions

Microsoft Entra ID manages:

* Users
* Groups
* Devices
* Applications
* Authentication
* Authorization

---

## Authentication vs Authorization

### Authentication

```text
Who are you?
```

Example:

```text
Username + Password
```

---

### Authorization

```text
What are you allowed to access?
```

Example:

```text
Admin
User
Guest
```

---

# Key Features

## Single Sign-On (SSO)

One login grants access to multiple applications.

### Examples

* Outlook
* Teams
* SharePoint
* OneDrive
* Third-Party SaaS Applications

---

## Multi-Factor Authentication (MFA)

Requires:

```text
Password
+
Authenticator App
```

---

## Conditional Access

Examples:

* Require MFA outside office
* Block risky countries
* Restrict unmanaged devices

---

## Identity Protection

Detects:

* Impossible travel
* Password spraying
* Credential theft attempts
* Risky sign-ins

---

# 📨 Microsoft 365 Email Setup

## Step 1: Purchase Domain

```text
company.com
```

---

## Step 2: Add Domain to Microsoft 365

Verify ownership using TXT records.

---

## Step 3: Configure DNS

Required records:

* TXT
* MX
* CNAME
* SPF
* DKIM
* DMARC

---

## Step 4: Create Users

```text
john@company.com
alice@company.com
```

---

## Step 5: Configure Email Security

### SPF

```dns
v=spf1 include:spf.protection.outlook.com -all
```

### DKIM

Enabled via Microsoft 365 Admin Center.

### DMARC

```dns
v=DMARC1;
p=reject;
rua=mailto:dmarc@company.com
```

---

# 🔒 Enterprise Security Best Practices

## DNS Security

* DNSSEC
* Secure DNS Providers
* DNS Monitoring

## Email Security

* SPF
* DKIM
* DMARC
* Anti-Phishing Policies

## Web Security

* HTTPS
* WAF
* Security Headers
* Patch Management

## Identity Security

* MFA Everywhere
* Conditional Access
* Least Privilege Access
* Privileged Identity Management (PIM)

---

# 📚 Technologies Covered

* DNS
* Email Security
* SPF
* DKIM
* DMARC
* Apache HTTP Server
* Linux Web Hosting
* SSL/TLS
* Microsoft 365
* Microsoft Entra ID
* Identity and Access Management
* Enterprise Infrastructure Security

---

# 🎓 Target Audience

This repository is designed for:

* Cybersecurity Students
* SOC Analysts
* Blue Team Engineers
* System Administrators
* Cloud Engineers
* Infrastructure Engineers
* Microsoft 365 Administrators
* Security Researchers
* IT Professionals

---

# 🚀 Conclusion

Modern enterprise infrastructure relies on multiple interconnected technologies. DNS resolves domains, Apache hosts websites, Microsoft Entra ID manages identities, and SPF/DKIM/DMARC secure email communications.

Understanding these technologies provides a strong foundation for careers in:

* Infrastructure Engineering
* Cybersecurity
* Cloud Security
* System Administration
* Identity and Access Management
* Network Security
* Microsoft 365 Administration

---

## ⭐ If you found this repository useful, consider starring it and sharing it with other cybersecurity and infrastructure engineering learners.
