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
What is DNS?

DNS (Domain Name System) is a globally distributed naming system that translates domain names into IP addresses. Humans prefer easy-to-remember names such as google.com, while computers communicate using numerical IP addresses. DNS acts as the bridge between these two worlds and allows users to access websites without memorizing complex IP addresses.

Without DNS, every internet service would require users to remember numerical addresses, making the internet difficult to use and manage. DNS is often referred to as the "Phonebook of the Internet" because it maps domain names to the servers hosting websites and applications.

Why DNS is Important

DNS is one of the most critical components of the Internet. Every website visit, email delivery, cloud application login, and API request relies on DNS resolution. If DNS becomes unavailable, users may not be able to access websites, send emails, or connect to online services.

Organizations use DNS not only for website hosting but also for load balancing, service discovery, email routing, and security controls.
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
What is Email Security?

Email Security refers to the collection of technologies, policies, and controls used to protect email communications from cyber threats. Since email is one of the most commonly used communication methods in organizations, it is also one of the most targeted attack vectors.

Modern email security protects organizations from phishing attacks, spoofing, malware delivery, ransomware campaigns, business email compromise (BEC), and unauthorized access to email accounts.

Why Email Security Matters

Cybercriminals frequently exploit email because employees trust messages that appear to come from colleagues, customers, or executives. A single successful phishing email can result in credential theft, financial fraud, or ransomware infections.

To address these threats, organizations implement SPF, DKIM, and DMARC to verify sender authenticity and improve trust in email communications.
# 🛡️ SPF (Sender Policy Framework)

## Purpose

SPF identifies which mail servers are authorized to send emails on behalf of a domain.
What is SPF?

SPF is an email authentication protocol that allows domain owners to specify which mail servers are authorized to send emails on behalf of their domain. The SPF policy is published as a TXT record in DNS and checked by receiving mail servers during email delivery.

When an email arrives, the receiving server compares the sender's IP address against the SPF record. If the sending server is not authorized, the email may be rejected or flagged as suspicious.

Why SPF is Important

SPF helps prevent email spoofing attacks where attackers impersonate trusted domains. Without SPF, anyone could attempt to send emails claiming to be from your company.

Although SPF significantly improves email security, it should always be used alongside DKIM and DMARC for complete protection.
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
What is DKIM?

DKIM is an email authentication mechanism that digitally signs outgoing emails using cryptographic keys. The signature allows recipients to verify that the message was sent by an authorized server and has not been modified during transmission.

A private key signs the message before sending, while a public key stored in DNS allows the recipient to verify the signature.

Why DKIM is Important

DKIM ensures message integrity and authenticity. If an attacker modifies the email content during transit, the DKIM validation process will fail, alerting the recipient server that the message may have been tampered with.

Organizations use DKIM to improve trust, prevent email manipulation, and increase email delivery success rates.
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
What is DMARC?

DMARC is an email authentication and policy framework built on top of SPF and DKIM. It tells receiving mail servers what action to take when an email fails authentication checks.

In addition to enforcing policies, DMARC provides reporting capabilities that allow organizations to monitor unauthorized use of their domains.

Why DMARC is Important

DMARC helps organizations protect their domains from phishing, spoofing, and business email compromise attacks. It provides visibility into who is sending emails on behalf of the organization and helps prevent malicious emails from reaching end users.

Large organizations such as banks, government agencies, and cloud providers rely heavily on DMARC to protect their brand reputation.
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
What is Apache?

Apache HTTP Server is one of the world's most widely used open-source web servers. It is responsible for receiving requests from web browsers and serving web content such as HTML pages, images, CSS files, JavaScript files, and backend application responses.

Apache has been a foundational technology of the Internet for decades and continues to power millions of websites globally.

Why Apache is Important

Apache allows organizations to host websites, applications, APIs, and internal services. It supports extensive customization through modules and integrates with technologies such as PHP, Python, SSL/TLS, reverse proxies, and Web Application Firewalls.

Its flexibility and reliability make it a preferred choice for both small businesses and large enterprises.
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
What is Website Hosting?

Website hosting is the process of making a website available on the Internet through a publicly accessible server. Hosting involves storing website files, configuring web servers, managing domain names, and securing communications using SSL/TLS certificates.

A hosted website becomes accessible to users worldwide through a domain name.

Why Website Hosting Matters

Every website requires infrastructure to store and deliver content. Hosting ensures that users can access web applications, e-commerce stores, company websites, and cloud-based services reliably and securely.

Proper hosting also improves website performance, scalability, and security.
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
What is Microsoft Entra ID?

Microsoft Entra ID (formerly Azure Active Directory) is Microsoft's cloud-based Identity and Access Management (IAM) platform. It manages user identities, authentication processes, application access, device management, and security policies across cloud and hybrid environments.

Entra ID acts as the central identity provider for Microsoft 365 and thousands of third-party applications.

Why Entra ID is Important

Organizations use Entra ID to simplify access management while improving security. Instead of maintaining separate credentials for every application, users can authenticate once and securely access multiple services through Single Sign-On (SSO).

Entra ID also provides advanced security features such as Multi-Factor Authentication (MFA), Conditional Access, Identity Protection, and Zero Trust controls.
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
What is SSO?

Single Sign-On (SSO) allows users to authenticate once and gain access to multiple applications without repeatedly entering credentials. The identity provider verifies the user's identity and issues trusted authentication tokens to connected applications.

Why SSO is Important

SSO improves user experience, reduces password fatigue, and decreases the number of credentials employees need to manage. It also strengthens security by centralizing authentication and enforcing consistent security policies.
### Examples

* Outlook
* Teams
* SharePoint
* OneDrive
* Third-Party SaaS Applications

---

## Multi-Factor Authentication (MFA)
What is MFA?

Multi-Factor Authentication requires users to provide multiple forms of verification before gaining access to a system. These factors typically include something the user knows (password), something they have (mobile device), or something they are (biometric data).

Why MFA is Important

Even if an attacker steals a password, MFA provides an additional security layer that prevents unauthorized access. Microsoft estimates that MFA can block the vast majority of automated account compromise attempts.
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
What is Microsoft 365 Email?

Microsoft 365 Email, powered by Exchange Online, is Microsoft's cloud-based email platform that provides secure communication, calendaring, collaboration, and enterprise-grade security controls.

It integrates closely with Microsoft Entra ID for identity management and authentication.

Why Organizations Use It

Microsoft 365 provides highly available, scalable, and secure email services without requiring organizations to maintain on-premises mail servers. Features such as spam filtering, malware protection, SPF, DKIM, DMARC, and advanced threat protection help secure communications at enterprise scale.
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
