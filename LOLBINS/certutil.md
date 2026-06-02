# Certutil (certutil.exe)

## 1. What is it?
Certutil is a Windows command-line utility used for certificate management and Public Key Infrastructure (PKI) administration.

## 2. Legitimate Use
- Certificate Management
- Certificate Validation
- PKI Administration
- Certificate Store Management

## 3. Why Attackers Abuse It
Certutil can download files, encode/decode data, and transfer payloads, making it useful for malware staging and payload delivery.

## 4. Common Attack Techniques
- Payload Downloading
- File Transfer
- Base64 Encoding/Decoding
- Defense Evasion
- Payload Staging

## 5. MITRE ATT&CK Mapping

| Technique ID | Technique |
|-------------|-----------|
| T1105 | Ingress Tool Transfer |
| T1140 | Deobfuscate/Decode Files |
| T1218 | Signed Binary Proxy Execution |

## 6. Detection Opportunities
- Sysmon Event ID 1
- Network Connections
- Command Line Analysis
- File Creation Monitoring

## 7. Red Flags
- `-urlcache` parameter
- `-decode` parameter
- Internet downloads
- Executables written to Temp directories
- Base64 decoding operations

## 8. Blue Team Takeaway
Certutil is one of the most abused LOLBins for downloading, decoding, and staging malware payloads during attacks.
