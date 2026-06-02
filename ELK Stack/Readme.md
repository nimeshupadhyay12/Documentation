# Elastic Security Architecture

```text
                                        ┌─────────────────────────────┐
                                        │         SOC Analyst         │
                                        │                             │
                                        │ • Threat Hunting            │
                                        │ • Alert Investigation       │
                                        │ • Incident Response         │
                                        │ • Dashboard Monitoring      │
                                        └──────────────┬──────────────┘
                                                       │
                                                       ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                                 KIBANA                                     │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  Security App        Fleet          Dashboards        Discover             │
│  Detection Rules     Cases          Visualizations    Dev Tools            │
│  Timeline            ML Jobs        Reporting         Alerts               │
│                                                                            │
└───────────────────────────────┬────────────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                            ELASTICSEARCH                                  │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  Data Storage                                                            │
│  Search Engine                                                           │
│  Analytics Engine                                                        │
│  Correlation Engine                                                      │
│  SIEM Backend                                                            │
│                                                                            │
│  Stores:                                                                 │
│  • Process Events                                                        │
│  • Registry Events                                                       │
│  • File Events                                                           │
│  • Network Events                                                        │
│  • Sysmon Logs                                                           │
│  • Windows Event Logs                                                    │
│  • Cloud Logs                                                            │
│  • Firewall Logs                                                         │
│                                                                            │
└───────────────────────────────┬────────────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                              FLEET SERVER                                │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  Agent Enrollment                                                        │
│  Agent Policy Management                                                 │
│  Configuration Distribution                                              │
│  Agent Health Monitoring                                                 │
│  Remote Response Actions                                                 │
│                                                                            │
│  Functions:                                                              │
│  • Register Elastic Agents                                               │
│  • Push Security Policies                                                │
│  • Upgrade Agents                                                        │
│  • Endpoint Isolation Commands                                           │
│  • Collect Investigation Artifacts                                       │
│                                                                            │
└─────────────┬──────────────────┬──────────────────┬───────────────────────┘
              │                  │                  │
              ▼                  ▼                  ▼

┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ Elastic Agent   │  │ Elastic Agent   │  │ Elastic Agent   │
│ Windows Host    │  │ Linux Host      │  │ Server Host     │
└────────┬────────┘  └────────┬────────┘  └────────┬────────┘
         │                    │                    │
         ▼                    ▼                    ▼

┌────────────────────────────────────────────────────────────────────────────┐
│                            ELASTIC DEFEND                                │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  Endpoint Detection & Response (EDR)                                      │
│  Next Generation Antivirus (NGAV)                                         │
│                                                                            │
│  Telemetry Collection:                                                    │
│  • Process Creation                                                       │
│  • DLL Loads                                                              │
│  • Registry Modifications                                                 │
│  • File Activity                                                          │
│  • Network Connections                                                    │
│  • Service Creation                                                       │
│  • Driver Loads                                                           │
│                                                                            │
│  Security Controls:                                                       │
│  • Malware Prevention                                                     │
│  • Ransomware Prevention                                                  │
│  • Memory Threat Protection                                               │
│  • Credential Theft Detection                                             │
│  • Behavioral Detection                                                   │
│  • Exploit Prevention                                                     │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```



----------------------------------------------------------------------------------------------------------------------------------------------------



```text
Attacker Executes Malware
            │
            ▼
    Elastic Defend
    Detects Activity
            │
            ▼
      Elastic Agent
    Collects Telemetry
            │
            ▼
      Fleet Server
  Applies Security Policy
            │
            ▼
     Elasticsearch
      Stores Events
            │
            ▼
         Kibana
      Generates Alert
            │
            ▼
       SOC Analyst
      Investigates
            │
            ▼
      Response Action
            │
            ▼
   Host Isolation / Kill Process
```

-------------------------------------------------------------------------------------------------------------------------------------------------------


# Elastic Defend

## 1. What is it?
Elastic Defend is Elastic's Endpoint Detection and Response (EDR) and Next-Generation Antivirus (NGAV) solution that provides endpoint visibility, threat detection, prevention, and response capabilities.

## 2. Primary Function
Monitor endpoint activity, detect malicious behavior, and protect systems against malware, ransomware, exploits, and credential theft.

## 3. Key Capabilities
- Malware Prevention
- Ransomware Protection
- Behavioral Detection
- Memory Threat Detection
- Host Isolation
- Endpoint Telemetry Collection

## 4. How It Works

Endpoint Activity
      ↓
Elastic Defend
      ↓
Threat Detection
      ↓
Elastic Agent
      ↓
Alert Generation

## 5. Data Processed
- Process Events
- File Events
- Registry Events
- Network Connections
- DLL Loads
- Service Activity

## 6. Blue Team Usage
- Threat Hunting
- Incident Response
- Malware Investigation
- Endpoint Monitoring
- Detection Validation

## 7. Common Investigations
- PowerShell Abuse
- Process Injection
- Ransomware Activity
- Credential Dumping
- Persistence Mechanisms

## 8. Advantages
- Built-in EDR
- Behavioral Analytics
- MITRE ATT&CK Mapping
- Centralized Management

## 9. Limitations
- Requires Elastic Agent
- Policy tuning required for optimal detections

## 10. Key Takeaway
Elastic Defend is the endpoint security component of Elastic Security, providing endpoint visibility, threat detection, prevention, and response capabilities.

------------------------------------------------------------------------------------------------------------------------------------------------------------

# Elastic Agent

## 1. What is it?
Elastic Agent is a unified endpoint agent used to collect logs, metrics, security events, and endpoint telemetry.

## 2. Primary Function
Collect and forward data from endpoints to the Elastic Stack.

## 3. Key Capabilities
- Log Collection
- Endpoint Telemetry
- Metrics Collection
- Security Monitoring
- Integration Management

## 4. How It Works

Endpoint
      ↓
Elastic Agent
      ↓
Fleet Server
      ↓
Elasticsearch

## 5. Data Processed
- Windows Logs
- Sysmon Logs
- Linux Logs
- Process Events
- Network Events
- System Metrics

## 6. Blue Team Usage
- Endpoint Monitoring
- Log Collection
- Security Visibility
- Threat Hunting Support

## 7. Common Investigations
- Process Execution Analysis
- User Activity Review
- Network Connection Analysis
- Host-Based Threat Hunting

## 8. Advantages
- Single Unified Agent
- Centralized Management
- Supports Multiple Integrations
- Lightweight Deployment

## 9. Limitations
- Requires Fleet for centralized management
- Endpoint resource consumption varies by integrations

## 10. Key Takeaway
Elastic Agent acts as the data collection layer of the Elastic ecosystem and serves as the primary source of endpoint telemetry.

------------------------------------------------------------------------------------------------------------------------------------------------------------


# Fleet Server

## 1. What is it?
Fleet Server is the centralized management component responsible for managing Elastic Agents.

## 2. Primary Function
Control, configure, monitor, and update Elastic Agents across the environment.

## 3. Key Capabilities
- Agent Enrollment
- Policy Management
- Configuration Distribution
- Agent Health Monitoring
- Remote Actions

## 4. How It Works

Fleet Policies
       ↓
Fleet Server
       ↓
Elastic Agents
       ↓
Endpoint Systems

## 5. Data Processed
- Agent Status
- Agent Policies
- Enrollment Information
- Configuration Updates
- Response Actions

## 6. Blue Team Usage
- Agent Deployment
- Policy Management
- Fleet Monitoring
- Endpoint Administration

## 7. Common Investigations
- Offline Agents
- Policy Misconfigurations
- Agent Health Issues
- Endpoint Coverage Gaps

## 8. Advantages
- Centralized Management
- Scalable
- Automated Policy Distribution
- Simplified Operations

## 9. Limitations
- Additional Infrastructure Component
- Fleet Server Availability Impacts Management

## 10. Key Takeaway
Fleet Server provides centralized control of Elastic Agents and serves as the management layer of the Elastic Security architecture.


------------------------------------------------------------------------------------------------------------------------------------------------------------


# Elasticsearch

## 1. What is it?
Elasticsearch is a distributed search, storage, and analytics engine that acts as the core backend of the Elastic Stack.

## 2. Primary Function
Store, index, search, correlate, and analyze security telemetry.

## 3. Key Capabilities
- Data Storage
- Full-Text Search
- Correlation
- Analytics
- Detection Support

## 4. How It Works

Data Sources
      ↓
Elasticsearch
      ↓
Indexing
      ↓
Search & Analytics
      ↓
Results

## 5. Data Processed
- Endpoint Telemetry
- Security Alerts
- Windows Logs
- Sysmon Logs
- Network Logs
- Cloud Logs

## 6. Blue Team Usage
- Threat Hunting
- IOC Searches
- Alert Correlation
- Detection Engineering
- Incident Investigation

## 7. Common Investigations
- Malware Activity
- Lateral Movement
- Suspicious Authentication
- Persistence Detection
- Data Exfiltration

## 8. Advantages
- Fast Search Performance
- Scalable Architecture
- Near Real-Time Analytics
- Large Data Handling

## 9. Limitations
- Requires Proper Sizing
- Cluster Management Complexity

## 10. Key Takeaway
Elasticsearch is the central storage and analytics engine that powers all searches, detections, and investigations within the Elastic ecosystem.

------------------------------------------------------------------------------------------------------------------------------------------------------------

# Kibana

## 1. What is it?
Kibana is the web-based interface used to interact with Elasticsearch and the Elastic Security platform.

## 2. Primary Function
Provide visualization, threat hunting, investigation, and management capabilities.

## 3. Key Capabilities
- Security Operations
- Fleet Management
- Dashboards
- Threat Hunting
- Incident Management

## 4. How It Works

Elasticsearch
      ↓
Kibana
      ↓
Searches
Dashboards
Alerts
Investigations

## 5. Data Processed
- Alerts
- Security Events
- Dashboards
- Cases
- Detection Rules
- Threat Intelligence

## 6. Blue Team Usage
- Alert Triage
- Threat Hunting
- Incident Response
- Detection Management
- Reporting

## 7. Common Investigations
- Suspicious Processes
- Malicious Network Activity
- User Authentication Events
- Endpoint Compromise
- MITRE ATT&CK Analysis

## 8. Advantages
- User-Friendly Interface
- Powerful Search Capabilities
- Rich Visualizations
- Integrated Security Operations

## 9. Limitations
- Depends on Elasticsearch Availability
- Large Datasets May Require Optimization

## 10. Key Takeaway
Kibana is the operational interface of the Elastic Security platform, allowing analysts to search, investigate, visualize, and respond to security events.

------------------------------------------------------------------------------------------------------------------------------------------------------------


Elastic Defend
      ↓
Detects & Prevents Threats

Elastic Agent
      ↓
Collects Telemetry

Fleet Server
      ↓
Manages Agents & Policies

Elasticsearch
      ↓
Stores & Analyzes Data

Kibana
      ↓
Visualizes & Investigates Data
