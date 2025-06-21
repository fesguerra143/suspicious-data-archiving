

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


## 🛡️ Incident Report: Suspicious Data Archiving on Corporate Device
## 1. Summary
Title: Suspected Data Exfiltration Attempt by PIP'd Employee <br />
Target: John Doe Smith (Employee under Performance Improvement Plan)<br />
Device Investigated: vmlab-fe<br />
Investigator: Fe Esguerra<br />
Date: June 21, 2025<br />
Tool Used: Microsoft Defender for Endpoint (MDE)<br />

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

- Queried for any signs of exfiltration:

```kql
let VMName = "vmlab-fe";
let specificTime = datetime(2025-06-21T04:53:44.4622833Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType

```

![DataCollection5-1](https://github.com/user-attachments/assets/87993368-76c8-4c55-9742-05ca40ecbb5a)
![DataCollection6](https://github.com/user-attachments/assets/4f280373-75d7-433a-902e-7dba51ee00b6)

Key Finding:
No evidence of network-based exfiltration was detected during this timeframe.



## 6. Response
### Actions Taken:

- The device vmlab-fe was immediately isolated from the network to prevent potential exfiltration or lateral movement.
- Full details were relayed to the employee's manager and internal HR/security teams.
- Awaiting next steps for HR or legal involvement.

## 7. MITRE ATT&CK Mapping

- T1059.001 – Command and Scripting Interpreter: PowerShell  
- T1560.001 – Archive Collected Data: Archive via Utility  
- T1005 – Data from Local System  
- T1074.001 – Local Data Staging  
- T1204.002 – User Execution: Malicious File (Potential)  
- T1083 – File and Directory Discovery (Inferred)  
- T1036 – Masquerading (Potential)


## 8. Lessons Learned / Improvement: 

Review PowerShell execution policies and endpoint monitoring rules

## 9. Final Status

Threat Contained: ✅

Device Isolated: ✅

✅ What We Did Well:
Time-based pivoting effectively correlated file, process, and network activity.

Rapid isolation of the host prevented possible data loss.

Used threat-informed hypothesis to guide focused hunting.

🛠️ What Could Be Improved:
Proactive Controls:

Implement application control to block unauthorized installers like 7-Zip.

Restrict PowerShell use via Group Policy or WDAC.

Enable PowerShell logging for better audit trails.

Enhanced Detection:

Develop detection rules for archive tool usage and scripting patterns.

Monitor .zip file creation in unusual folders or by non-standard processes.

Automation:

Build KQL automation to alert when archiving tools and data directories interact.




