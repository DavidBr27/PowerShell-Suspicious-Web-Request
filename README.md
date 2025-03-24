# 🚨 **Threat Detection: PowerShell Suspicious Web Request** 🚨

![image](https://github.com/user-attachments/assets/c0ab8d18-fc8d-4bbe-a8e7-88b93e76a48b)


## 🛡️ **Overview**

This alert helps identify potential malicious activity where attackers use **PowerShell** to download external payloads. Common techniques involve `Invoke-WebRequest` to:

- 📥 Download files or scripts from external servers  
- 🚀 Execute them immediately, bypassing traditional defenses  
- 📡 Communicate with Command-and-Control (C2) infrastructure  

Detecting such behavior is critical to identifying and disrupting an ongoing attack!

![image](https://github.com/user-attachments/assets/c7e2f0a6-9e45-4776-9e85-2ce2cb674e6c)


---

## 🔍 **Detection Pipeline**

1. 🖥️ Logs are collected via **Microsoft Defender for Endpoint** (`DeviceProcessEvents`).  
2. 📊 Forwarded to **Log Analytics Workspace** connected with **Microsoft Sentinel**.  
3. 🛎️ **Sentinel Alert Rule** is configured to trigger on suspicious PowerShell usage.

---

## 🔧 **Step-by-Step: Creating the Alert Rule**

### 1️⃣ **Inspect Logs in Defender for Endpoint**

1. Navigate to Microsoft 365 Security Portal → Advanced Hunting  
2. Use the following KQL queries:

```kql
DeviceFileEvents
| top 20 by Timestamp desc
```
```kql
DeviceNetworkEvents
| top 20 by Timestamp desc
```
```kql
DeviceProcessEvents
| top 20 by Timestamp desc
```

3. Locate suspicious activity, e.g., `powershell.exe` executing `Invoke-WebRequest`.

4. Refine query for target device:

```kql
let TargetDevice = "windows-target-1";
DeviceProcessEvents
| where DeviceName == TargetDevice
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "Invoke-WebRequest"
```

![Screenshot](https://github.com/user-attachments/assets/418f503e-ebab-4cb4-9541-8c1c30ccc56a)

5. Confirm detection of known payloads:

```kql
let TargetHostname = "windows-target-1";
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| summarize Count = count() by AccountName, DeviceName, FileName, ProcessCommandLine
```

![Screenshot](https://github.com/user-attachments/assets/9520d3df-b646-4ce6-a72e-52e1eaedc3f4)

---

### 2️⃣ **Create Sentinel Alert Rule**

1. Open **Microsoft Sentinel** → *Analytics* → *Scheduled Query Rule* → **Create Alert Rule**

2. Input the following:

- **Rule Name**: PowerShell Suspicious Download Detected  
- **Description**: Detects use of PowerShell to download remote files  
- **Query**:

```kql
let TargetDevice = "windows-target-1";
DeviceProcessEvents
| where DeviceName == TargetDevice
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "Invoke-WebRequest"
```

- **Frequency**: Every 4 hours  
- **Lookup Period**: 24 hours  
- **Incident Behavior**: Group alerts into one incident per day  

3. Set **Entity Mappings**:
   - **Account** → `AccountName`
   - **Host** → `DeviceName`
   - **Process** → `ProcessCommandLine`

4. Enable **MITRE ATT&CK mappings** if applicable.

5. Save and activate! 🚀

![Screenshot](https://github.com/user-attachments/assets/2cb640e9-9471-4439-a545-e3395bd2fd16)

---

## 🛠️ **Work the Incident**
Follow the **NIST 800-161: Incident Response Lifecycle**:

### 1️⃣ **Preparation** 📂
- Define roles, responsibilities, and procedures 🗂️.
- Ensure tools, systems, and training are in place 🛠️.

### 2️⃣ **Detection and Analysis** 🕵️‍♀️
1. **Validate Incident**:
   - Assign it to yourself and set the status to **Active** ✅.

![Screenshot 2025-01-07 135609](https://github.com/user-attachments/assets/f1c4ba25-0a90-4924-86b9-1e87f25031f6)

2. **Investigate**:
   - Review logs and entity mappings 🗒️.
   - Check PowerShell commands:
     ```plaintext
     powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri <URL> -OutFile <Path>
     ```
   - Identify downloaded scripts:
     - `portscan.ps1`
     - `pwncrypt.ps1`
     - `eicar.ps1`
     - `exfiltratedata.ps1`
3. Gather evidence:
   - Scripts downloaded and executed 🧪.
   - User admitted to downloading free software during the events.

### 3️⃣ **Containment, Eradication, and Recovery** 🛡️
1. Isolate affected systems:
   - Use **Defender for Endpoint** to isolate the machine 🔒.
   - Run anti-malware scans.
2. Analyze downloaded scripts:

3. Remove threats and restore systems:
   - Confirm scripts executed.
   - Clean up affected files and verify machine integrity 🧹.

### 4️⃣ **Post-Incident Activities** 📝
1. Document findings and lessons learned 🖊️.
   - Scripts executed: `pwncrypt.ps1` , `exfiltratedata.ps1` , `portscan.ps1` , `eicar.ps1` .
   - Account involved: `system-user`.
2. Update policies:
   - Restrict PowerShell usage 🚫.
   - Enhance cybersecurity training programs 📚.
3. Finalize reporting and close the case:
   - Mark incident as **True Positive** ✅. 

---

## 🎯 **Incident Summary**
| **Metric**                     | **Value**                        |
|---------------------------------|-----------------------------------|
| **Affected Device**            | `windows-target-1`               |
| **Suspicious Commands**        | 4                                |
| **Scripts Downloaded**         | `portscan.ps1`, `pwncrypt.ps1`, `eicar.ps1`, `exfiltratedata.ps1`   |
| **Incident Status**            | Resolved                         |

---

🎉 **Great Job Securing Your Environment!** 🔒
