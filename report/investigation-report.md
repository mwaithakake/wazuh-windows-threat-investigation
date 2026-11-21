# Wazuh-Based Investigation of Suspicious Activity on a Windows Workstation

**Investigation Type:** Windows Endpoint Security Investigation  
**SIEM Platform:** Wazuh  
**Endpoint Telemetry:** Sysmon and Windows Event Logs  
**Investigated Endpoint:** `Windows_SwiftSpend2`  
**Agent ID:** `003`  
**Endpoint IP:** `10.10.205.57`  
**Activity Date:** April 29, 2024 (UTC)

---

## 1. Executive Summary

This investigation examined suspicious activity recorded on a Windows workstation monitored through Wazuh. Using Sysmon process creation events, Windows Security events, and command-line telemetry, I reconstructed a sequence of activity involving suspicious PowerShell execution, credential-access operations, local account reconnaissance, account manipulation, persistence-related commands, Pass-the-Hash activity, and attempted data exfiltration.

The investigation began with a PowerShell process running under the local Administrator context with execution policy bypass. Subsequent activity revealed the use of temporary files and .NET compilation, checks for credential-dumping utilities, attempts to access LSASS-related dump data, and extensive enumeration of local accounts and stored credentials.

Additional events showed attempts to modify the built-in Guest account, establish scheduled task execution, and use Mimikatz functionality to perform Pass-the-Hash against the `john.sterling` account. The investigation also identified a PowerShell operation attempting to submit data containing sensitive-labeled information to the Pastebin API.

By correlating process creation events, parent-child relationships, command-line arguments, and authentication telemetry, I reconstructed the observed sequence of activity and identified several behaviors consistent with common attacker techniques.

The investigation provides an evidence-based account of the activity recorded on the endpoint, distinguishing observed execution and attempted operations from outcomes that the available telemetry does not independently establish.

## 2. Investigation Objectives

The investigation aimed to:

- Identify suspicious process execution and establish the earliest observed activity.
- Examine PowerShell commands, temporary file activity, and process relationships.
- Identify credential-access tooling and attempts to interact with LSASS.
- Investigate local account, group, session, and stored credential enumeration.
- Examine account manipulation and persistence-related commands.
- Analyze the Pass-the-Hash process execution chain.
- Investigate attempted payload retrieval and potential data exfiltration.
- Reconstruct a chronological timeline using available endpoint telemetry.

## 3. Environment & Evidence Sources

### Monitoring Environment

The investigation focused on the Windows endpoint registered in Wazuh as `Windows_SwiftSpend2`.

| Attribute | Value |
|---|---|
| Host / Agent | `Windows_SwiftSpend2` |
| Agent ID | `003` |
| Endpoint IP | `10.10.205.57` |
| Operating System | Windows |
| SIEM | Wazuh |
| Endpoint Telemetry | Sysmon |
| Activity Date | April 29, 2024 |

### Evidence Sources

The investigation used the following telemetry:

- **Sysmon Process Creation (Event ID 1):** Used to examine process execution, command-line arguments, process identifiers, parent processes, users, and integrity levels.
- **Sysmon File Creation (Event ID 11):** Used to identify temporary files created during suspicious activity.
- **Windows Security Event ID 4624:** Used to examine successful logon activity and authentication context.
- **Wazuh Alerts and Event Details:** Used to locate, review, and correlate relevant endpoint events.

The analysis prioritized the underlying event details, particularly process command lines and Sysmon metadata, rather than relying exclusively on Wazuh alert titles.

## 4. Investigation Methodology

I approached the investigation by examining suspicious endpoint events and progressively correlating related activity.

The analysis followed these steps:

1. **Event identification:** Reviewed Wazuh telemetry to identify suspicious commands, processes, and file activity.
2. **Process analysis:** Examined process images, command lines, process IDs, parent process IDs, user contexts, and integrity levels.
3. **Event correlation:** Connected related process and file events to understand how activity developed over time.
4. **Command interpretation:** Examined command-line arguments to identify the purpose of executed operations.
5. **Timeline reconstruction:** Arranged relevant events chronologically to establish the observed sequence of activity.
6. **Behavioral assessment:** Compared observed behavior with known adversary techniques and identified relevant MITRE ATT&CK mappings.

Where an event showed that a command was launched, I treated that as evidence of execution or an attempted operation—not automatic proof that the intended action succeeded.

## 5. Investigation Findings & Timeline

### 5.1 Initial Execution and Preparation

**Time: 12:04:12 UTC onwards**

The earliest observed activity in the available evidence involved a PowerShell process running under `ATOMIC\Administrator` with High integrity.

The process was launched with the following execution policy option:

`-ExecutionPolicy bypass`

The process was identified as PID `2980`, with parent PID `6232`.

This PowerShell session became an important reference point during the investigation because several subsequent processes were launched beneath it.

**Evidence:**

<img width="919" height="425" alt="1 1" src="https://github.com/user-attachments/assets/26e2fab8-639a-4c8c-a9e5-ef1583c912a3" />

The same PowerShell process subsequently created two files in a temporary directory:

- `n1phi4c0.dll`
- `n1phi4c0.cmdline`

Shortly afterwards, the Windows .NET C# compiler, `csc.exe`, was launched using the temporary `.cmdline` response file.

The compiler process was associated with the original PowerShell process (PID `2980`).

**Evidence:**

![Initial PowerShell execution](https://github.com/user-attachments/assets/b26e56bd-bf64-472c-8e37-8adcf947e7a5)

This sequence establishes PowerShell execution with policy bypass, temporary file creation, and subsequent compiler activity. The telemetry supports the conclusion that code compilation or processing was initiated, although it does not independently establish whether the resulting DLL was successfully loaded or what functionality it performed.

**Assessment:** The initial process activity provides the starting point for the observed sequence of suspicious execution and preparation.

### 5.2 Credential Tool Discovery and Environment Checks

Following the initial PowerShell activity, several commands were executed to check for credential-access tools and related files.

The investigation identified checks involving:

- ProcDump
- Outflank-Dumpert
- NanoDump
- `memotech.exe`
- `lsass.DMP`
- Pypykatz

These checks indicate that the environment was being examined for utilities and files associated with credential extraction.

**Evidence — `2.1.png`**

![Credential tool discovery evidence](https://github.com/user-attachments/assets/fdaea4db-7c0c-424a-a374-43aabbab9071)

A separate command checked whether `lsass.DMP` existed in the temporary directory.

**Evidence — `2.2.png`**

![LSASS dump file check](https://github.com/user-attachments/assets/9abdbab2-8d87-4913-9c6a-6936537e46a7)

Another command attempted to check the availability of Pypykatz by invoking its help option:

`pypykatz -h`

**Evidence — `2.3.png`**

![Pypykatz availability check](https://github.com/user-attachments/assets/972feef2-3da2-46cd-9850-4a407bc4fbaa)

The telemetry also showed Python and pip availability checks, followed by a later invocation of `pypykatz.exe -h`.

These commands indicate preparation and discovery of credential-access tooling. They do not, by themselves, establish that a credential-dumping operation completed successfully.

**Assessment:** The repeated checks for credential-access utilities and LSASS-related files provide important context for the subsequent credential extraction activity.

### 5.3 LSASS Credential Extraction Attempt

**Time: 14:16:17 UTC**

A particularly significant event involved the execution of `memotech.exe` through `cmd.exe`.

The command included:

`sekurlsa::minidump %tmp%\lsass.DMP`

followed by:

`sekurlsa::logonpasswords full`

The executable was located in the Atomic Red Team directory associated with the LSASS memory technique, `T1003.001`.

The process was launched under the Administrator account with High integrity.

**Evidence — `4.1.png`**

![LSASS credential extraction attempt](https://github.com/user-attachments/assets/5ff77f62-57b9-49c6-bf1d-d1f314c9b43c)

The command indicates an attempt to load an LSASS dump file and extract logon credential information using Mimikatz functionality.

This is consistent with the MITRE ATT&CK technique:

- **T1003.001 — OS Credential Dumping: LSASS Memory**

The process creation event establishes that the extraction command was launched. However, the available evidence does not independently establish that the dump file was valid, that credentials were successfully extracted, or that credentials were obtained.

**Assessment:** The command represents a direct credential-access attempt and is one of the most significant findings in the investigation.

### 5.4 Network Authentication Observation

**Time: 13:40:51 UTC**

Windows Security Event ID 4624 recorded a successful network logon for:

`ATOMIC\john.sterling`

The event contained the following details:

| Attribute | Observed value |
|---|---|
| Event ID | `4624` |
| Account | `john.sterling` |
| Logon Type | `3` — Network |
| Source IP | `10.9.3.14` |
| Source Workstation | `SecurityNomad-1` |
| Authentication Package | NTLM |
| Authentication Variant | NTLMv2 |

**Evidence — `8.1.png`**

![John Sterling network logon](https://github.com/user-attachments/assets/84efee39-9aed-4c2e-8996-9242be30f77c)

This event establishes a successful network logon for the account from the identified source workstation.

It is important to distinguish this authentication event from the later Pass-the-Hash activity targeting the same account. Although both involve `john.sterling`, the available telemetry does not establish that the earlier network logon resulted from, or was caused by, the later Pass-the-Hash command.

**Assessment:** The event provides useful authentication context and identifies a network logon involving an account that was subsequently targeted by credential-related activity.

### 5.5 Payload Retrieval Attempt

**Time: 13:55:35 UTC**

A PowerShell process (PID `6088`), launched beneath the earlier PowerShell process (PID `2980`), executed an `Invoke-WebRequest` command.

The command attempted to retrieve:

`http://localhost/PhishingAttachment.xlsm`

The specified output filename was:

`SwiftSpend_Financial_Expenses.xlsm`

The file was intended to be saved in the current user's temporary directory.

**Evidence — `8.2.png`**

![Phishing attachment retrieval attempt](https://github.com/user-attachments/assets/413ae3b6-9bc1-4d88-83ee-c31188e1bb4a)

The filename and `.xlsm` extension indicate that the requested file was a macro-enabled Excel document.

The command demonstrates an attempt to retrieve and save the attachment. The available process telemetry does not independently establish whether the request returned a file, whether the file was opened, or whether any macros were executed.

**Assessment:** The event identifies a payload retrieval operation that forms part of the broader suspicious activity observed on the workstation.

### 5.6 Persistence-Related Activity

**Time: 14:00:30 UTC**

A command executed through `cmd.exe`, with the earlier PowerShell process as its parent, attempted to create a registry value and a scheduled task.

The registry operation targeted:

`HKCU\SOFTWARE\ATOM`

The value name was:

`test`

The command stored a Base64-encoded string in this registry location.

The scheduled task was named:

`ATOM`

It was configured with a daily schedule at `12:34`.

Its intended action launched PowerShell, read the registry value, decoded the Base64 content, and passed the resulting command to `IEX`.

The encoded content in the observed command decodes to:

`ping www.youarevulnerable.thm`

**Evidence — `6.1.png`**

![Registry and scheduled task persistence attempt](https://github.com/user-attachments/assets/9f548d27-daad-49e2-9ad0-85785511275f)

The scheduled task behavior is relevant to:

- **T1053.005 — Scheduled Task/Job: Scheduled Task**

The registry value served as storage for the command that the scheduled task was designed to retrieve and execute.

This demonstrates an attempt to establish recurring command execution using a scheduled task and registry-stored data. The process telemetry establishes that the creation command was launched, but does not independently confirm that the registry modification or scheduled task creation succeeded or that the task subsequently ran.

**Assessment:** The command represents a persistence attempt using scheduled task execution and registry-based command storage.

### 5.7 Local Account and System Reconnaissance

**Time: 14:14:43 UTC**

A PowerShell process (PID `2388`) performed several enumeration operations under the Administrator account.

The observed commands included:

- `net user`
- `Get-LocalUser`
- `Get-LocalGroupMember`
- `Get-LocalGroup`
- `net localgroup`
- `cmdkey.exe /list`
- Directory enumeration under `C:\Users`

**Evidence — `5.2.png`**

<img width="1369" height="723" alt="5 1" src="https://github.com/user-attachments/assets/89721947-06a8-4099-8f84-0c8f41b67935" />

These commands were intended to gather information about local accounts, group memberships, user directories, and stored credential targets.

The `cmdkey.exe /list` operation is particularly relevant because it queries credentials stored in Windows Credential Manager.

The observed behavior is consistent with local account and system discovery, including:

- **T1087.001 — Account Discovery: Local Account**
- **T1069.001 — Permission Groups Discovery: Local Groups**

The command lines establish that these enumeration operations were launched. Their resulting output was not available in the reviewed telemetry.

**Assessment:** The activity demonstrates systematic enumeration of local users, groups, directories, and stored credential targets.

### 5.8 Guest Account Manipulation

**Time: 14:14:13–14:14:54 UTC**

The investigation identified three commands targeting the built-in Windows Guest account. The commands were launched through `net.exe` and shared the same parent PowerShell process (PID `2980`), running as `ATOMIC\Administrator` with High integrity.

**1. Guest account activation — 14:14:13.958 UTC**

The first command attempted to enable the Guest account:

```cmd
net.exe user guest /active:yes
```

**Evidence — `5.1.png`**

![Guest account activation](https://github.com/user-attachments/assets/89721947-06a8-4099-8f84-0c8f41b67935)

**2. Guest account password modification — 14:14:35.717 UTC**

A subsequent command attempted to change the Guest account password:

```cmd
net.exe user guest I_AM_M0N1T0R1NG
```

**Evidence — `5.2.png`**

![Guest account password modification](https://github.com/user-attachments/assets/677ff4bc-f9eb-482c-9942-3a6248661b10)

**3. Guest account added to the Administrators group — 14:14:54.452 UTC**

The final command attempted to add the Guest account to the local Administrators group:

```cmd
net.exe localgroup Administrators guest /add
```

**Evidence — `5.3.png`**

![Guest account added to Administrators group](https://github.com/user-attachments/assets/844a694c-6554-40e6-ac44-ac18356a4e79)

**Assessment**

The sequence shows an attempt to enable the built-in Guest account, change its password, and grant it local administrator privileges. Taken together, these actions are consistent with account manipulation and attempted privilege escalation.

The process creation events confirm that all three commands were launched. They do not independently confirm that the account was successfully enabled, its password changed, or its group membership modified.
### 5.9 Pass-the-Hash Activity

**Time: 14:21:41 UTC**

A process identified as `memotech.exe` was launched from the Atomic Red Team directory.

Although the executable was named `memotech.exe`, its process metadata identified its original filename as:

`mimikatz.exe`

The command included the Mimikatz module:

`sekurlsa::pth`

It targeted the account:

`john.sterling`

The command also supplied an NTLM hash and specified the domain through the `%userdnsdomain%` environment variable.

**Evidence — `7.1.png`**

![Mimikatz Pass-the-Hash invocation](https://github.com/user-attachments/assets/b7001ecd-9fc4-471e-b8ac-e0f799bf4761)

The activity corresponds to:

- **T1550.002 — Use Alternate Authentication Material: Pass the Hash**

A subsequent Sysmon process creation event showed that the Mimikatz process (PID `4800`) spawned a child `cmd.exe` process (PID `3104`).

**Evidence — `7.2.png`**

![Pass-the-Hash child process](https://github.com/user-attachments/assets/bec2c4a7-9619-4fce-890d-c613a86ac142)

The parent-child relationship provides additional context for the execution chain:

- Parent: `memotech.exe` / Mimikatz, PID `4800`
- Child: `cmd.exe`, PID `3104`

This establishes that the Pass-the-Hash command was invoked and that a command shell was subsequently created by the Mimikatz process.

The process chain does not independently establish that the supplied hash was valid, that authentication succeeded, or that access to another system was obtained.

**Assessment:** The evidence identifies a Pass-the-Hash attempt targeting `john.sterling`, supported by both executable metadata and the resulting process creation relationship.

### 5.10 Potential Data Exfiltration Through Pastebin

**Time: 14:56 UTC**

The final significant activity examined involved a PowerShell process (PID `1776`) attempting to submit data to the Pastebin API.

The command used:

`Invoke-RestMethod`

with the HTTP method:

`POST`

The destination was:

`https://pastebin.com/api/api_post.php`

The request included content containing sensitive-labeled strings, simulated secrets, API keys, passwords, and a flag value.

**Evidence — `9.1.png`**

![Pastebin data submission attempt](https://github.com/user-attachments/assets/d6805f05-8e4d-4fbd-afff-019863beed50)

The use of an HTTP POST request to a text-sharing service is consistent with an attempted data exfiltration operation.

Relevant MITRE ATT&CK technique:

- **T1567.003 — Exfiltration Over Web Service: Exfiltration to Text Storage Sites**

The command provides evidence of an attempted submission of the specified content. The available telemetry does not independently establish whether Pastebin accepted the request or whether the content became publicly accessible.

**Assessment:** This activity represents a potential data exfiltration attempt and provides an important final stage in the reconstructed sequence.

## 6. Consolidated Activity Timeline

The following timeline summarizes the major events identified during the investigation.

| Time (UTC) | Observed activity |
|---|---|
| 12:04:12 | PowerShell PID 2980 launched with execution policy bypass under Administrator |
| 12:04:16 | Temporary DLL and command-line files created |
| 12:04:16 | `csc.exe` launched using the temporary response file |
| Around 12:04 | Credential tool and LSASS dump checks observed |
| 12:04:53 | NanoDump availability check observed |
| 12:04:54 | Python and pip availability checks performed |
| 13:18:02 | Pypykatz help command executed |
| 13:40:51 | Successful NTLM network logon for `john.sterling` |
| 13:41:11 | Additional temporary files created by a PowerShell process running as `john.sterling` |
| 13:55:35 | PowerShell attempted to retrieve a macro-enabled Excel attachment |
| 14:00:30 | Registry and scheduled task creation commands executed |
| 14:11:33 | Hostname enumeration command launched |
| 14:14:34 | Guest account password change attempted |
| 14:14:43 | Local user, group, directory, and stored credential enumeration performed |
| 14:14:54 | Guest account addition to Administrators attempted |
| 14:15:40 | Windows Stored User Names and Passwords interface invoked |
| 14:16:17 | Mimikatz-related LSASS dump credential extraction command launched |
| 14:19:16 | User session enumeration performed |
| 14:19:42 | Additional local account, group, and credential reconnaissance performed |
| 14:21:41 | Mimikatz Pass-the-Hash command targeting `john.sterling` launched |
| 14:21:41 | Child command shell created by the Mimikatz process |
| 14:56 | PowerShell attempted to submit data to the Pastebin API |

*Note:* The Pypykatz event contained a timestamp discrepancy between the Sysmon event time and the Wazuh event timestamp. The process execution time shown in the Sysmon event was used for the reconstructed timeline. The timeline represents observed telemetry, not a claim that every action was successful.

## 7. MITRE ATT&CK Mapping

The following techniques describe behaviors identified in the observed commands and process activity.

| Technique | ATT&CK ID | Observed behavior |
|---|---|---|
| PowerShell | T1059.001 | PowerShell execution and command activity |
| OS Credential Dumping: LSASS Memory | T1003.001 | Mimikatz-related LSASS dump extraction attempt |
| Account Discovery: Local Account | T1087.001 | Local user enumeration |
| Permission Groups Discovery: Local Groups | T1069.001 | Local group enumeration |
| Scheduled Task/Job: Scheduled Task | T1053.005 | Scheduled task creation command |
| Use Alternate Authentication Material: Pass the Hash | T1550.002 | Mimikatz Pass-the-Hash invocation |
| Exfiltration Over Web Service: Exfiltration to Text Storage Sites | T1567.003 | Pastebin API submission attempt |

These mappings are based on the observed command behavior. They describe the techniques indicated by the telemetry and do not imply that every attempted operation achieved its intended outcome.

## 8. Overall Assessment

The investigation identified a sequence of suspicious endpoint activities that, when examined individually, provided evidence of execution, credential-access preparation, account reconnaissance, account manipulation, persistence-related commands, and potential data exfiltration.

Correlating the events revealed a broader pattern:

- An initial PowerShell process operated with execution policy bypass and initiated subsequent activity.
- Temporary files and compiler activity indicated additional execution preparation.
- Multiple checks were performed for credential-access tools and LSASS-related files.
- Mimikatz functionality was invoked in an attempt to extract credential information from an LSASS dump.
- Local users, groups, sessions, directories, and stored credential targets were enumerated.
- Commands attempted to modify the Guest account and establish scheduled task execution.
- A separate Mimikatz process invoked Pass-the-Hash against `john.sterling` and spawned a child command shell.
- PowerShell attempted to retrieve a macro-enabled attachment and later submit data to Pastebin.

The strongest findings are the directly observed process execution commands, the Mimikatz executable metadata, the LSASS extraction command, the Guest account modification commands, the Pass-the-Hash process chain, and the Pastebin submission command.

Together, these findings demonstrate how endpoint telemetry can be used to reconstruct suspicious activity, identify potential adversary techniques, and develop an evidence-supported understanding of events on a Windows workstation.

## 9. Scope & Evidence Considerations

This investigation was based on the Wazuh alerts and Windows endpoint telemetry available for the monitored workstation.

The analysis established the execution of relevant commands and the relationships between observed processes. Some outcomes—including successful credential extraction, completed account modifications, successful scheduled task execution, successful Pass-the-Hash authentication, and successful Pastebin publication—were not independently established by the reviewed evidence.

The investigation did not include a direct forensic examination of the endpoint's memory, disk image, or external network traffic. Accordingly, conclusions are limited to the available telemetry and the behavior indicated by the recorded commands.

These boundaries are important when interpreting the findings, but they do not change the core result: the available evidence was sufficient to reconstruct and analyze a substantial sequence of suspicious endpoint activity.

## 10. Skills Demonstrated

- SIEM alert investigation using Wazuh
- Windows endpoint telemetry analysis
- Sysmon Event ID 1 and Event ID 11 analysis
- Windows Security Event analysis
- PowerShell command-line investigation
- Process and parent-child relationship correlation
- Credential-access behavior analysis
- Local account and group reconnaissance analysis
- Persistence and account manipulation investigation
- Pass-the-Hash process analysis
- MITRE ATT&CK technique mapping
- Chronological incident reconstruction
- Evidence-based reporting and analytical judgement

---

