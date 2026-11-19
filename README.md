# Wazuh-Based Investigation of Suspicious Activity on a Windows Workstation

## Overview

This project involved investigating suspicious activity on a Windows endpoint using Wazuh SIEM alerts and Sysmon telemetry.

The investigation focused on reconstructing observed activity, analyzing process execution, correlating related events, and identifying potential attacker techniques across the endpoint.

## Key Investigation Findings

The investigation uncovered a sequence of suspicious activities, including:

- **Suspicious Execution:** PowerShell execution with execution policy bypass and temporary file creation.
- **Credential Access:** Discovery and execution attempts involving credential dumping tools, including Mimikatz-related activity targeting LSASS.
- **System Reconnaissance:** Enumeration of local users, group memberships, active sessions, and stored credentials.
- **Account Manipulation:** Attempts to enable the Guest account, change its password, and add it to the local Administrators group.
- **Persistence:** Commands attempting to establish registry-based storage and scheduled task execution.
- **Lateral Movement Technique:** Pass-the-Hash activity targeting the `john.sterling` account.
- **Potential Data Exfiltration:** A PowerShell operation attempting to submit data to the Pastebin API.

## Investigation & Analysis

Through Wazuh and Sysmon telemetry, I:

- Analyzed Windows process creation events and command-line activity.
- Traced parent-child process relationships to understand execution chains.
- Correlated related events to reconstruct a chronological sequence of activity.
- Examined suspicious commands and mapped observed behaviors to relevant MITRE ATT&CK techniques.
- Evaluated evidence to distinguish observed actions from outcomes that could not be independently established.

## Tools & Technologies

- Wazuh SIEM
- Sysmon
- Windows Event Logs
- Windows endpoint telemetry
- MITRE ATT&CK Framework

## Repository Contents

| Directory / File | Description |
|---|---|
| `evidence.md` | Screenshots of relevant Wazuh alerts and event details |
| `report/investigation-report.md` | Detailed investigation timeline, technical analysis, findings, and conclusion |

## Investigation Scope

The investigation was conducted using available Wazuh alerts and Windows endpoint telemetry. Findings describe observed activity and evidence-supported interpretations; successful execution and resulting impact are distinguished from attempted actions where the available evidence does not establish the outcome.
