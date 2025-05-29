# Incident Response Playbook: File and Directory Discovery (T1139)

---

## Incident Type

Enumeration of files and directories on a system to identify sensitive data and potential targets.

---

## Introduction

This playbook covers detection and response to **File and Directory Discovery** (MITRE T1139).  
Attackers list files and folders using tools like `dir`, `tree`, `ls`, or PowerShell commands to locate sensitive files for further exploitation or exfiltration.  
Aligned with [NIST 800-61](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) and [MITRE ATT&CK: File and Directory Discovery (T1139)](https://attack.mitre.org/techniques/T1139/).

---

## Summary

Steps to:

- Detect directory listing commands.
- Contain compromised systems.
- Remove reconnaissance tools.
- Secure sensitive directories.

---

## Incident Response Process

### Part 1: Acquire, Preserve, Document Evidence

Collect:

- Wazuh/Splunk logs (EventCode 4688).
- Commands like `dir`, `tree`, `Get-ChildItem`.
- User accounts, source IPs, timestamps.

---

### Part 2: Contain the Incident

Actions:

- Quarantine the system.
- Kill processes involved in enumeration.
- Lock down file shares/directories.

---

### Part 3: Eradicate the Incident

Steps:

- Remove reconnaissance scripts.
- Reset credentials for compromised accounts.
- Audit sensitive directories for tampering.

---

### Part 4: Recover from the Incident

Steps:

- Restore permissions to least privilege.
- Enable file integrity monitoring (e.g., Wazuh FIM).
- Reconnect system post-validation.

---

### Part 5: Post-Incident Activity

Review:

- File access permissions.
- Detection rules for file enumeration.
- Awareness training for SOC and IT staff.

---

## Detection Strategies

### Wazuh Query

```kql
data.win.eventdata.CommandLine: ("dir" OR "tree" OR "Get-ChildItem")

### Splunk Query

index=windows EventCode=4688 (CommandLine="*dir*" OR CommandLine="*tree*" OR CommandLine="*Get-ChildItem*")

## Example Logs

{
  "timestamp": "2024-05-28T14:52:00Z",
  "Image": "C:\\Windows\\System32\\cmd.exe",
  "CommandLine": "cmd.exe /c dir /s C:\\Users",
  "ParentImage": "C:\\Windows\\System32\\explorer.exe",
  "EventID": "4688",
  "User": "jdoe"
}

## MITRE ATT&CK Mapping

| Tactic    | Technique                    | ID    |
| --------- | ---------------------------- | ----- |
| Discovery | File and Directory Discovery | T1139 |

