# Incident Response Playbook: System Information Discovery (T1142)

---

## Incident Type

Enumeration of system information such as hostname, OS version, and hardware configuration.

---

## Introduction

This playbook outlines detection and response for **System Information Discovery** (MITRE T1142), where attackers gather system details to inform further attack stages.  
Common tools include `systeminfo`, `hostname`, or `Get-ComputerInfo`.  
Aligned with [NIST 800-61](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) and [MITRE ATT&CK: System Information Discovery (T1142)](https://attack.mitre.org/techniques/T1142/).

---

## Summary

Steps to:

- Detect system information gathering.
- Contain systems performing reconnaissance.
- Remove scripts/tools used.
- Harden system exposure settings.

---

## Incident Response Process

### Part 1: Acquire, Preserve, Document Evidence

Collect:

- Wazuh/Splunk logs (EventCode 4688).
- Commands like `systeminfo`, `hostname`, `Get-ComputerInfo`.
- User accounts, source IPs, timestamps.

---

### Part 2: Contain the Incident

Actions:

- Isolate affected endpoints.
- Terminate enumeration processes.
- Revoke suspicious user sessions.

---

### Part 3: Eradicate the Incident

Steps:

- Remove enumeration scripts/tools.
- Reset credentials for accounts used.
- Harden system information access (e.g., Group Policy).

---

### Part 4: Recover from the Incident

Steps:

- Validate system integrity.
- Re-enable monitoring and alerting.
- Restore systems under strict access controls.

---

### Part 5: Post-Incident Activity

Review:

- System access permissions.
- Detection logic for system information commands.
- Training for IT teams on detection patterns.

---

## Detection Strategies

### Wazuh Query

```kql
data.win.eventdata.CommandLine: ("systeminfo" OR "hostname" OR "Get-ComputerInfo")
```
### Splunk Query

index=windows EventCode=4688 (CommandLine="*systeminfo*" OR CommandLine="*hostname*" OR CommandLine="*Get-ComputerInfo*")

## Wazuh Logs

{
  "timestamp": "2024-05-28T15:05:00Z",
  "Image": "C:\\Windows\\System32\\systeminfo.exe",
  "CommandLine": "systeminfo",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "EventID": "4688",
  "User": "svc-account"
}


## MITRE ATT&CK Mapping

| Tactic    | Technique                    | ID    |
| --------- | ---------------------------- | ----- |
| Discovery | System Information Discovery | T1142 |

