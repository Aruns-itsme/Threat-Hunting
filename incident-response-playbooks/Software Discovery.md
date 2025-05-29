# Incident Response Playbook: Software Discovery (T1141)

---

## Incident Type

Enumeration of installed software and applications to identify potential targets for exploitation.

---

## Introduction

This playbook covers detection and response to **Software Discovery** (MITRE T1141), where attackers enumerate software via tools like `wmic product`, `Get-WmiObject`, or `PowerShell Get-Package`.  
Aligned with [NIST 800-61](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) and [MITRE ATT&CK: Software Discovery (T1141)](https://attack.mitre.org/techniques/T1141/).

---

## Summary

Steps to:

- Detect software enumeration activity.
- Contain endpoints performing reconnaissance.
- Remove scripts/tools used.
- Harden software configurations.

---

## Incident Response Process

### Part 1: Acquire, Preserve, Document Evidence

Collect:

- Wazuh/Splunk logs (EventCode 4688).
- Commands like `wmic product`, `Get-WmiObject`.
- User accounts, source IPs, timestamps.

---

### Part 2: Contain the Incident

Actions:

- Quarantine affected hosts.
- Kill processes performing enumeration.
- Revoke access tokens if necessary.

---

### Part 3: Eradicate the Incident

Steps:

- Delete enumeration scripts.
- Reset credentials for compromised users.
- Harden software discovery permissions (Group Policy, RBAC).

---

### Part 4: Recover from the Incident

Steps:

- Validate installed software integrity.
- Enable auditing for software enumeration.
- Restore operations post-verification.

---

### Part 5: Post-Incident Activity

Review:

- Software discovery permissions.
- Detection rules for enumeration commands.
- SOC training for software discovery threats.

---

## Detection Strategies

### Wazuh Query

```kql
data.win.eventdata.CommandLine: ("wmic product" OR "Get-WmiObject" OR "Get-Package")
```
### Splunk Query

index=windows EventCode=4688 (CommandLine="*wmic product*" OR CommandLine="*Get-WmiObject*" OR CommandLine="*Get-Package*")

## Wazuh Logs

{
  "timestamp": "2024-05-28T15:00:00Z",
  "Image": "C:\\Windows\\System32\\wmic.exe",
  "CommandLine": "wmic product get name",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "EventID": "4688",
  "User": "jdoe"
}

## MITRE ATT&CK Mapping

| Tactic    | Technique          | ID    |
| --------- | ------------------ | ----- |
| Discovery | Software Discovery | T1141 |


