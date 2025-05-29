# Incident Response Playbook: Network Share Discovery (T1138)

---

## Incident Type

Enumeration of accessible network shares to identify file storage locations for lateral movement or data exfiltration.

---

## Introduction

This playbook outlines detection and response to **Network Share Discovery** (MITRE T1138), where attackers use tools like `net view`, `net share`, or PowerShell commands to enumerate network shares.  
Aligned with [NIST 800-61](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) and [MITRE ATT&CK: Network Share Discovery (T1138)](https://attack.mitre.org/techniques/T1138/).

---

## Summary

This playbook provides steps to:

- Detect network share enumeration activity.
- Contain affected endpoints.
- Remove reconnaissance tools and scripts.
- Harden systems and review permissions.

---

## Incident Response Process

### Part 1: Acquire, Preserve, Document Evidence

Collect:

- Wazuh/Splunk logs for commands like `net view`, `net share`.
- User accounts, source IPs, timestamps.
- Network device logs showing enumeration attempts.

---

### Part 2: Contain the Incident

Actions:

- Quarantine the host performing enumeration.
- Block suspicious accounts.
- Isolate sensitive network shares.

---

### Part 3: Eradicate the Incident

Steps:

- Delete enumeration scripts.
- Reset credentials for affected accounts.
- Harden SMB configurations (disable SMBv1, restrict access).

---

### Part 4: Recover from the Incident

Steps:

- Validate share permissions (least privilege).
- Monitor for new enumeration attempts.
- Re-enable network access after verification.

---

### Part 5: Post-Incident Activity

Review:

- Share access policies.
- Detection rules for enumeration tools.
- User education on network security.

---

## Detection Strategies

### Wazuh Query

```kql
data.win.eventdata.CommandLine: ("net view" OR "net share")
```
### Splunk Query

index=windows EventCode=4688 (CommandLine="*tasklist /v*" OR CommandLine="*Get-Process*")

## Wazuh Logs

{
  "timestamp": "2024-05-28T14:44:00Z",
  "Image": "C:\\Windows\\System32\\tasklist.exe",
  "CommandLine": "tasklist /v",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "EventID": "4688",
  "User": "Administrator"
}

## MITRE ATT&CK Mapping

| Tactic    | Technique                    | ID    |
| --------- | ---------------------------- | ----- |
| Discovery | Application Window Discovery | T1137 |

