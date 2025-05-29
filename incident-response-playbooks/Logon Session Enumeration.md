# Incident Response Playbook: Logon Session Enumeration (T1135)

---

## Incident Type

Enumeration of active logon sessions to discover valid accounts or privileged users.

---

## Introduction

This playbook covers detection and response to **Logon Session Enumeration** (MITRE T1135), a technique used by attackers to map out accounts and privileges on a compromised system.  
It aligns with [NIST 800-61](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) and [MITRE ATT&CK: Logon Session Enumeration (T1135)](https://attack.mitre.org/techniques/T1135/).

---

## Summary

This playbook will help:

- Detect enumeration commands like `query user`, `qwinsta`, or `tasklist /v`.
- Contain systems accessed for enumeration.
- Eradicate enumeration tools.
- Securely restore services and permissions.

---

## Incident Response Process

### Part 1: Acquire, Preserve, Document Evidence

Collect:

- Wazuh and Splunk logs (EventCode 4688 - Process Creation).
- CommandLine details (`query user`, `qwinsta`).
- User account details, source IPs, timestamps.

---

### Part 2: Contain the Incident

Actions:

- Quarantine the affected host.
- Kill processes associated with enumeration.
- Block outbound traffic if enumeration was part of lateral movement.

---

### Part 3: Eradicate the Incident

Steps:

- Remove enumeration tools/scripts.
- Check for privilege escalation attempts.
- Reset credentials for users targeted in enumeration.
- Review access controls and group memberships.

---

### Part 4: Recover from the Incident

Steps:

- Harden permissions (least privilege).
- Enable auditing for logon events.
- Restore operations under strict monitoring.

---

### Part 5: Post-Incident Activity

Update:

- Detection rules for enumeration patterns.
- Security baselines for user and admin privileges.
- Awareness training for SOC and IT teams.

---

## Detection Strategies

### Wazuh Query

```kql
data.win.eventdata.CommandLine: ("query user" OR "qwinsta" OR "tasklist /v")
```
### Splunk Query

index=windows EventCode=4688 (CommandLine="*query user*" OR CommandLine="*qwinsta*" OR CommandLine="*tasklist /v*")

## Wazuh Logs

{
  "timestamp": "2024-05-28T14:36:00Z",
  "Image": "C:\\Windows\\System32\\cmd.exe",
  "CommandLine": "cmd.exe /c query user",
  "ParentImage": "C:\\Windows\\System32\\explorer.exe",
  "EventID": "4688",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.104"
}

## MITRE ATT&CK Mapping

| Tactic    | Technique                 | ID    |
| --------- | ------------------------- | ----- |
| Discovery | Logon Session Enumeration | T1135 |
