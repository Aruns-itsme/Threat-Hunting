# Incident Response Playbook: System Service Discovery (T1136)

---

## Incident Type

Enumeration of system services to identify installed services, their configurations, and potential attack vectors.

---

## Introduction

This playbook guides detection and response to **System Service Discovery** (MITRE T1136), where attackers enumerate services via tools like `sc query` or `Get-Service`.  
Aligned with [NIST 800-61](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) and [MITRE ATT&CK: System Service Discovery (T1136)](https://attack.mitre.org/techniques/T1136/).

---

## Summary

Steps to:

- Detect service enumeration attempts.
- Contain affected endpoints.
- Remove reconnaissance tools.
- Harden service configurations.

---

## Incident Response Process

### Part 1: Acquire, Preserve, Document Evidence

- Wazuh/Splunk alerts (EventID 4688).
- Command lines like `sc query`, `Get-Service`.
- Usernames, source IPs, and timestamps.

---

### Part 2: Contain the Incident

- Isolate affected hosts.
- Kill enumeration processes.
- Block suspicious user sessions.

---

### Part 3: Eradicate the Incident

- Delete scripts/binaries used for enumeration.
- Reset affected accounts.
- Harden service permissions.

---

### Part 4: Recover from the Incident

- Validate system services.
- Audit service configurations.
- Enable monitoring for service queries.

---

### Part 5: Post-Incident Activity

- Update detection rules for service discovery.
- Review service permissions.
- Conduct awareness training.

---

## Detection Strategies

### Wazuh Query

```kql
data.win.eventdata.CommandLine: ("sc query" OR "Get-Service")

### Splunk Query

index=windows EventCode=4688 (CommandLine="*sc query*" OR CommandLine="*Get-Service*")

## Wazuh Logs

{
  "timestamp": "2024-05-28T14:40:00Z",
  "Image": "C:\\Windows\\System32\\sc.exe",
  "CommandLine": "sc query",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "EventID": "4688",
  "User": "testuser"
}

## MITRE ATT&CK Mapping

| Tactic    | Technique                | ID    |
| --------- | ------------------------ | ----- |
| Discovery | System Service Discovery | T1136 |
