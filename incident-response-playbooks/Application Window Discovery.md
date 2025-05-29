# Incident Response Playbook: Application Window Discovery (T1137)

---

## Incident Type

Enumeration of active application windows to understand running applications and potential targets.

---

## Introduction

This playbook covers detection and response for **Application Window Discovery** (MITRE T1137), where attackers identify running applications via APIs or tools like `tasklist`, `Get-Process`, or `window enumeration utilities`.  
Aligned with [NIST 800-61](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) and [MITRE ATT&CK: Application Window Discovery (T1137)](https://attack.mitre.org/techniques/T1137/).

---

## Summary

Steps to:

- Detect window enumeration tools and commands.
- Contain affected systems.
- Remove reconnaissance utilities.
- Harden systems against information leaks.

---

## Incident Response Process

### Part 1: Acquire, Preserve, Document Evidence

- Wazuh/Splunk logs with EventID 4688.
- Commands like `tasklist /v`, `Get-Process`.
- User accounts, IP addresses, timestamps.

---

### Part 2: Contain the Incident

- Quarantine affected hosts.
- Kill reconnaissance processes.
- Lockdown suspicious user sessions.

---

### Part 3: Eradicate the Incident

- Delete scripts/tools (e.g., `tasklist.exe` if misused).
- Reset user credentials if compromised.
- Audit installed software for legitimacy.

---

### Part 4: Recover from the Incident

- Validate and restrict process enumeration permissions.
- Enable enhanced auditing for sensitive tools.
- Restore clean system state if necessary.

---

### Part 5: Post-Incident Activity

- Update detection rules for process enumeration.
- Harden Group Policy: restrict access to utilities like `tasklist`.
- Review user permissions and privileges.

---

## Detection Strategies

### Wazuh Query

```kql
data.win.eventdata.CommandLine: ("tasklist /v" OR "Get-Process")

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

