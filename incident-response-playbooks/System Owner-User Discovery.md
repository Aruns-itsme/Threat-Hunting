# 🛡️ Incident Response Playbook: System Owner/User Discovery (T1140)

---

## Incident Type

Enumeration of system users and owner accounts to identify targets for privilege escalation.

---

## Introduction

This playbook details detection and response for **System Owner/User Discovery** (MITRE T1140), where attackers query system users via `whoami`, `net user`, or PowerShell commands to identify privileged accounts.  
Aligned with [NIST 800-61](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) and [MITRE ATT&CK: System Owner/User Discovery (T1140)](https://attack.mitre.org/techniques/T1140/).

---

## Summary

Steps to:

- Detect user enumeration commands.
- Contain systems used for reconnaissance.
- Remove enumeration tools.
- Harden access controls.

---

## Incident Response Process

### Part 1: Acquire, Preserve, Document Evidence

Collect:

- Wazuh/Splunk logs (EventCode 4688).
- Commands like `whoami`, `net user`, `Get-LocalUser`.
- User accounts, source IPs, timestamps.

---

### Part 2: Contain the Incident

Actions:

- Quarantine affected systems.
- Terminate reconnaissance processes.
- Disable suspicious accounts.

---

### Part 3: Eradicate the Incident

Steps:

- Delete enumeration scripts/binaries.
- Reset passwords for discovered accounts.
- Audit privileged group memberships.

---

### Part 4: Recover from the Incident

Steps:

- Validate account permissions.
- Enable auditing for account enumeration attempts.
- Reconnect systems post-verification.

---

### Part 5: Post-Incident Activity

Review:

- User permissions and group memberships.
- Detection rules for enumeration.
- Awareness training for SOC and admins.

---

## Detection Strategies

### Wazuh Query

```kql
data.win.eventdata.CommandLine: ("whoami" OR "net user" OR "Get-LocalUser")
```
### Splunk Query

index=windows EventCode=4688 (CommandLine="*whoami*" OR CommandLine="*net user*" OR CommandLine="*Get-LocalUser*")

## Example Logs

{
  "timestamp": "2024-05-28T14:55:00Z",
  "Image": "C:\\Windows\\System32\\cmd.exe",
  "CommandLine": "cmd.exe /c net user",
  "ParentImage": "C:\\Windows\\System32\\explorer.exe",
  "EventID": "4688",
  "User": "testuser"
}

## MITRE ATT&CK Mapping

| Tactic    | Technique                   | ID    |
| --------- | --------------------------- | ----- |
| Discovery | System Owner/User Discovery | T1140 |
