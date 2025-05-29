# Incident Response Playbook: Access Token Manipulation (T1134)

---

## Incident Type

Manipulation of Windows access tokens to escalate privileges or impersonate users.

---

## Introduction

This playbook covers detection and response to **Access Token Manipulation** attacks (MITRE T1134).  
Attackers exploit token privileges to masquerade as higher-privileged users, enabling lateral movement and persistence.  
This guide aligns with [NIST 800-61](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) and [MITRE ATT&CK: Access Token Manipulation (T1134)](https://attack.mitre.org/techniques/T1134/).

---

## Summary

This playbook helps:

- Detect suspicious token usage.
- Contain compromised systems.
- Remove persistence mechanisms.
- Restore secure authentication.

---

## Incident Response Process

### Part 1: Acquire, Preserve, Document Evidence

Collect:

- Wazuh and Splunk alerts (EventCode 4624, LogonType 9/11).
- Suspicious command lines (e.g., `CreateProcessWithTokenW` usage).
- User accounts, source IPs, timestamps.

---

### Part 2: Contain the Incident

Actions:

- Isolate affected systems.
- Disable compromised accounts.
- Terminate processes with abnormal tokens.

---

### Part 3: Eradicate the Incident

Steps:

- Remove rogue user sessions.
- Harden token usage via Group Policy.
- Reset passwords for compromised accounts.

---

### Part 4: Recover from the Incident

Steps:

- Review system policies for token abuse.
- Enable logging for sensitive APIs.
- Restore operations under strict user permissions.

---

### Part 5: Post-Incident Activity

Update:

- Detection logic for token manipulation.
- Access review processes for high-privilege accounts.
- Incident response training materials.

---

## Detection Strategies

### Wazuh Query

```kql
data.win.system.eventID: "4624" AND data.win.eventdata.LogonType: ("9" OR "11")
```
### Splunk Query

index=windows EventCode="4624" LogonType="9" OR LogonType="11"

## Wazuh Logs

{
  "timestamp": "2024-05-28T14:32:00Z",
  "Image": "C:\\Windows\\System32\\cmd.exe",
  "CommandLine": "cmd.exe /c whoami",
  "ParentImage": "C:\\Windows\\System32\\services.exe",
  "EventID": "4624",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.103"
}

## MITRE ATT&CK Mapping

| Tactic               | Technique                 | ID    |
| -------------------- | ------------------------- | ----- |
| Privilege Escalation | Access Token Manipulation | T1134 |
