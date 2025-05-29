# Incident Response Playbook: Data from Information Repositories (T1145)

---

## Incident Type

Accessing data stored in centralized repositories (e.g., databases, SharePoint, document management systems).

---

## Introduction

This playbook covers detection and response for **Data from Information Repositories** (MITRE T1145), where attackers extract sensitive information from structured sources.  
Aligned with [NIST 800-61](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) and [MITRE ATT&CK: Data from Information Repositories (T1145)](https://attack.mitre.org/techniques/T1145/).

---

## Summary

Steps to:

- Detect unauthorized access to information repositories.
- Contain affected systems and users.
- Remove access vectors.
- Secure repositories against future threats.

---

## Incident Response Process

### Part 1: Acquire, Preserve, Document Evidence

Collect:

- Wazuh/Splunk logs showing repository access (EventCode 4624, 4663, SQL logs).
- Usernames, source IPs, timestamps.
- Queries run (e.g., SQL SELECT statements).

---

### Part 2: Contain the Incident

Actions:

- Revoke access for suspicious accounts.
- Isolate endpoints used for data access.
- Block outbound data flows if exfiltration is detected.

---

### Part 3: Eradicate the Incident

Steps:

- Remove malicious scripts/queries.
- Reset database/service credentials.
- Harden repository access controls.

---

### Part 4: Recover from the Incident

Steps:

- Restore data integrity if modified.
- Audit repository permissions.
- Enable query logging and monitoring.

---

### Part 5: Post-Incident Activity

Review:

- Data classification policies.
- Detection rules for repository access.
- Security awareness for data handling.

---

## Detection Strategies

### Wazuh Query

```kql
data.win.eventdata.ObjectName: "*\\database*" OR data.win.eventdata.ObjectName: "*\\sharepoint*"

### Splunk Query

index=windows (EventCode=4624 OR EventCode=4663) ObjectName="*\\database*" OR ObjectName="*\\sharepoint*"

## Wazuh Logs

{
  "timestamp": "2024-05-28T15:20:00Z",
  "Image": "C:\\Windows\\System32\\sqlcmd.exe",
  "CommandLine": "sqlcmd -S dbserver -Q \"SELECT * FROM Customers\"",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "EventID": "4624",
  "User": "svc-dba",
  "Source_Network_Address": "192.168.56.110"
}

## MITRE ATT&CK Mapping

| Tactic     | Technique                          | ID    |
| ---------- | ---------------------------------- | ----- |
| Collection | Data from Information Repositories | T1145 |
