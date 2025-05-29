# Incident Response Playbook: File Deletion (T1144)

---

## Incident Type

Deletion of files to erase evidence, disrupt operations, or prevent detection.

---

## Introduction

This playbook details detection and response for **File Deletion** (MITRE T1144), where attackers delete files to hinder investigations or achieve anti-forensics objectives.  
Aligned with [NIST 800-61](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) and [MITRE ATT&CK: File Deletion (T1144)](https://attack.mitre.org/techniques/T1144/).

---

## Summary

Steps to:

- Detect unauthorized file deletions.
- Contain affected systems.
- Recover deleted files where possible.
- Strengthen monitoring and prevention mechanisms.

---

## Incident Response Process

### Part 1: Acquire, Preserve, Document Evidence

Collect:

- Wazuh/Splunk logs (EventCode 4663).
- File paths, user accounts, and timestamps.
- Backup copies (if available) for recovery.

---

### Part 2: Contain the Incident

Actions:

- Quarantine the affected system.
- Lock accounts involved in deletions.
- Block network access if necessary.

---

### Part 3: Eradicate the Incident

Steps:

- Identify and remove malicious scripts/tools used for deletion.
- Reset affected user credentials.
- Harden file permissions and access controls.

---

### Part 4: Recover from the Incident

Steps:

- Restore deleted files from backups or shadow copies.
- Validate data integrity post-recovery.
- Monitor for repeat deletion attempts.

---

### Part 5: Post-Incident Activity

Review:

- Backup and recovery procedures.
- Detection rules for file deletion events.
- SOC awareness on anti-forensics tactics.

---

## Detection Strategies

### Wazuh Query

```kql
data.win.system.eventID: "4663" AND data.win.eventdata.AccessMask: "0x10000"
```
### Splunk Query

index=windows EventCode=4663 AccessMask=0x10000

## Wazuh Logs

{
  "timestamp": "2024-05-28T15:15:00Z",
  "Image": "C:\\Windows\\System32\\cmd.exe",
  "CommandLine": "cmd.exe /c del C:\\Sensitive\\file.txt",
  "ParentImage": "C:\\Windows\\System32\\explorer.exe",
  "EventID": "4663",
  "User": "jdoe"
}

## MITRE ATT&CK Mapping

| Tactic          | Technique     | ID    |
| --------------- | ------------- | ----- |
| Defense Evasion | File Deletion | T1144 |
