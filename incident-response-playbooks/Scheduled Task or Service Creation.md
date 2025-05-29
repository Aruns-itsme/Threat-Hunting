# Incident Response Playbook: Scheduled Task or Service Creation (T1131)

---

## Incident Type

Creation of Scheduled Tasks or Services for Persistence

---

## Introduction

This playbook outlines response actions for **Scheduled Task/Service Creation** attacks (MITRE T1131).  
Attackers leverage scheduled tasks or services to achieve **persistence** and **privilege escalation**.  
This playbook aligns with **NIST SP 800-61** and **MITRE ATT&CK** for effective detection, response, and recovery.

---

## Summary

Detect and respond to unauthorized scheduled tasks/services by:

- Identifying suspicious `schtasks.exe` or `sc.exe` executions.
- Containing compromised hosts.
- Eradicating malicious tasks and binaries.
- Conducting post-incident review.

---

## Incident Response Process

### Part 1: Acquire, Preserve, Document Evidence

Identify:
- Wazuh Alerts: `schtasks.exe` execution.
- Splunk Logs: Process creation, user, parent process.

Document:
- Timestamps, usernames, IPs.
- Task names and scheduled intervals.
- Registry modifications.

---

### Part 2: Contain the Incident

Actions:
- Isolate compromised endpoint.
- Disable unauthorized scheduled tasks (`schtasks /Delete /TN <TaskName>`).
- Kill related processes.

---

### Part 3: Eradicate the Incident

Actions:
- Remove malicious task (`schtasks` or `services.msc`).
- Delete associated binaries/scripts.
- Reset impacted account credentials.

---

### Part 4: Recover from the Incident

Steps:
- Restore legitimate services if impacted.
- Monitor task creation events (Wazuh/Splunk).
- Harden task/service permissions.

---

### Part 5: Post-Incident Activity

Lessons Learned:
- Update detection queries for task/service creation.
- Audit task permissions.
- Train SOC on persistence techniques.

---

## Detection Strategies

### Wazuh Query

```kql
data.win.eventdata.Image: "schtasks.exe" OR data.win.eventdata.Image: "sc.exe"

### Splunk Query

index=windows EventCode=4688 NewProcessName="*schtasks.exe*" OR NewProcessName="*sc.exe*"

## Logs

### Wazuh

{
  "timestamp": "2024-05-28T14:12:00Z",
  "Image": "C:\\Windows\\System32\\schtasks.exe",
  "CommandLine": "schtasks /create /tn backdoor /tr C:\\malicious.exe /sc minute",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "EventID": "4688",
  "User": "jdoe"
}

## MITRE ATT&CK Mapping

| Tactic      | Technique                       | ID    |
| ----------- | ------------------------------- | ----- |
| Persistence | Scheduled Task/Service Creation | T1131 |

## References

[MITRE ATT&CK: Scheduled Task/Job (T1131)](https://attack.mitre.org/techniques/T1131/)

[NIST 800-61: Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
