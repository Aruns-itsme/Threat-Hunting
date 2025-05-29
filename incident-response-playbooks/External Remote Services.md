# Incident Response Playbook: External Remote Services (T1133)

---

## Incident Type

Unauthorized access to systems using external remote services (e.g., RDP, SSH, SMB).

---

## Introduction

This playbook outlines response actions for **External Remote Services** attacks (MITRE T1133).  
Attackers exploit remote services to access target systems from external networks, enabling lateral movement, data exfiltration, and persistence.  
This guide aligns with [NIST 800-61](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) and [MITRE ATT&CK: External Remote Services (T1133)](https://attack.mitre.org/techniques/T1133/).

---

## Summary

This playbook provides steps to:

- Detect external remote access attempts via logs.
- Contain compromised endpoints.
- Eradicate unauthorized accounts and services.
- Recover and secure systems.

---

## Incident Response Process

### Part 1: Acquire, Preserve, Document Evidence

Collect:

- Logs of RDP/SSH/SMB activity.
- Wazuh and Splunk alerts for EventID 4624/4625, 3 (network connection).
- User accounts, source IPs, timestamps.

---

### Part 2: Contain the Incident

Actions:

- Quarantine affected endpoints.
- Disable accounts involved in unauthorized access.
- Block source IPs at the firewall or network edge.

---

### Part 3: Eradicate the Incident

Steps:

- Remove unauthorized users/groups.
- Review and revoke external access policies (VPN, RDP).
- Reset affected user credentials.
- Implement IP whitelisting for critical systems.

---

### Part 4: Recover from the Incident

Steps:

- Validate logs for residual unauthorized activity.
- Harden remote access protocols (enable MFA, restrict ports).
- Restore legitimate access under strict access controls.

---

### Part 5: Post-Incident Activity

Review and update:

- Remote access policies and detection rules.
- Network segmentation and firewall configurations.
- Training for users and admins on secure remote access.

---

## Detection Strategies

### Wazuh Query

```kql
data.win.system.eventID: ("4624" OR "4625" OR "3") AND data.win.eventdata.LogonType: "10"
```
### Splunk Query

index=windows (EventCode="4624" OR EventCode="4625" OR EventCode="3") LogonType="10"

## Logs

{
  "timestamp": "2024-05-28T14:24:00Z",
  "Image": "C:\\Windows\\System32\\mstsc.exe",
  "CommandLine": "mstsc.exe /v:192.168.56.102",
  "ParentImage": "C:\\Windows\\explorer.exe",
  "EventID": "4624",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.102"
}

## MITRE ATT&CK Mapping

| Tactic                        | Technique                | ID    |
| ----------------------------- | ------------------------ | ----- |
| Persistence, Lateral Movement | External Remote Services | T1133 |
