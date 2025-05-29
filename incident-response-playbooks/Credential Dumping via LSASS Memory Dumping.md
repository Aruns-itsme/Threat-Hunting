# Incident Response Playbook: Credential Dumping (T1003.001)

---

## Incident Type

Credential Dumping via LSASS Memory Dumping

---

## Introduction

This playbook provides a structured response guide for detecting, containing, and mitigating **Credential Dumping** attacks using tools like **Mimikatz**.  
Aligned with **NIST SP 800-61 Rev.2** and **MITRE ATT&CK** (T1003.001), it ensures effective detection, response, and recovery.  
Credential Dumping enables attackers to extract user credentials from system memory (LSASS) for lateral movement and privilege escalation.

---

## Summary

This playbook outlines response steps to:

- Detect Credential Dumping activity in Wazuh and Splunk
- Contain and eradicate the threat
- Recover systems and validate remediation
- Conduct post-incident review and lessons learned

This playbook assumes you have the **SIEM Threat Detection Lab** deployed (Project 1) and **Wazuh/Splunk detection rules** configured.

---

## Incident Response Process

---

### Part 1: Acquire, Preserve, Document Evidence

✅ **Sources of Detection**:
- Wazuh Alerts (Sysmon Event ID 10, 4688)
- Splunk Logs (Mimikatz execution, LSASS access)
- GuardDuty, Security Hub (if available)

✅ **Steps**:
1. Confirm alerts:
   - Wazuh: `data.win.eventdata.Image: "mimikatz.exe"`
   - Splunk: `CommandLine="*sekurlsa::logonpasswords*"`
2. Correlate with **user** (`Administrator`, `jdoe`) and **source IP** (`192.168.56.101`).
3. Document logs, screenshots, and findings:
   - Command executed
   - Parent process (e.g., `cmd.exe`, `explorer.exe`)
   - User and timestamp
4. Preserve:
   - Wazuh alerts JSON
   - Splunk CSV export
   - System memory dump (if available)

---

### Part 2: Contain the Incident

✅ Isolate affected system:
- Quarantine endpoint via EDR
- Remove from network (disable NIC)

✅ Terminate malicious processes:
- `mimikatz.exe`, suspicious PowerShell sessions

✅ Disable compromised accounts:
- Lock/reset user passwords
- Revoke access keys or tokens

✅ Block known IOCs:
- Binary hashes, file names, IPs

---

### Part 3: Eradicate the Incident

✅ Remove Mimikatz binaries:
- Search for `mimikatz.exe` and variants across systems.

✅ Clean registry entries, startup folders, and scheduled tasks.

✅ Reset credentials:
- Domain admin accounts
- Local admin accounts
- Service accounts

✅ Harden LSASS:
- Enable **LSASS Protection** (`RunAsPPL`)
- Consider **Credential Guard** (Windows Defender)

---

### Part 4: Recover from the Incident

✅ Restore system integrity:
- Confirm no backdoors, persistence mechanisms remain.
- Validate restored system logs show no anomalous activity.

✅ Re-enable network access:
- After successful scans and verification.

✅ Monitor:
- Re-enable Wazuh/Splunk alerts.
- Set up **auto-escalation** for future detections.

---

### Part 5: Post-Incident Activity

✅ Conduct **post-mortem** with stakeholders:
- SOC, IT, Legal, Management

✅ Lessons learned:
- Detection gaps (e.g., missed obfuscated commands)
- Response efficiency

✅ Update:
- Detection rules (e.g., PowerShell EncodedCommand detection)
- IR documentation (this playbook!)
- Training materials

✅ Report:
- External obligations (e.g., regulatory)
- Internal summaries for leadership

---

## Detection Strategies

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "mimikatz.exe"
OR data.win.eventdata.CommandLine: "*sekurlsa::logonpasswords*"



## Splunk Query

index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
(EventCode="10" AND TargetImage="*lsass.exe*")
OR (EventCode="4688" AND NewProcessName="*mimikatz.exe*")

## Wazuh Log

{
  "timestamp": "2024-05-28T14:00:00Z",
  "Image": "C:\\Users\\Public\\mimikatz\\mimikatz.exe",
  "CommandLine": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "EventID": "10",
  "User": "Administrator",
  "Location": "C:\\Users\\Public\\mimikatz\\mimikatz.exe"
}

MITRE ATT&CK Mapping

| Tactic            | Technique            | ID        |
| ----------------- | -------------------- | --------- |
| Credential Access | LSASS Memory Dumping | T1003.001 |

## References

[MITRE ATT&CK: Credential Dumping (T1003)](https://attack.mitre.org/techniques/T1003/)

[NIST 800-61: Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)

[Microsoft: LSASS Protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management)


