# Incident Response Playbook: Network Sniffing (T1143)

---

## Incident Type

Capturing network traffic to obtain sensitive information such as credentials, session tokens, or confidential data.

---

## Introduction

This playbook covers detection and response for **Network Sniffing** (MITRE T1143), where attackers use tools like `Wireshark`, `tcpdump`, or custom scripts to capture and analyze network traffic.  
Aligned with [NIST 800-61](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) and [MITRE ATT&CK: Network Sniffing (T1143)](https://attack.mitre.org/techniques/T1143/).

---

## Summary

Steps to:

- Detect packet capture tools and suspicious processes.
- Contain affected systems.
- Remove sniffing tools and backdoors.
- Harden network monitoring configurations.

---

## Incident Response Process

### Part 1: Acquire, Preserve, Document Evidence

Collect:

- Wazuh/Splunk logs for tools like `Wireshark`, `tcpdump`, `pcap`.
- User accounts, process IDs, and timestamps.
- Network device logs for abnormal traffic.

---

### Part 2: Contain the Incident

Actions:

- Quarantine the sniffing host.
- Terminate packet capture processes.
- Revoke access tokens for suspicious accounts.

---

### Part 3: Eradicate the Incident

Steps:

- Delete sniffing tools and dump files.
- Reset credentials for affected accounts.
- Validate NIC configurations (disable promiscuous mode).

---

### Part 4: Recover from the Incident

Steps:

- Restore network monitoring baselines.
- Enable detection of sniffing activity.
- Reconnect systems post-validation.

---

### Part 5: Post-Incident Activity

Review:

- Detection logic for sniffing tools.
- Network monitoring policies.
- SOC awareness on packet capture risks.

---

## Detection Strategies

### Wazuh Query

```kql
data.win.eventdata.CommandLine: ("wireshark" OR "tcpdump" OR "*.pcap")

### Splunk Query

index=windows EventCode=4688 (CommandLine="*wireshark*" OR CommandLine="*tcpdump*" OR CommandLine="*.pcap*")

## Wazuh Logs

{
  "timestamp": "2024-05-28T15:10:00Z",
  "Image": "C:\\Program Files\\Wireshark\\Wireshark.exe",
  "CommandLine": "Wireshark.exe",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "EventID": "4688",
  "User": "jdoe"
}

## MITRE ATT&CK Mapping

| Tactic            | Technique        | ID    |
| ----------------- | ---------------- | ----- |
| Credential Access | Network Sniffing | T1143 |
