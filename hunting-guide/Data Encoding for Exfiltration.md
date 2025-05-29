# Hunting Guide: Data Encoding for Exfiltration (T1132)

---

## Objective

Hunt for Base64 or other encoding usage in commands for obfuscation or exfiltration purposes.

---

## Detection Hypothesis

"If an attacker encodes data for exfiltration, we expect to see Base64-encoded strings in command-line arguments or PowerShell commands."

---

## Wazuh Query

```kql
data.win.eventdata.CommandLine: "*EncodedCommand*" OR data.win.eventdata.CommandLine: "*Base64*"

## Splunk Query

index=windows EventCode=4104 CommandLine="*EncodedCommand*" OR CommandLine="*Base64*"

## Wazuh Log

{
  "timestamp": "2024-05-28T14:18:00Z",
  "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "CommandLine": "powershell.exe -EncodedCommand SQBFAFgA",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "User": "Administrator",
  "EventID": "4104"
}


## Hunting Steps

1. Search for -EncodedCommand or long Base64 strings in command lines.

2. Review related processes and parent-child relationships.

3. Correlate with user accounts and IP addresses.

4. Look for data staging or large file transfers.


## Why it Matters

Encoding enables attackers to bypass detection and exfiltrate data stealthily.
