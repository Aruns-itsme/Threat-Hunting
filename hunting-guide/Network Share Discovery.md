# Hunting Guide: Network Share Discovery (T1138)

---

## Objective

Hunt for activity where attackers enumerate accessible network shares to identify targets for lateral movement or data theft.

---

## Detection Hypothesis

"If an attacker enumerates network shares, we expect to see commands like `net view`, `net share`, or PowerShell commands querying SMB shares."

---

## Wazuh Query

```kql
data.win.eventdata.CommandLine: ("net view" OR "net share")
```
## Splunk Query

index=windows EventCode=4688 (CommandLine="*net view*" OR CommandLine="*net share*")

## Wazuh Log

{
  "timestamp": "2024-05-28T14:48:00Z",
  "Image": "C:\\Windows\\System32\\net.exe",
  "CommandLine": "net view",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "EventID": "4688",
  "User": "svc-account"
}

## Hunting Steps

1. Search for command lines containing net view, net share, or PowerShell SMB queries.

2. Correlate results with:

- User accounts and source IPs.

- Parent processes and command execution context.

3. Investigate for subsequent file access or data staging.

## Why it Matters

Network share discovery allows attackers to map accessible resources for lateral movement, data theft, and privilege escalation. 