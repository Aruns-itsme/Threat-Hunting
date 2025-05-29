# Hunting Guide: File and Directory Discovery (T1139)

---

## Objective

Hunt for evidence of attackers listing files and directories to identify sensitive data or targets.

---

## Detection Hypothesis

"If an attacker enumerates files and directories, we expect to see commands like `dir`, `tree`, or `Get-ChildItem` in command lines."

---

## Wazuh Query

```kql
data.win.eventdata.CommandLine: ("dir" OR "tree" OR "Get-ChildItem")
```
## Splunk Query

index=windows EventCode=4688 (CommandLine="*dir*" OR CommandLine="*tree*" OR CommandLine="*Get-ChildItem*")

## Wazuh Log

{
  "timestamp": "2024-05-28T14:52:00Z",
  "Image": "C:\\Windows\\System32\\cmd.exe",
  "CommandLine": "cmd.exe /c dir /s C:\\Users",
  "ParentImage": "C:\\Windows\\System32\\explorer.exe",
  "EventID": "4688",
  "User": "jdoe"
}

## Hunting Steps

1. Search for file enumeration commands (dir, tree, Get-ChildItem).

2. Correlate with:

- User accounts and source IPs.

- Parent-child process chains.

3. Check for concurrent data exfiltration or staging activity.

## Why it Matters

File and directory discovery helps attackers locate sensitive data, staging areas, and potential attack vectors.

