# Hunting Guide: Application Window Discovery (T1137)

---

## Objective

Hunt for evidence of attackers enumerating application windows to identify running applications and potential targets.

---

## Detection Hypothesis

"If an attacker uses application window discovery, we expect to see commands like `tasklist /v`, `Get-Process`, or custom window enumeration scripts."

---

## Wazuh Query

```kql
data.win.eventdata.CommandLine: ("tasklist /v" OR "Get-Process")

## Splunk Query

index=windows EventCode=4688 (CommandLine="*tasklist /v*" OR CommandLine="*Get-Process*")

## Wazuh Log

{
  "timestamp": "2024-05-28T14:44:00Z",
  "Image": "C:\\Windows\\System32\\tasklist.exe",
  "CommandLine": "tasklist /v",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "EventID": "4688",
  "User": "Administrator"
}

## Hunting Steps

1. Search for command-line activity containing tasklist /v or Get-Process.

2. Correlate results with:

- User accounts performing enumeration.

- Parent process context (e.g., cmd.exe or explorer.exe).

3. Investigate for follow-on discovery or lateral movement actions.

## Why it Matters

Application Window Discovery enables attackers to identify running software, potentially revealing sensitive applications or targets for exploitation.