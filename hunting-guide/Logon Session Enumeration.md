# Hunting Guide: Logon Session Enumeration (T1135)

---

## Objective

Hunt for attackers enumerating logon sessions using commands like `query user`, `qwinsta`, or `tasklist /v` to identify active users and sessions.

---

## Detection Hypothesis

"If an attacker enumerates logon sessions, we expect to see specific command-line activity related to session listing commands."

---

## Wazuh Query

```kql
data.win.eventdata.CommandLine: ("query user" OR "qwinsta" OR "tasklist /v")

## Splunk Query

index=windows EventCode=4688 (CommandLine="*query user*" OR CommandLine="*qwinsta*" OR CommandLine="*tasklist /v*")

## Wazuh Log

{
  "timestamp": "2024-05-28T14:36:00Z",
  "Image": "C:\\Windows\\System32\\cmd.exe",
  "CommandLine": "cmd.exe /c query user",
  "ParentImage": "C:\\Windows\\System32\\explorer.exe",
  "EventID": "4688",
  "User": "jdoe"
}


## Hunting Steps

1. Search for execution of query user, qwinsta, and tasklist /v.

2. Review parent-child relationships of processes (e.g., explorer.exe spawning enumeration commands).

3. Correlate with user accounts and source IPs.

4. Look for concurrent lateral movement or privilege escalation events.

## Why it Matters

Logon session enumeration enables attackers to identify active users for lateral movement, privilege escalation, and further attacks.