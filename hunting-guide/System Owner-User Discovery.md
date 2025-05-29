# Hunting Guide: System Owner/User Discovery (T1140)

---

## Objective

Hunt for evidence of attackers enumerating system users and owners to identify targets for privilege escalation.

---

## Detection Hypothesis

"If an attacker enumerates system users, we expect to see commands like `whoami`, `net user`, or `Get-LocalUser` in logs."

---

## Wazuh Query

```kql
data.win.eventdata.CommandLine: ("whoami" OR "net user" OR "Get-LocalUser")
```
## Splunk Query

index=windows EventCode=4688 (CommandLine="*whoami*" OR CommandLine="*net user*" OR CommandLine="*Get-LocalUser*")

## Wazuh Log

{
  "timestamp": "2024-05-28T14:55:00Z",
  "Image": "C:\\Windows\\System32\\cmd.exe",
  "CommandLine": "cmd.exe /c net user",
  "ParentImage": "C:\\Windows\\System32\\explorer.exe",
  "EventID": "4688",
  "User": "testuser"
}

## Hunting Steps

1. Search for commands like whoami, net user, or Get-LocalUser.

2. Correlate with:

- User accounts and source IPs.

- Parent processes (e.g., cmd.exe or powershell.exe).

3. Investigate subsequent privilege escalation or lateral movement.

## Why it Matters

User enumeration enables attackers to identify privileged accounts and plan further compromise activities.

