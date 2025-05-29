# Hunting Guide: System Information Discovery (T1142)

---

## Objective

Hunt for attacker activity aimed at collecting system information like OS version, hostname, hardware details, or architecture.

---

## Detection Hypothesis

"If an attacker gathers system information, we expect to see commands like `systeminfo`, `hostname`, or `Get-ComputerInfo` in logs."

---

## Wazuh Query

```kql
data.win.eventdata.CommandLine: ("systeminfo" OR "hostname" OR "Get-ComputerInfo")

## Splunk Query

index=windows EventCode=4688 (CommandLine="*systeminfo*" OR CommandLine="*hostname*" OR CommandLine="*Get-ComputerInfo*")

## Wazuh Log

{
  "timestamp": "2024-05-28T15:05:00Z",
  "Image": "C:\\Windows\\System32\\systeminfo.exe",
  "CommandLine": "systeminfo",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "EventID": "4688",
  "User": "svc-account"
}

## Hunting Steps

1. Run the queries in Wazuh and Splunk.

2. Filter for:

- User accounts executing systeminfo, hostname, Get-ComputerInfo.

- Unusual parent processes or high-privilege accounts.

3. Investigate:

- Follow-on privilege escalation or lateral movement activity.

- Repeated information gathering attempts.

## Why it Matters

System Information Discovery helps attackers profile the environment, identify potential weaknesses, and plan further attacks.