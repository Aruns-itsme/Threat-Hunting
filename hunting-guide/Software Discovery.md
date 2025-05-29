# Hunting Guide: Software Discovery (T1141)

---

## Objective

Hunt for activity where attackers enumerate installed software to identify exploitable applications or weaknesses.

---

## Detection Hypothesis

"If an attacker enumerates installed software, we expect to see commands like `wmic product get`, `Get-WmiObject`, or `Get-Package` in command lines."

---

## Wazuh Query

```kql
data.win.eventdata.CommandLine: ("wmic product" OR "Get-WmiObject" OR "Get-Package")

## Splunk Query

index=windows EventCode=4688 (CommandLine="*wmic product*" OR CommandLine="*Get-WmiObject*" OR CommandLine="*Get-Package*")

## Wazuh Log

{
  "timestamp": "2024-05-28T15:00:00Z",
  "Image": "C:\\Windows\\System32\\wmic.exe",
  "CommandLine": "wmic product get name",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "EventID": "4688",
  "User": "jdoe"
}


## Hunting Steps

1. Search for execution of software discovery commands.

2. Filter by:

- User accounts performing enumeration.

- Parent processes like cmd.exe or powershell.exe.

3. Correlate with:

- Privilege escalation attempts.

- Application installation patterns.

4. Check for lateral movement activity post-discovery.

## Why it Matters

Software discovery helps attackers identify vulnerable software, outdated apps, or high-value targets for exploitation.

