# Hunting Guide: System Service Discovery (T1136)

---

## Objective

Hunt for activity where attackers enumerate system services to identify potential targets for privilege escalation or lateral movement.

---

## Detection Hypothesis

"If an attacker enumerates system services, we expect to see commands like `sc query`, `Get-Service`, or WMI queries in the command line."

---

## Wazuh Query

```kql
data.win.eventdata.CommandLine: ("sc query" OR "Get-Service")
```
## Splunk Query

index=windows EventCode=4688 (CommandLine="*sc query*" OR CommandLine="*Get-Service*")

## Wazuh Log

{
  "timestamp": "2024-05-28T14:40:00Z",
  "Image": "C:\\Windows\\System32\\sc.exe",
  "CommandLine": "sc query",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "EventID": "4688",
  "User": "testuser"
}


## Hunting Steps

1. Run the queries in Wazuh and Splunk.

2. Filter for:

- Command lines containing sc query, Get-Service, or similar.

- Parent process anomalies (e.g., explorer.exe spawning service queries).

3. Correlate with user accounts and source IPs.

4. Investigate for subsequent lateral movement or privilege escalation attempts.

Why it Matters

1. Enumerating services helps attackers identify:

2. Running services that can be hijacked.

3. Privileged services for privilege escalation.

4. Potential persistence mechanisms.