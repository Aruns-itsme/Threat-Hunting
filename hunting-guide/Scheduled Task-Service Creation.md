# Hunting Guide: Scheduled Task/Service Creation (T1131)

---

## Objective

Hunt for malicious creation of scheduled tasks or services, which attackers use for persistence and execution of malicious binaries.

---

## Detection Hypothesis

"If an attacker creates a scheduled task or service, we expect to see command-line arguments involving `schtasks.exe` or `sc.exe` with suspicious task names or binary paths."

---

## Wazuh Query

```kql
data.win.eventdata.CommandLine: ("schtasks.exe /create" OR "sc.exe create")

## Splunk Query

index=windows EventCode=4688 (NewProcessName="*schtasks.exe*" OR NewProcessName="*sc.exe*")

## Wazuh Log

{
  "timestamp": "2024-05-28T14:12:00Z",
  "Image": "C:\\Windows\\System32\\schtasks.exe",
  "CommandLine": "schtasks /create /tn backdoor /tr C:\\malicious.exe /sc minute",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "User": "jdoe",
  "EventID": "4688"
}

## Hunting Steps

1. Run the Wazuh and Splunk queries.

2. Filter for:

- Suspicious task names (backdoor, update, etc.)

- Binary paths in non-standard locations (e.g., C:\Users\Public\)

3. Correlate with user accounts, IP addresses, and parent processes.

4. Check for related file creations or command executions.

## Why it Matters

Scheduled tasks enable persistent code execution and can be used to maintain access, deploy malware, or exfiltrate data.



