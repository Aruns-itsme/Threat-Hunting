# Hunting Guide: External Remote Services (T1133)

---

## Objective

Hunt for suspicious use of external remote services like RDP or SSH, which attackers use for lateral movement or persistence.

---

## Detection Hypothesis

"If an attacker uses external remote services, we expect to see EventCodes 4624/4625 (Logon Type 10) and usage of remote tools like `mstsc.exe`."

---

## Wazuh Query

```kql
data.win.system.eventID: ("4624" OR "4625") AND data.win.eventdata.LogonType: "10"

## Splunk Query

index=windows (EventCode="4624" OR EventCode="4625") LogonType="10"

## Wazuh Log

{
  "timestamp": "2024-05-28T14:24:00Z",
  "Image": "C:\\Windows\\System32\\mstsc.exe",
  "CommandLine": "mstsc.exe /v:192.168.56.102",
  "ParentImage": "C:\\Windows\\explorer.exe",
  "EventID": "4624",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.102"
}

## Hunting Steps

1. Search for LogonType 10 events (remote interactive logons).

2. Correlate with source IPs, users, and tools like mstsc.exe, ssh.exe.

3. Check for lateral movement or privilege escalation patterns.

## Why it Matters

External remote services can enable stealthy access to systems and facilitate data exfiltration.




