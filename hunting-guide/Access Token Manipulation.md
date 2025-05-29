# Hunting Guide: Access Token Manipulation (T1134)

---

## Objective

Hunt for evidence of attackers using access token manipulation techniques (e.g., `CreateProcessWithTokenW`, `ImpersonateLoggedOnUser`) to escalate privileges or impersonate users.

---

## Detection Hypothesis

"If an attacker manipulates access tokens, we expect to see specific API calls, anomalous LogonType values (9, 11), and processes launched under different user contexts."

---

## Wazuh Query

```kql
data.win.system.eventID: "4624" AND data.win.eventdata.LogonType: ("9" OR "11")
```
## Splunk Query

index=windows EventCode=4624 (LogonType="9" OR LogonType="11")

## Wazuh Log

{
  "timestamp": "2024-05-28T14:32:00Z",
  "Image": "C:\\Windows\\System32\\cmd.exe",
  "CommandLine": "cmd.exe /c whoami",
  "ParentImage": "C:\\Windows\\System32\\services.exe",
  "EventID": "4624",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.103"
}


## Hunting Steps

1. Search for LogonType 9 (NewCredentials) and 11 (CachedInteractive).

2. Correlate with processes launched under unusual user contexts (e.g., svc-account spawning cmd.exe).

3. Investigate lateral movement patterns or privilege escalation.

4. Check for related tools like PsExec or token abuse scripts.

## Why it Matters

Access Token Manipulation allows attackers to bypass security controls, escalate privileges, and persist undetected within networks.

