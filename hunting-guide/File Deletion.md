# Hunting Guide: File Deletion (T1144)

---

## Objective

Hunt for attackers deleting files to hide evidence, disrupt systems, or conduct anti-forensics.

---

## Detection Hypothesis

"If an attacker deletes files, we expect to see EventCode 4663 with delete access and command lines like `del`, `erase`, or PowerShell `Remove-Item`."

---

## Wazuh Query

```kql
data.win.system.eventID: "4663" AND data.win.eventdata.AccessMask: "0x10000"

## Splunk Query

index=windows EventCode=4663 AccessMask=0x10000

## Wazuh Log

{
  "timestamp": "2024-05-28T15:15:00Z",
  "Image": "C:\\Windows\\System32\\cmd.exe",
  "CommandLine": "cmd.exe /c del C:\\Sensitive\\file.txt",
  "ParentImage": "C:\\Windows\\System32\\explorer.exe",
  "EventID": "4663",
  "User": "jdoe"
}

## Hunting Steps

1. Search for delete operations in logs (AccessMask 0x10000, del, erase).

2. Correlate:

- User accounts involved in deletions.

- Sensitive file paths (e.g., C:\Sensitive\, C:\Temp\Logs\).

3. Investigate:

- Frequency and pattern of deletions.

- Possible anti-forensic behavior.

## Why it Matters

File deletion is a common anti-forensics technique used to hide malicious activity, erase logs, and disrupt investigations.