# Hunting Guide: Data from Information Repositories (T1145)

---

## Objective

Hunt for attackers accessing data from repositories like databases, SharePoint, or document management systems.

---

## Detection Hypothesis

"If an attacker extracts data from information repositories, we expect to see SQL queries, access to SharePoint URLs, or file repository access events in logs."

---

## Wazuh Query

```kql
data.win.eventdata.ObjectName: "*\\database*" OR data.win.eventdata.ObjectName: "*\\sharepoint*"

## Splunk Query

index=windows (EventCode=4624 OR EventCode=4663) ObjectName="*\\database*" OR ObjectName="*\\sharepoint*"

## Wazuh Log

{
  "timestamp": "2024-05-28T15:20:00Z",
  "Image": "C:\\Windows\\System32\\sqlcmd.exe",
  "CommandLine": "sqlcmd -S dbserver -Q \"SELECT * FROM Customers\"",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "EventID": "4624",
  "User": "svc-dba",
  "Source_Network_Address": "192.168.56.110"
}

## Hunting Steps

1. Search for access to information repositories (sqlcmd.exe, SharePoint URLs).

2. Correlate with:

- User accounts performing access.

- Source IPs and parent processes.

3. Investigate:

- Unusual data queries or bulk access patterns.

- Access from non-standard locations.

## Why it Matters

Accessing data from information repositories is a high-value attacker activity, enabling data theft, espionage, and business impact.



