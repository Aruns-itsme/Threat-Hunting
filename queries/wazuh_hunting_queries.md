# Wazuh Threat Hunting Queries


## T1131 - Suspicious activity detected related to T1131

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\tasklist.exe"
OR data.win.eventdata.CommandLine: "tasklist /v --session 0"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\lsass.exe"
OR data.win.system.eventID: "3"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:00:00Z",
  "Image": "C:\Windows\System32\tasklist.exe",
  "CommandLine": "tasklist /v --session 0",
  "ParentImage": "C:\Windows\System32\lsass.exe",
  "EventID": "3",
  "User": "jdoe",
  "Location": "C:\Users\SYSTEM\tasklist.exe"
}
```

---


## T1132 - Suspicious activity detected related to T1132

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\cmd.exe"
OR data.win.eventdata.CommandLine: "cmd.exe /c whoami"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\explorer.exe"
OR data.win.system.eventID: "4104"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:01:00Z",
  "Image": "C:\Windows\System32\cmd.exe",
  "CommandLine": "cmd.exe /c whoami",
  "ParentImage": "C:\Windows\System32\explorer.exe",
  "EventID": "4104",
  "User": "Administrator",
  "Location": "C:\Users\svc-account\cmd.exe"
}
```

---


## T1133 - Suspicious activity detected related to T1133

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\tasklist.exe"
OR data.win.eventdata.CommandLine: "tasklist /v --session 2"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\lsass.exe"
OR data.win.system.eventID: "4688"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:02:00Z",
  "Image": "C:\Windows\System32\tasklist.exe",
  "CommandLine": "tasklist /v --session 2",
  "ParentImage": "C:\Windows\System32\lsass.exe",
  "EventID": "4688",
  "User": "SYSTEM",
  "Location": "C:\Users\jdoe\tasklist.exe"
}
```

---


## T1134 - Suspicious activity detected related to T1134

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\net.exe"
OR data.win.eventdata.CommandLine: "net localgroup administrators"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\svchost.exe"
OR data.win.system.eventID: "4663"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:03:00Z",
  "Image": "C:\Windows\System32\net.exe",
  "CommandLine": "net localgroup administrators",
  "ParentImage": "C:\Windows\System32\svchost.exe",
  "EventID": "4663",
  "User": "SYSTEM",
  "Location": "C:\Users\testuser\net.exe"
}
```

---


## T1135 - Suspicious activity detected related to T1135

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\tasklist.exe"
OR data.win.eventdata.CommandLine: "tasklist /v --session 4"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\explorer.exe"
OR data.win.system.eventID: "4104"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:04:00Z",
  "Image": "C:\Windows\System32\tasklist.exe",
  "CommandLine": "tasklist /v --session 4",
  "ParentImage": "C:\Windows\System32\explorer.exe",
  "EventID": "4104",
  "User": "svc-account",
  "Location": "C:\Users\svc-account\tasklist.exe"
}
```

---


## T1136 - Suspicious activity detected related to T1136

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\net.exe"
OR data.win.eventdata.CommandLine: "net localgroup administrators --session 5"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\taskhostw.exe"
OR data.win.system.eventID: "4663"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:05:00Z",
  "Image": "C:\Windows\System32\net.exe",
  "CommandLine": "net localgroup administrators --session 5",
  "ParentImage": "C:\Windows\System32\taskhostw.exe",
  "EventID": "4663",
  "User": "jdoe",
  "Location": "C:\Users\jdoe\net.exe"
}
```

---


## T1137 - Suspicious activity detected related to T1137

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\net.exe"
OR data.win.eventdata.CommandLine: "net localgroup administrators"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\wininit.exe"
OR data.win.system.eventID: "4663"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:06:00Z",
  "Image": "C:\Windows\System32\net.exe",
  "CommandLine": "net localgroup administrators",
  "ParentImage": "C:\Windows\System32\wininit.exe",
  "EventID": "4663",
  "User": "Administrator",
  "Location": "C:\Users\SYSTEM\net.exe"
}
```

---


## T1138 - Suspicious activity detected related to T1138

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\tasklist.exe"
OR data.win.eventdata.CommandLine: "tasklist /v"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\smss.exe"
OR data.win.system.eventID: "1102"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:07:00Z",
  "Image": "C:\Windows\System32\tasklist.exe",
  "CommandLine": "tasklist /v",
  "ParentImage": "C:\Windows\System32\smss.exe",
  "EventID": "1102",
  "User": "testuser",
  "Location": "C:\Users\SYSTEM\tasklist.exe"
}
```

---


## T1139 - Suspicious activity detected related to T1139

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\tasklist.exe"
OR data.win.eventdata.CommandLine: "tasklist /v --session 8"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\explorer.exe"
OR data.win.system.eventID: "1102"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:08:00Z",
  "Image": "C:\Windows\System32\tasklist.exe",
  "CommandLine": "tasklist /v --session 8",
  "ParentImage": "C:\Windows\System32\explorer.exe",
  "EventID": "1102",
  "User": "SYSTEM",
  "Location": "C:\Users\testuser\tasklist.exe"
}
```

---


## T1140 - Obfuscated PowerShell Script Execution

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
OR data.win.eventdata.CommandLine: "powershell.exe -enc SQBFAFgA --session 9"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\lsass.exe"
OR data.win.system.eventID: "4625"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:09:00Z",
  "Image": "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
  "CommandLine": "powershell.exe -enc SQBFAFgA --session 9",
  "ParentImage": "C:\Windows\System32\lsass.exe",
  "EventID": "4625",
  "User": "testuser",
  "Location": "C:\Users\svc-account\WindowsPowerShell\v1.0\powershell.exe"
}
```

---


## T1141 - Suspicious activity detected related to T1141

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\net.exe"
OR data.win.eventdata.CommandLine: "net localgroup administrators --session 10"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\svchost.exe"
OR data.win.system.eventID: "4104"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:10:00Z",
  "Image": "C:\Windows\System32\net.exe",
  "CommandLine": "net localgroup administrators --session 10",
  "ParentImage": "C:\Windows\System32\svchost.exe",
  "EventID": "4104",
  "User": "SYSTEM",
  "Location": "C:\Users\SYSTEM\net.exe"
}
```

---


## T1142 - Suspicious activity detected related to T1142

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\net.exe"
OR data.win.eventdata.CommandLine: "net localgroup administrators"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\smss.exe"
OR data.win.system.eventID: "4663"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:11:00Z",
  "Image": "C:\Windows\System32\net.exe",
  "CommandLine": "net localgroup administrators",
  "ParentImage": "C:\Windows\System32\smss.exe",
  "EventID": "4663",
  "User": "testuser",
  "Location": "C:\Users\testuser\net.exe"
}
```

---


## T1143 - Suspicious activity detected related to T1143

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\schtasks.exe"
OR data.win.eventdata.CommandLine: "schtasks /create /tn backdoor /tr cmd.exe /sc minute"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\smss.exe"
OR data.win.system.eventID: "4624"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:12:00Z",
  "Image": "C:\Windows\System32\schtasks.exe",
  "CommandLine": "schtasks /create /tn backdoor /tr cmd.exe /sc minute",
  "ParentImage": "C:\Windows\System32\smss.exe",
  "EventID": "4624",
  "User": "jdoe",
  "Location": "C:\Users\testuser\schtasks.exe"
}
```

---


## T1144 - Suspicious activity detected related to T1144

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\tasklist.exe"
OR data.win.eventdata.CommandLine: "tasklist /v --session 13"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\wininit.exe"
OR data.win.system.eventID: "4625"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:13:00Z",
  "Image": "C:\Windows\System32\tasklist.exe",
  "CommandLine": "tasklist /v --session 13",
  "ParentImage": "C:\Windows\System32\wininit.exe",
  "EventID": "4625",
  "User": "jdoe",
  "Location": "C:\Users\SYSTEM\tasklist.exe"
}
```

---


## T1145 - Suspicious activity detected related to T1145

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\net.exe"
OR data.win.eventdata.CommandLine: "net localgroup administrators --session 14"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\wininit.exe"
OR data.win.system.eventID: "4663"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:14:00Z",
  "Image": "C:\Windows\System32\net.exe",
  "CommandLine": "net localgroup administrators --session 14",
  "ParentImage": "C:\Windows\System32\wininit.exe",
  "EventID": "4663",
  "User": "SYSTEM",
  "Location": "C:\Users\testuser\net.exe"
}
```

---


## T1146 - Suspicious activity detected related to T1146

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\tasklist.exe"
OR data.win.eventdata.CommandLine: "tasklist /v --session 15"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\lsass.exe"
OR data.win.system.eventID: "4663"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:15:00Z",
  "Image": "C:\Windows\System32\tasklist.exe",
  "CommandLine": "tasklist /v --session 15",
  "ParentImage": "C:\Windows\System32\lsass.exe",
  "EventID": "4663",
  "User": "testuser",
  "Location": "C:\Users\SYSTEM\tasklist.exe"
}
```

---


## T1147 - Suspicious activity detected related to T1147

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\cmd.exe"
OR data.win.eventdata.CommandLine: "cmd.exe /c whoami"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\svchost.exe"
OR data.win.system.eventID: "3"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:16:00Z",
  "Image": "C:\Windows\System32\cmd.exe",
  "CommandLine": "cmd.exe /c whoami",
  "ParentImage": "C:\Windows\System32\svchost.exe",
  "EventID": "3",
  "User": "svc-account",
  "Location": "C:\Users\jdoe\cmd.exe"
}
```

---


## T1148 - Suspicious activity detected related to T1148

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\net.exe"
OR data.win.eventdata.CommandLine: "net localgroup administrators"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\wininit.exe"
OR data.win.system.eventID: "4625"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:17:00Z",
  "Image": "C:\Windows\System32\net.exe",
  "CommandLine": "net localgroup administrators",
  "ParentImage": "C:\Windows\System32\wininit.exe",
  "EventID": "4625",
  "User": "SYSTEM",
  "Location": "C:\Users\svc-account\net.exe"
}
```

---


## T1149 - Suspicious activity detected related to T1149

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\schtasks.exe"
OR data.win.eventdata.CommandLine: "schtasks /create /tn backdoor /tr cmd.exe /sc minute"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\services.exe"
OR data.win.system.eventID: "3"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:18:00Z",
  "Image": "C:\Windows\System32\schtasks.exe",
  "CommandLine": "schtasks /create /tn backdoor /tr cmd.exe /sc minute",
  "ParentImage": "C:\Windows\System32\services.exe",
  "EventID": "3",
  "User": "testuser",
  "Location": "C:\Users\jdoe\schtasks.exe"
}
```

---


## T1150 - Suspicious activity detected related to T1150

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\cmd.exe"
OR data.win.eventdata.CommandLine: "cmd.exe /c whoami --session 19"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\wininit.exe"
OR data.win.system.eventID: "1102"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:19:00Z",
  "Image": "C:\Windows\System32\cmd.exe",
  "CommandLine": "cmd.exe /c whoami --session 19",
  "ParentImage": "C:\Windows\System32\wininit.exe",
  "EventID": "1102",
  "User": "Administrator",
  "Location": "C:\Users\SYSTEM\cmd.exe"
}
```

---


## T1151 - Suspicious activity detected related to T1151

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\net.exe"
OR data.win.eventdata.CommandLine: "net localgroup administrators"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\explorer.exe"
OR data.win.system.eventID: "4663"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:20:00Z",
  "Image": "C:\Windows\System32\net.exe",
  "CommandLine": "net localgroup administrators",
  "ParentImage": "C:\Windows\System32\explorer.exe",
  "EventID": "4663",
  "User": "SYSTEM",
  "Location": "C:\Users\svc-account\net.exe"
}
```

---


## T1152 - Suspicious activity detected related to T1152

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\cmd.exe"
OR data.win.eventdata.CommandLine: "cmd.exe /c whoami --session 21"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\lsass.exe"
OR data.win.system.eventID: "4625"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:21:00Z",
  "Image": "C:\Windows\System32\cmd.exe",
  "CommandLine": "cmd.exe /c whoami --session 21",
  "ParentImage": "C:\Windows\System32\lsass.exe",
  "EventID": "4625",
  "User": "Administrator",
  "Location": "C:\Users\testuser\cmd.exe"
}
```

---


## T1153 - Suspicious activity detected related to T1153

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\net.exe"
OR data.win.eventdata.CommandLine: "net localgroup administrators --session 22"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\lsass.exe"
OR data.win.system.eventID: "1102"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:22:00Z",
  "Image": "C:\Windows\System32\net.exe",
  "CommandLine": "net localgroup administrators --session 22",
  "ParentImage": "C:\Windows\System32\lsass.exe",
  "EventID": "1102",
  "User": "svc-account",
  "Location": "C:\Users\testuser\net.exe"
}
```

---


## T1154 - Suspicious activity detected related to T1154

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\net.exe"
OR data.win.eventdata.CommandLine: "net localgroup administrators"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\taskhostw.exe"
OR data.win.system.eventID: "1102"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:23:00Z",
  "Image": "C:\Windows\System32\net.exe",
  "CommandLine": "net localgroup administrators",
  "ParentImage": "C:\Windows\System32\taskhostw.exe",
  "EventID": "1102",
  "User": "jdoe",
  "Location": "C:\Users\SYSTEM\net.exe"
}
```

---


## T1155 - Suspicious activity detected related to T1155

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\schtasks.exe"
OR data.win.eventdata.CommandLine: "schtasks /create /tn backdoor /tr cmd.exe /sc minute"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\explorer.exe"
OR data.win.system.eventID: "4663"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:24:00Z",
  "Image": "C:\Windows\System32\schtasks.exe",
  "CommandLine": "schtasks /create /tn backdoor /tr cmd.exe /sc minute",
  "ParentImage": "C:\Windows\System32\explorer.exe",
  "EventID": "4663",
  "User": "testuser",
  "Location": "C:\Users\testuser\schtasks.exe"
}
```

---


## T1156 - Suspicious activity detected related to T1156

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\cmd.exe"
OR data.win.eventdata.CommandLine: "cmd.exe /c whoami"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\lsass.exe"
OR data.win.system.eventID: "1102"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:25:00Z",
  "Image": "C:\Windows\System32\cmd.exe",
  "CommandLine": "cmd.exe /c whoami",
  "ParentImage": "C:\Windows\System32\lsass.exe",
  "EventID": "1102",
  "User": "SYSTEM",
  "Location": "C:\Users\jdoe\cmd.exe"
}
```

---


## T1157 - Suspicious activity detected related to T1157

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\cmd.exe"
OR data.win.eventdata.CommandLine: "cmd.exe /c whoami"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\smss.exe"
OR data.win.system.eventID: "4625"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:26:00Z",
  "Image": "C:\Windows\System32\cmd.exe",
  "CommandLine": "cmd.exe /c whoami",
  "ParentImage": "C:\Windows\System32\smss.exe",
  "EventID": "4625",
  "User": "Administrator",
  "Location": "C:\Users\Administrator\cmd.exe"
}
```

---


## T1158 - Suspicious activity detected related to T1158

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\tasklist.exe"
OR data.win.eventdata.CommandLine: "tasklist /v"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\explorer.exe"
OR data.win.system.eventID: "1102"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:27:00Z",
  "Image": "C:\Windows\System32\tasklist.exe",
  "CommandLine": "tasklist /v",
  "ParentImage": "C:\Windows\System32\explorer.exe",
  "EventID": "1102",
  "User": "svc-account",
  "Location": "C:\Users\Administrator\tasklist.exe"
}
```

---


## T1159 - Suspicious activity detected related to T1159

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\tasklist.exe"
OR data.win.eventdata.CommandLine: "tasklist /v"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\services.exe"
OR data.win.system.eventID: "4663"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:28:00Z",
  "Image": "C:\Windows\System32\tasklist.exe",
  "CommandLine": "tasklist /v",
  "ParentImage": "C:\Windows\System32\services.exe",
  "EventID": "4663",
  "User": "jdoe",
  "Location": "C:\Users\SYSTEM\tasklist.exe"
}
```

---


## T1160 - Suspicious activity detected related to T1160

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\cmd.exe"
OR data.win.eventdata.CommandLine: "cmd.exe /c whoami"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\wininit.exe"
OR data.win.system.eventID: "4625"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:29:00Z",
  "Image": "C:\Windows\System32\cmd.exe",
  "CommandLine": "cmd.exe /c whoami",
  "ParentImage": "C:\Windows\System32\wininit.exe",
  "EventID": "4625",
  "User": "testuser",
  "Location": "C:\Users\testuser\cmd.exe"
}
```

---


## T1161 - Suspicious activity detected related to T1161

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\tasklist.exe"
OR data.win.eventdata.CommandLine: "tasklist /v --session 30"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\explorer.exe"
OR data.win.system.eventID: "4625"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:30:00Z",
  "Image": "C:\Windows\System32\tasklist.exe",
  "CommandLine": "tasklist /v --session 30",
  "ParentImage": "C:\Windows\System32\explorer.exe",
  "EventID": "4625",
  "User": "Administrator",
  "Location": "C:\Users\svc-account\tasklist.exe"
}
```

---


## T1162 - Suspicious activity detected related to T1162

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\net.exe"
OR data.win.eventdata.CommandLine: "net localgroup administrators --session 31"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\wininit.exe"
OR data.win.system.eventID: "4688"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:31:00Z",
  "Image": "C:\Windows\System32\net.exe",
  "CommandLine": "net localgroup administrators --session 31",
  "ParentImage": "C:\Windows\System32\wininit.exe",
  "EventID": "4688",
  "User": "svc-account",
  "Location": "C:\Users\SYSTEM\net.exe"
}
```

---


## T1163 - Suspicious activity detected related to T1163

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\schtasks.exe"
OR data.win.eventdata.CommandLine: "schtasks /create /tn backdoor /tr cmd.exe /sc minute"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\svchost.exe"
OR data.win.system.eventID: "4663"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:32:00Z",
  "Image": "C:\Windows\System32\schtasks.exe",
  "CommandLine": "schtasks /create /tn backdoor /tr cmd.exe /sc minute",
  "ParentImage": "C:\Windows\System32\svchost.exe",
  "EventID": "4663",
  "User": "testuser",
  "Location": "C:\Users\svc-account\schtasks.exe"
}
```

---


## T1164 - Suspicious activity detected related to T1164

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\tasklist.exe"
OR data.win.eventdata.CommandLine: "tasklist /v"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\wininit.exe"
OR data.win.system.eventID: "3"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:33:00Z",
  "Image": "C:\Windows\System32\tasklist.exe",
  "CommandLine": "tasklist /v",
  "ParentImage": "C:\Windows\System32\wininit.exe",
  "EventID": "3",
  "User": "SYSTEM",
  "Location": "C:\Users\testuser\tasklist.exe"
}
```

---


## T1165 - Suspicious activity detected related to T1165

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\net.exe"
OR data.win.eventdata.CommandLine: "net localgroup administrators --session 34"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\explorer.exe"
OR data.win.system.eventID: "4688"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:34:00Z",
  "Image": "C:\Windows\System32\net.exe",
  "CommandLine": "net localgroup administrators --session 34",
  "ParentImage": "C:\Windows\System32\explorer.exe",
  "EventID": "4688",
  "User": "svc-account",
  "Location": "C:\Users\SYSTEM\net.exe"
}
```

---


## T1166 - Suspicious activity detected related to T1166

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\cmd.exe"
OR data.win.eventdata.CommandLine: "cmd.exe /c whoami"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\lsass.exe"
OR data.win.system.eventID: "3"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:35:00Z",
  "Image": "C:\Windows\System32\cmd.exe",
  "CommandLine": "cmd.exe /c whoami",
  "ParentImage": "C:\Windows\System32\lsass.exe",
  "EventID": "3",
  "User": "Administrator",
  "Location": "C:\Users\svc-account\cmd.exe"
}
```

---


## T1167 - Suspicious activity detected related to T1167

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\tasklist.exe"
OR data.win.eventdata.CommandLine: "tasklist /v"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\wininit.exe"
OR data.win.system.eventID: "4663"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:36:00Z",
  "Image": "C:\Windows\System32\tasklist.exe",
  "CommandLine": "tasklist /v",
  "ParentImage": "C:\Windows\System32\wininit.exe",
  "EventID": "4663",
  "User": "testuser",
  "Location": "C:\Users\svc-account\tasklist.exe"
}
```

---


## T1168 - Suspicious activity detected related to T1168

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\tasklist.exe"
OR data.win.eventdata.CommandLine: "tasklist /v --session 37"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\services.exe"
OR data.win.system.eventID: "4663"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:37:00Z",
  "Image": "C:\Windows\System32\tasklist.exe",
  "CommandLine": "tasklist /v --session 37",
  "ParentImage": "C:\Windows\System32\services.exe",
  "EventID": "4663",
  "User": "testuser",
  "Location": "C:\Users\Administrator\tasklist.exe"
}
```

---


## T1169 - Suspicious activity detected related to T1169

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\net.exe"
OR data.win.eventdata.CommandLine: "net localgroup administrators"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\smss.exe"
OR data.win.system.eventID: "4625"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:38:00Z",
  "Image": "C:\Windows\System32\net.exe",
  "CommandLine": "net localgroup administrators",
  "ParentImage": "C:\Windows\System32\smss.exe",
  "EventID": "4625",
  "User": "testuser",
  "Location": "C:\Users\Administrator\net.exe"
}
```

---


## T1170 - Suspicious activity detected related to T1170

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\schtasks.exe"
OR data.win.eventdata.CommandLine: "schtasks /create /tn backdoor /tr cmd.exe /sc minute --session 39"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\svchost.exe"
OR data.win.system.eventID: "1102"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:39:00Z",
  "Image": "C:\Windows\System32\schtasks.exe",
  "CommandLine": "schtasks /create /tn backdoor /tr cmd.exe /sc minute --session 39",
  "ParentImage": "C:\Windows\System32\svchost.exe",
  "EventID": "1102",
  "User": "jdoe",
  "Location": "C:\Users\SYSTEM\schtasks.exe"
}
```

---


## T1171 - Suspicious activity detected related to T1171

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\net.exe"
OR data.win.eventdata.CommandLine: "net localgroup administrators"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\taskhostw.exe"
OR data.win.system.eventID: "4625"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:40:00Z",
  "Image": "C:\Windows\System32\net.exe",
  "CommandLine": "net localgroup administrators",
  "ParentImage": "C:\Windows\System32\taskhostw.exe",
  "EventID": "4625",
  "User": "jdoe",
  "Location": "C:\Users\testuser\net.exe"
}
```

---


## T1172 - Suspicious activity detected related to T1172

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\net.exe"
OR data.win.eventdata.CommandLine: "net localgroup administrators --session 41"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\svchost.exe"
OR data.win.system.eventID: "4688"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:41:00Z",
  "Image": "C:\Windows\System32\net.exe",
  "CommandLine": "net localgroup administrators --session 41",
  "ParentImage": "C:\Windows\System32\svchost.exe",
  "EventID": "4688",
  "User": "jdoe",
  "Location": "C:\Users\Administrator\net.exe"
}
```

---


## T1173 - Suspicious activity detected related to T1173

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\net.exe"
OR data.win.eventdata.CommandLine: "net localgroup administrators"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\taskhostw.exe"
OR data.win.system.eventID: "3"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:42:00Z",
  "Image": "C:\Windows\System32\net.exe",
  "CommandLine": "net localgroup administrators",
  "ParentImage": "C:\Windows\System32\taskhostw.exe",
  "EventID": "3",
  "User": "svc-account",
  "Location": "C:\Users\svc-account\net.exe"
}
```

---


## T1174 - Suspicious activity detected related to T1174

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\schtasks.exe"
OR data.win.eventdata.CommandLine: "schtasks /create /tn backdoor /tr cmd.exe /sc minute --session 43"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\smss.exe"
OR data.win.system.eventID: "4104"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:43:00Z",
  "Image": "C:\Windows\System32\schtasks.exe",
  "CommandLine": "schtasks /create /tn backdoor /tr cmd.exe /sc minute --session 43",
  "ParentImage": "C:\Windows\System32\smss.exe",
  "EventID": "4104",
  "User": "SYSTEM",
  "Location": "C:\Users\jdoe\schtasks.exe"
}
```

---


## T1175 - Suspicious activity detected related to T1175

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\cmd.exe"
OR data.win.eventdata.CommandLine: "cmd.exe /c whoami"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\wininit.exe"
OR data.win.system.eventID: "4625"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:44:00Z",
  "Image": "C:\Windows\System32\cmd.exe",
  "CommandLine": "cmd.exe /c whoami",
  "ParentImage": "C:\Windows\System32\wininit.exe",
  "EventID": "4625",
  "User": "Administrator",
  "Location": "C:\Users\svc-account\cmd.exe"
}
```

---


## T1176 - Suspicious activity detected related to T1176

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\cmd.exe"
OR data.win.eventdata.CommandLine: "cmd.exe /c whoami"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\smss.exe"
OR data.win.system.eventID: "4624"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:45:00Z",
  "Image": "C:\Windows\System32\cmd.exe",
  "CommandLine": "cmd.exe /c whoami",
  "ParentImage": "C:\Windows\System32\smss.exe",
  "EventID": "4624",
  "User": "jdoe",
  "Location": "C:\Users\Administrator\cmd.exe"
}
```

---


## T1177 - Suspicious activity detected related to T1177

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\net.exe"
OR data.win.eventdata.CommandLine: "net localgroup administrators --session 46"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\lsass.exe"
OR data.win.system.eventID: "3"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:46:00Z",
  "Image": "C:\Windows\System32\net.exe",
  "CommandLine": "net localgroup administrators --session 46",
  "ParentImage": "C:\Windows\System32\lsass.exe",
  "EventID": "3",
  "User": "testuser",
  "Location": "C:\Users\jdoe\net.exe"
}
```

---


## T1178 - Suspicious activity detected related to T1178

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\cmd.exe"
OR data.win.eventdata.CommandLine: "cmd.exe /c whoami --session 47"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\lsass.exe"
OR data.win.system.eventID: "4104"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:47:00Z",
  "Image": "C:\Windows\System32\cmd.exe",
  "CommandLine": "cmd.exe /c whoami --session 47",
  "ParentImage": "C:\Windows\System32\lsass.exe",
  "EventID": "4104",
  "User": "svc-account",
  "Location": "C:\Users\SYSTEM\cmd.exe"
}
```

---


## T1179 - Suspicious activity detected related to T1179

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\net.exe"
OR data.win.eventdata.CommandLine: "net localgroup administrators"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\smss.exe"
OR data.win.system.eventID: "4663"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:48:00Z",
  "Image": "C:\Windows\System32\net.exe",
  "CommandLine": "net localgroup administrators",
  "ParentImage": "C:\Windows\System32\smss.exe",
  "EventID": "4663",
  "User": "testuser",
  "Location": "C:\Users\SYSTEM\net.exe"
}
```

---


## T1180 - Suspicious activity detected related to T1180

### Wazuh Query (Kibana)

```kql
data.win.eventdata.Image: "C:\Windows\System32\cmd.exe"
OR data.win.eventdata.CommandLine: "cmd.exe /c whoami --session 49"
OR data.win.eventdata.ParentImage: "C:\Windows\System32\smss.exe"
OR data.win.system.eventID: "1102"
```

### Result Data
```json
{
  "timestamp": "2024-05-28T14:49:00Z",
  "Image": "C:\Windows\System32\cmd.exe",
  "CommandLine": "cmd.exe /c whoami --session 49",
  "ParentImage": "C:\Windows\System32\smss.exe",
  "EventID": "1102",
  "User": "SYSTEM",
  "Location": "C:\Users\svc-account\cmd.exe"
}
```

---
