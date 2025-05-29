# 🎯 Hunting Guide: Network Sniffing (T1143)

---

## Objective

Hunt for attacker activity capturing network traffic to obtain sensitive data like credentials or session tokens.

---

## Detection Hypothesis

"If an attacker uses network sniffing tools, we expect to see execution of applications like `Wireshark`, `tcpdump`, or processes opening `.pcap` files."

---

## Wazuh Query

```kql
data.win.eventdata.CommandLine: ("wireshark" OR "tcpdump" OR "*.pcap")

## Splunk Query

index=windows EventCode=4688 (CommandLine="*wireshark*" OR CommandLine="*tcpdump*" OR CommandLine="*.pcap*")

## Wazuh Log

{
  "timestamp": "2024-05-28T15:10:00Z",
  "Image": "C:\\Program Files\\Wireshark\\Wireshark.exe",
  "CommandLine": "Wireshark.exe",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "EventID": "4688",
  "User": "jdoe"
}

## Hunting Steps

1. Search for execution of sniffing tools like Wireshark, tcpdump, or .pcap file access.

2. Correlate with:

- User accounts and source IPs.

- High-privilege accounts accessing sensitive network segments.

3. Investigate:

- Presence of .pcap files in suspicious directories.

- Unusual data transfer patterns.

## Why it Matters

Network sniffing enables attackers to harvest sensitive data like credentials, tokens, or session cookies without detection.