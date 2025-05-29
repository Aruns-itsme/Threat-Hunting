# 🛡️ Threat Hunting & Incident Response Repository

Welcome to the **Threat Hunting** repository! This project is a comprehensive, MITRE ATT&CK-mapped threat hunting and incident response resource for security analysts, blue teams, and SOC professionals. It provides practical hunting guides, real-world logs, detection queries, and incident response playbooks designed to help defenders proactively detect, investigate, and respond to cyber threats.

---

## 📂 Repository Structure

```bash
Threat-Hunting/
├── README.md
├── hunting-guides/
│   ├── credential-access-hunt.md
│   ├── rdp-brute-force-hunt.md
│   ├── powershell-abuse-hunt.md
│   ├── ... (15 guides total)
├── incident-response-playbooks/
│   ├── credential-dumping-playbook.md
│   ├── scheduled-task-creation-playbook.md
│   ├── ... (15 playbooks total)
├── queries/
│   ├── wazuh_hunting_queries.md
│   ├── splunk_hunting_queries.md
├── logs/
│   ├── wazuh_alert_log_enhanced.json
│   ├── splunk_alerts_log_enhanced.csv
│   ├── example_wazuh_alerts.json
│   ├── example_splunk_alerts.csv
├── dashboards/
│   ├── wazuh_dashboard_screenshot.png
│   ├── splunk_dashboard_screenshot.png
├── report/
│   └── final_threat_hunting_report.pdf
├── LICENSE
```

## Project Highlights

## In-Depth Hunting Guides

- MITRE-mapped (T1131–T1145)

- Wazuh & Splunk queries

- Realistic log examples

- Hunting steps, why it matters, and references

## Detailed Incident Response Playbooks

- Aligned with NIST 800-61 & MITRE ATT&CK

- Containment, eradication, recovery, and post-incident steps

## Detection Queries

- Wazuh & Splunk formats

- Copy-paste ready

## Logs

- Wazuh and Splunk logs

## Getting Started

1️. Clone this repository:

```kql
git clone https://github.com/Aruns-itsme/Threat-Hunting.git
```

2️. Explore the hunting-guides/ and incident-response-playbooks/ folders for ready-to-use resources.

3️. Import detection queries into your SIEM:

- Wazuh: queries/wazuh_hunting_queries.md

- Splunk: queries/splunk_hunting_queries.md

4️. Use the logs in logs/ for lab simulations and testing.

5️. Review the final report in report/final_threat_hunting_report.pdf for project insights.

## MITRE ATT&CK Coverage

This project maps to the following MITRE ATT&CK techniques (T1131–T1145), including:

- Credential Dumping (T1003.001)

- Scheduled Task Creation (T1131)

- External Remote Services (T1133)

- Network Sniffing (T1143)

- Data from Information Repositories (T1145)

...and many more.

For full coverage, see individual hunting guides and playbooks.

## 📑 License
This project is licensed under the MIT License.
See the LICENSE file for details.

## Contributing
Contributions are welcome! Feel free to submit issues or pull requests.
For major changes, please open an issue first to discuss what you'd like to change.

## Acknowledgements

MITRE ATT&CK

NIST 800-61

The cybersecurity community for inspiration and resources.
