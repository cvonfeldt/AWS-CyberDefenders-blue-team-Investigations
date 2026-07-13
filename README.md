# CyberDefenders Blue Team Investigations Writeups

### A structured series of various cloud (AWS) forensics and threat hunting challenges focused on isolating infrastructure breaches, initial access vectors, and malicious automation. Designed around real-world SOC workflows, each project documents the complete analytical process required to identify, investigate, and scope security events through timeline reconstruction, IOC extraction, and MITRE ATT&CK mapping.

<br>

### These labs examine initial access vectors, infrastructure metadata abuse, and malicious automation. Investigations leverage CloudTrail, API activity, and Lambda telemetry to trace real-world attack vectors across your portfolio, including IMDSv1 SSRF exploits, S3 credential theft, and malicious Lambda correlations.

---
<br>

## Investigations:

| # | Investigation | Platform | Focus | Status |
|---|--------------|----------|-------|--------|
| 01 | AbuSESer - Trufflenet | CyberDefenders | AWS + Lambda correlation, Business Email Compromise, IOC extraction |	Complete |
| 02 | AWSRaid | CyberDefenders	| Splunk, Brute-force attacks, S3 asset exfiltration, lateral movement analysis | In Progress |
| 03 | AWSWatcher	| CyberDefenders	| AWS CloudTrail, IAM abuse, API activity, Cloud Forensics	| Complete |
| 04 | IMDSv1 | CyberDefenders | Wireshark, jq, SSRF exploitation, Metadata service abuse, Credential theft | Not Started |
| 05 | S3CredentialsHunt | CyberDefenders | jq, Exposed credential discovery, defense evasion (DeleteTrail) | Not Started |

---

## Report Structure

Each investigation follows a consistent format:

```
Overview        — scenario background and scope
Methodology     — step-by-step analytical approach
Attack Chain    — chronological event reconstruction
IOCs            — IPs, hashes, domains, file names
ATT&CK Mapping  — tactic and technique identification
Investigation   — evidence, artifacts, and answers
```

---

## Platform

Primary: [CyberDefenders](https://cyberdefenders.org/)
