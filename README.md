# CyberDefenders Blue Team Investigations Writeup

### A collection of blue team investigations, threat hunting exercises, and incident response case studies focused on real-world SOC workflows. Each investigation documents the analytical process used to identify, investigate, and understand security events through evidence collection, timeline reconstruction, IOC analysis, ATT&CK mapping, and reporting. 

<br>

### Topics span endpoint, network, identity, cloud, and threat intelligence investigations using industry-standard security tools and methodologies.

---
<br>

## Investigations:

| # | Investigation | Platform | Focus | Status |
|---|--------------|----------|-------|--------|
| 01 | [Log Analysis - Sysmon](./01-Log-Analysis-Sysmon/) | BTLO | Endpoint, Windows Event Logs | Complete |
| 02 | [Paranoid - Linux IR](./02-Paranoid-Linux-IR/) | BTLO | Linux, SSH, Privilege Escalation | Complete |
| 03 | [Phishing Analysis](./03-Phishing-Analysis/) | BTLO | Email, IOC Extraction | Complete |
| 04 | [Follina - CVE-2022-30190](./04-Follina-Investigation/) | BTLO | Endpoint, Vulnerability, Malware | Complete |
| 05 | [The Report - Threat Intelligence](./05-The-Report-Threat-Intel/) | BTLO | Threat Intel, IOC Analysis | Complete |

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

Primary: [Blue Team Labs Online (BTLO)](https://blueteamlabs.online/)

Additional investigations may be added from CyberDefenders and TryHackMe
