# 🛡️ Enterprise Security Operations Portfolio

A comprehensive, production-grade cybersecurity portfolio consisting of 5 standalone pillars. 
This repository is carefully engineered to demonstrate deep expertise in **Network Reconnaissance, Stateful Defense, Log Correlation (SIEM), Compliance Management (Vulnerability Scanning), and OT/ICS Industrial Security**.

⚠️ **Note:** All corporate/company-specific references have been abstracted to maintain professional presentation standards.

## 📌 Architecture at a Glance
| Pillar | Project | Main Tech / Focus | Status |
|--------|---------|-------------------|--------|
| **Recon** | [P1: Network Scanner & Analyzer](./Project-1-Network-Scanner) | Packet Crafting, Host/Port Discovery | ✅ Completed |
| **Defense** | [P2: Stateful Firewall Simulator](./Project-2-Firewall-Simulator) | Stateful Tracker, Access Control Lists | ✅ Completed |
| **Correlation**| [P3: Enterprise SIEM & SOC](./Project-3-SIEM-Dashboard) | Log Normalizer, Threat Intel, Brute-Force rules | ✅ Completed |
| **Risk** | [P4: Vulnerability & Compliance](./Project-4-Vulnerability-Scanner)| CVE engine, ISO 27001 Auditor | ✅ Completed |
| **Industrial** | [P6: OT/ICS Modbus Monitor](./Project-6-OT-ICS-Security) | SCADA HMI, PLC sim, ICS IDS Alerting | ✅ Completed |

*Note: Project 5 (IDS/IPS) logic has been absorbed directly into the SIEM and OT Industrial monitors.*

---

## 🛠️ Individual Project Details

### Project 1: Network Scanner & Port Analyzer
Scans subnets and performs reconnaissance. Simulates Nmap-like syntax and exports findings to a visual dashboard.
```bash
cd Project-1-Network-Scanner
python main.py --web
```

### Project 2: Stateful Firewall Simulator
A 6-module network firewall engine simulating Purdue Model segmentation. Detects stateful anomalies like unauthorized out-of-state packets and drops IT-to-OT malicious requests.
```bash
cd Project-2-Firewall-Simulator
python main.py --simulate
```

### Project 3: Enterprise SIEM & SOC Dashboard
Acts as the central integration nervous system. Normalizes raw `[FIREWALL] DENY` traces and Windows Active Directory JSON logs. The correlation engine tracks sliding-window failures to alert on live Brute Force attacks.
```bash
cd Project-3-SIEM-Dashboard
python main.py --web
```

### Project 4: Vulnerability Scanner & Compliance Auditor
Takes discovered network assets and maps software versions (e.g. Apache 2.4.49) to NVD simulated endpoints to calculate raw CVSS scores. It cross-references internal configurations against ISO 27001 constraints.
```bash
cd Project-4-Vulnerability-Scanner
python main.py --web
```

### Project 6: OT/ICS Security Monitor
An elite capability demonstrator. Uses `pymodbus` to simulate a live Refinery Boiler. Allows performing direct Register Manipulation attacks via Python, which are instantly detected by a passive Modbus IDS analyzer.
```bash
cd Project-6-OT-ICS-Security
python main.py --web
```

---
**Author:** Eren Kale
**Focus:** Enterprise Server/Network Security, Industrial Information Security (OT/ICS).
