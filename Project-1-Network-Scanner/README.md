# 🛡️ Network Scanner & Port Analyzer

> **Security-Fundamentals Project 1** — A comprehensive network scanning tool built to learn the fundamentals of network security.

## 🎯 What This Tool Does

1. **Host Discovery** — Find active devices on a network using TCP/ICMP probes
2. **Port Scanning** — Identify open TCP ports with multiple scan profiles
3. **Service Detection** — Determine running services via banner grabbing
4. **Security Analysis** — Identify risky ports and OT/ICS exposure
5. **Report Generation** — Professional HTML/JSON scan reports
6. **Web Dashboard** — Modern dark-themed interactive dashboard

## 🏗️ Architecture

```
Project-1-Network-Scanner/
├── scanner/
│   ├── host_discovery.py      # ARP/ICMP/TCP host discovery
│   ├── port_scanner.py        # TCP Connect scan with multiple profiles
│   └── service_detector.py    # Banner grabbing & service fingerprinting
├── utils/
│   ├── ip_utils.py            # IP/Subnet calculation & well-known ports
│   └── report_generator.py    # HTML & JSON report generation
├── web_dashboard/
│   ├── index.html             # Dashboard UI
│   ├── style.css              # Cyberpunk dark theme
│   └── app.js                 # Frontend logic & API integration
├── main.py                    # CLI & Flask web server
├── requirements.txt
└── README.md
```

## 🚀 Quick Start

### Install Dependencies
```bash
cd Project-1-Network-Scanner
pip install -r requirements.txt
```

### Interactive CLI Mode
```bash
python main.py
```

### Web Dashboard
```bash
python main.py --web
# Open http://localhost:5000
```

### Command Line Scan
```bash
# Discover hosts on your network
python main.py --target 192.168.1.0/24 --discover

# Scan ports on a target
python main.py --target 192.168.1.1 --profile common --services

# Full scan with report
python main.py --target 192.168.1.1 --profile top100 --services --report
```

## 📚 Key Concepts Learned

### TCP/IP Fundamentals
- **IP Addressing**: IPv4 structure, subnetting, CIDR notation
- **TCP 3-Way Handshake**: SYN → SYN-ACK → ACK connection establishment
- **Port States**: Open (service listening), Closed (no service), Filtered (firewall)
- **Socket Programming**: Raw socket creation for network probing

### Network Security
- **Asset Discovery**: Finding all devices on a network (first step in security)
- **Attack Surface**: Every open port is a potential entry point
- **Banner Hardening**: Why services should minimize version disclosure
- **OT/ICS Ports**: Industrial protocol exposure (Modbus, BACnet, etc.)

### Scan Profiles
| Profile | Ports | Use Case |
|---------|-------|----------|
| `common` | ~36 critical ports | Quick security check |
| `quick` | 1-1024 | Well-known ports |
| `top100` | Top 100 | Comprehensive check |
| `full` | 1-65535 | Complete audit (slow) |

## ⚠️ Disclaimer

This tool is for **authorized security testing only**. Unauthorized network scanning is illegal. Always obtain proper permission before scanning any network.

## 📖 Related Projects
- [Project 2: Firewall Simulator](../Project-2-Firewall-Simulator/)
- [Project 3: SIEM Dashboard](../Project-3-SIEM-Dashboard/)
