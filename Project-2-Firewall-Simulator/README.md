# 🔥 Firewall Simulator & Packet Filtering Engine

> **Security-Fundamentals Project 2** — A stateful firewall simulator with zone-based security policies and real-time traffic visualization.

## 🎯 What This Tool Does

1. **Packet Parsing** — Parse and analyze network packets layer by layer
2. **Rule-Based Filtering** — Evaluate packets against ordered firewall rules (first match wins)
3. **Stateful Inspection** — Track TCP connection states (SYN → ESTABLISHED → FIN)
4. **Zone-Based Policies** — Enforce security between network zones (IT/OT/DMZ)
5. **Traffic Simulation** — Generate realistic and attack traffic for testing
6. **Web Dashboard** — 6-page interactive dashboard for real-time monitoring

## 🏗️ Architecture

```
Project-2-Firewall-Simulator/
├── firewall/
│   ├── packet_parser.py       # Packet data structure & parsing
│   ├── rule_engine.py         # Priority-based rule evaluation
│   ├── stateful_tracker.py    # TCP state machine & connection table
│   ├── zone_manager.py       # Security zones & inter-zone policies
│   ├── firewall_engine.py    # Main engine (combines all modules)
│   └── traffic_generator.py  # Simulated traffic & attack patterns
├── rules/
│   └── default_rules.json    # Enterprise firewall rule set
├── dashboard/
│   ├── index.html / style.css / app.js
├── logs/
│   └── firewall.log          # Packet processing log
├── main.py                   # CLI + Flask web server
└── README.md
```

## 🚀 Quick Start

```bash
cd Project-2-Firewall-Simulator
pip install -r requirements.txt

# Interactive demo
python main.py --demo

# Web dashboard (port 5001)
python main.py --web

# Traffic simulation
python main.py --simulate
```

## 📚 Key Concepts Learned

### Firewall Fundamentals
- **Stateless vs Stateful**: Why tracking connection state matters
- **Default Deny**: Whitelist approach (only allow what's explicitly permitted)
- **Rule Priority**: First-match-wins evaluation order
- **TCP State Machine**: SYN → SYN_RECV → ESTABLISHED → FIN_WAIT → CLOSED

### Zone-Based Security (Purdue Model)
| Zone | Trust | Networks | Purpose |
|------|-------|----------|---------|
| untrusted | 0 | Internet | External |
| dmz | 25 | 172.16.0.0/24 | Public servers |
| trusted | 75 | 192.168.x.0/24 | Corporate IT |
| ot_network | 90 | 10.10.0.0/16 | Industrial OT |
| management | 100 | 10.0.0.0/24 | Admin access |

### Attack Simulations
- **Port Scan** — Rapid probing of many ports
- **Brute Force** — Repeated SSH login attempts
- **SYN Flood** — DDoS using spoofed SYN packets
- **OT Intrusion** — Unauthorized Modbus access from IT to OT
- **Lateral Movement** — Compromised host scanning internal network

## ⚠️ Disclaimer
This tool is for **educational purposes only**. Understanding attack techniques helps build better defenses.
