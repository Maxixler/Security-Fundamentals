"""
IDS/IPS - Main Application
============================
Enterprise Intrusion Detection & Prevention System with real-time
packet analysis, signature-based detection, and rate-based anomaly alerting.

This tool provides:
    1. Multi-Protocol Traffic Generation (TCP, UDP, ICMP, ARP)
    2. Signature-Based Detection (13+ Snort-style rules)
    3. Rate-Based Anomaly Detection (SYN flood, port scan, brute force)
    4. IP Blocking with TTL-Based Ban Management
    5. Real-Time SOC Dashboard with Live Packet Stream
    6. MITRE ATT&CK Technique Mapping

Usage:
    python main.py                 # Interactive mode
    python main.py --web           # Start IDS dashboard
    python main.py --simulate      # Run traffic simulation (CLI)
"""

import argparse
import sys
import os
import threading
import time
import random

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS

from engine.packet_sniffer import TrafficGenerator, Packet
from engine.signature_matcher import SignatureEngine


# ─── Application State ─────────────────────────────────────────────────
traffic_gen = TrafficGenerator(attack_ratio=0.15)
ids_engine = SignatureEngine()

packet_log = []
alert_log = []
MAX_PACKETS = 80
MAX_ALERTS = 60

simulation_running = False


def banner():
    print("""
    +---------------------------------------------------------------+
    |                                                               |
    |   IDS / IPS ENGINE                                            |
    |   Intrusion Detection & Prevention System v2.0                |
    |   Security-Fundamentals Project 5                             |
    |                                                               |
    +---------------------------------------------------------------+
    """)


# ─── Traffic Simulation Thread ──────────────────────────────────────────
def run_simulation():
    """Background thread: generates traffic and runs through IDS engine."""
    global simulation_running
    simulation_running = True
    print("  [*] Traffic simulation engine started")
    print(f"  [*] Attack ratio: {traffic_gen.attack_ratio * 100:.0f}%")
    print(f"  [*] Loaded {ids_engine.get_rule_count()} detection signatures\n")

    while simulation_running:
        time.sleep(random.uniform(0.2, 1.5))

        # Generate packets (occasional bursts for attack simulation)
        burst_size = 1
        if random.random() > 0.9:
            burst_size = random.randint(3, 10)

        for _ in range(burst_size):
            packet = traffic_gen.generate_packet()
            pkt_dict = packet.to_dict()

            # Run through IDS
            result = ids_engine.analyze_packet(packet)

            # Add to packet log
            pkt_dict["detection"] = result.to_dict()
            packet_log.insert(0, pkt_dict)
            if len(packet_log) > MAX_PACKETS:
                packet_log.pop()

            # If alert was generated, add to alert log
            if result.matched:
                alert_entry = {
                    **result.to_dict(),
                    "src_ip": pkt_dict["src_ip"],
                    "dst_ip": pkt_dict["dst_ip"],
                    "dst_port": pkt_dict["dst_port"],
                    "protocol": pkt_dict["protocol"],
                }
                alert_log.insert(0, alert_entry)
                if len(alert_log) > MAX_ALERTS:
                    alert_log.pop()


# ─── Flask Web Dashboard ───────────────────────────────────────────────
app = Flask(__name__, static_folder="dashboard")
CORS(app)


@app.route("/")
def index():
    return send_from_directory("dashboard", "index.html")


@app.route("/<path:filename>")
def serve_static(filename):
    return send_from_directory("dashboard", filename)


@app.route("/api/status")
def get_status():
    return jsonify({
        "packets": packet_log[:20],
        "alerts": alert_log[:20],
        "blocked_ips": ids_engine.get_blocked_ips(),
        "stats": ids_engine.stats,
        "rule_count": ids_engine.get_rule_count(),
    })


@app.route("/api/alerts")
def get_alerts():
    severity = request.args.get("severity", "")
    if severity:
        filtered = [a for a in alert_log if a.get("severity", "").lower() == severity.lower()]
        return jsonify({"alerts": filtered})
    return jsonify({"alerts": alert_log})


@app.route("/api/blocked")
def get_blocked():
    return jsonify({"blocked": ids_engine.get_blocked_ips()})


@app.route("/api/rules")
def get_rules():
    rules = [{
        "sid": r["sid"], "name": r["name"],
        "severity": r["severity"], "category": r["category"],
        "protocol": r["protocol"], "mitre": r.get("mitre", ""),
    } for r in ids_engine.rules]
    return jsonify({"rules": rules, "total": len(rules)})


# ─── Interactive CLI ────────────────────────────────────────────────────
def interactive_mode():
    banner()
    sim_thread = threading.Thread(target=run_simulation, daemon=True)
    sim_thread.start()
    time.sleep(1)

    while True:
        print("\n" + "=" * 55)
        print("  IDS/IPS CONTROL PANEL")
        print("=" * 55)
        print("  1. View Recent Alerts")
        print("  2. View Packet Stream")
        print("  3. View Blocked IPs")
        print("  4. View Detection Rules")
        print("  5. View Statistics")
        print("  6. Start Web Dashboard")
        print("  7. Exit")
        print("=" * 55)

        choice = input("\n  Select option [1-7]: ").strip()

        if choice == "1":
            _cli_alerts()
        elif choice == "2":
            _cli_packets()
        elif choice == "3":
            _cli_blocked()
        elif choice == "4":
            _cli_rules()
        elif choice == "5":
            _cli_stats()
        elif choice == "6":
            _start_dashboard()
        elif choice == "7":
            print("\n  [*] IDS/IPS system shutting down. Stay vigilant! 🛡️")
            sys.exit(0)


def _cli_alerts():
    print(f"\n  ─── THREAT ALERTS ({len(alert_log)} total) ───\n")
    for a in alert_log[:10]:
        sev = a.get("severity", "?")
        icon = "🔴" if sev == "Critical" else "🟠" if sev == "High" else "🟡"
        print(f"  {icon} [{sev:8s}] SID:{a.get('rule_sid', '?'):5d} | {a.get('rule_name', 'Unknown')}")
        print(f"            {a.get('src_ip', '?')} → {a.get('dst_ip', '?')}:{a.get('dst_port', '?')} "
              f"| MITRE: {a.get('mitre', 'N/A')}")


def _cli_packets():
    print(f"\n  ─── PACKET STREAM ({len(packet_log)} buffered) ───\n")
    for p in packet_log[:10]:
        det = p.get("detection", {})
        flag = "🔴" if det.get("matched") else "🟢"
        print(f"  {flag} {p['protocol']:5s} {p['src_ip']:17s}:{p.get('src_port', 0):5d} → "
              f"{p['dst_ip']:17s}:{p.get('dst_port', 0):5d} [{p.get('flags', '')}] {p['size']}B")


def _cli_blocked():
    blocked = ids_engine.get_blocked_ips()
    print(f"\n  ─── BLOCKED IPs ({len(blocked)}) ───\n")
    for b in blocked:
        print(f"  🚫 {b['ip']:17s} | TTL: {b['ttl_remaining']:4d}s | Reason: {b['reason']}")


def _cli_rules():
    print(f"\n  ─── LOADED RULES ({ids_engine.get_rule_count()}) ───\n")
    for r in ids_engine.rules:
        print(f"  SID:{r['sid']:5d} | {r['severity']:8s} | {r['category']:25s} | {r['name']}")


def _cli_stats():
    s = ids_engine.stats
    print("\n  ─── DETECTION STATISTICS ───\n")
    for k, v in s.items():
        print(f"    {k:25s}: {v}")


def _start_dashboard(port=5005):
    print(f"\n  [*] Starting IDS/IPS Dashboard on http://localhost:{port}")
    print("  [*] Press Ctrl+C to stop\n")
    app.run(host="0.0.0.0", port=port, debug=False)


# ─── Entry Point ────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Intrusion Detection & Prevention System — Security-Fundamentals Project 5",
    )
    parser.add_argument("--web", "-w", action="store_true", help="Start web dashboard")
    parser.add_argument("--port", type=int, default=5005, help="Dashboard port")
    parser.add_argument("--simulate", "-s", action="store_true", help="Run simulation (CLI)")
    parser.add_argument("--attack-ratio", type=float, default=0.15, help="Attack traffic ratio (0-1)")

    args = parser.parse_args()
    traffic_gen.attack_ratio = args.attack_ratio

    sim_thread = threading.Thread(target=run_simulation, daemon=True)
    sim_thread.start()

    if args.web:
        banner()
        _start_dashboard(args.port)
    elif args.simulate:
        banner()
        print("  [*] Running traffic simulation. Press Ctrl+C to stop.\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n  [*] Simulation stopped.")
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
