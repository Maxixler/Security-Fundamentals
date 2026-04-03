"""
Firewall Simulator - Main Application
======================================
A complete firewall simulator with:
- Rule-based packet filtering
- Stateful connection tracking
- Zone-based security policies
- Traffic simulation and testing
- Web dashboard for visualization

Usage:
    python main.py              # Interactive demo mode
    python main.py --web        # Start web dashboard
    python main.py --simulate   # Run traffic simulation
"""

import argparse
import sys
import os
import json
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from firewall.packet_parser import Packet, PacketParser, Protocol
from firewall.rule_engine import RuleEngine, FirewallRule
from firewall.stateful_tracker import StatefulTracker
from firewall.zone_manager import ZoneManager
from firewall.firewall_engine import FirewallEngine
from firewall.traffic_generator import TrafficGenerator


# Global firewall instance for web API
fw_engine = None
traffic_gen = TrafficGenerator()
simulation_running = False
simulation_thread = None


def banner():
    print(r"""
    ╔══════════════════════════════════════════════════════╗
    ║  ███████╗██╗██████╗ ███████╗██╗    ██╗ █████╗ ██╗   ║
    ║  ██╔════╝██║██╔══██╗██╔════╝██║    ██║██╔══██╗██║   ║
    ║  █████╗  ██║██████╔╝█████╗  ██║ █╗ ██║███████║██║   ║
    ║  ██╔══╝  ██║██╔══██╗██╔══╝  ██║███╗██║██╔══██║██║   ║
    ║  ██║     ██║██║  ██║███████╗╚███╔███╔╝██║  ██║███████║
    ║  ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝║
    ║  Firewall Simulator v1.0                             ║
    ║  Security-Fundamentals Project 2                     ║
    ╚══════════════════════════════════════════════════════╝
    """)


def init_firewall() -> FirewallEngine:
    """Initialize the firewall with default rules."""
    global fw_engine
    rules_path = os.path.join(os.path.dirname(__file__), "rules", "default_rules.json")
    fw_engine = FirewallEngine(rules_file=rules_path, stateful=True)
    return fw_engine


def run_demo():
    """Run an interactive demonstration of the firewall."""
    banner()
    fw = init_firewall()

    print("[*] Firewall initialized with default rules")
    print(f"[*] Rules loaded: {len(fw.rule_engine.rules)}")
    print(f"[*] Default policy: {fw.rule_engine.default_policy}")
    print(f"[*] Zones: {', '.join(fw.zone_manager.zones.keys())}")
    print()

    # Demo 1: Normal traffic
    print("=" * 60)
    print("  DEMO 1: Normal Enterprise Traffic")
    print("=" * 60)
    normal_packets = traffic_gen.generate_normal_traffic(20)
    for pkt in normal_packets:
        result = fw.process_packet(pkt)
        action_symbol = "[+]" if result["action"] == "ALLOW" else "[-]"
        print(f"  {action_symbol} {result['action']:>5} | {pkt} | {result['reason'][:50]}")

    # Demo 2: Attack traffic
    print()
    print("=" * 60)
    print("  DEMO 2: Port Scan Attack")
    print("=" * 60)
    attack_packets = traffic_gen.generate_attack_traffic("port_scan", 10)
    for pkt in attack_packets:
        result = fw.process_packet(pkt)
        action_symbol = "[+]" if result["action"] == "ALLOW" else "[-]"
        print(f"  {action_symbol} {result['action']:>5} | {pkt} | {result['reason'][:50]}")

    # Demo 3: OT intrusion attempt
    print()
    print("=" * 60)
    print("  DEMO 3: OT/ICS Intrusion Attempt")
    print("=" * 60)
    ot_attack = traffic_gen.generate_attack_traffic("ot_intrusion", 5)
    for pkt in ot_attack:
        result = fw.process_packet(pkt)
        action_symbol = "[+]" if result["action"] == "ALLOW" else "[-]"
        print(f"  {action_symbol} {result['action']:>5} | {pkt} | {result['reason'][:50]}")

    # Statistics
    print()
    print("=" * 60)
    print("  STATISTICS")
    print("=" * 60)
    stats = fw.get_stats()
    print(f"  Total packets:   {stats['total_packets']}")
    print(f"  Allowed:         {stats['allowed']} ({stats['allow_rate']}%)")
    print(f"  Denied:          {stats['denied']} ({stats['deny_rate']}%)")
    print(f"  Dropped:         {stats['dropped']} ({stats['drop_rate']}%)")
    print(f"  Invalid state:   {stats['invalid_state']}")


def start_web_server(host="0.0.0.0", port=5001):
    """Start the Flask web dashboard."""
    global fw_engine, simulation_running, simulation_thread

    try:
        from flask import Flask, send_from_directory, jsonify, request
        from flask_cors import CORS
    except ImportError:
        print("[!] Flask not installed. Run: pip install flask flask-cors")
        return

    fw = init_firewall()
    app = Flask(__name__, static_folder="dashboard")
    CORS(app)

    @app.route("/")
    def index():
        return send_from_directory("dashboard", "index.html")

    @app.route("/<path:filename>")
    def serve_static(filename):
        return send_from_directory("dashboard", filename)

    # ---- Stats & Logs ----
    @app.route("/api/stats")
    def get_stats():
        return jsonify(fw.get_stats())

    @app.route("/api/logs")
    def get_logs():
        count = int(request.args.get("count", 50))
        return jsonify({"logs": fw.get_recent_logs(count)})

    @app.route("/api/log-summary")
    def get_log_summary():
        return jsonify(fw.get_log_summary())

    # ---- Rules ----
    @app.route("/api/rules")
    def get_rules():
        return jsonify({
            "rules": [r.to_dict() for r in fw.rule_engine.rules],
            "default_policy": fw.rule_engine.default_policy,
        })

    @app.route("/api/rules", methods=["POST"])
    def add_rule():
        data = request.json
        rule = FirewallRule.from_dict(data)
        fw.rule_engine.add_rule(rule)
        return jsonify({"status": "ok", "rule": rule.to_dict()})

    @app.route("/api/rules/<int:rule_id>", methods=["PUT"])
    def update_rule(rule_id):
        data = request.json
        rule = fw.rule_engine.update_rule(rule_id, data)
        if rule:
            return jsonify({"status": "ok", "rule": rule.to_dict()})
        return jsonify({"error": "Rule not found"}), 404

    @app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
    def delete_rule(rule_id):
        if fw.rule_engine.remove_rule(rule_id):
            return jsonify({"status": "ok"})
        return jsonify({"error": "Rule not found"}), 404

    # ---- Zones ----
    @app.route("/api/zones")
    def get_zones():
        return jsonify({
            "zones": fw.zone_manager.get_all_zones(),
            "policies": fw.zone_manager.get_all_policies(),
            "matrix": fw.zone_manager.get_zone_matrix(),
        })

    # ---- Connections ----
    @app.route("/api/connections")
    def get_connections():
        if fw.state_tracker:
            return jsonify({
                "connections": fw.state_tracker.get_connection_table(),
                "stats": fw.state_tracker.get_stats(),
            })
        return jsonify({"connections": [], "stats": {}})

    # ---- Packet Testing ----
    @app.route("/api/test-packet", methods=["POST"])
    def test_packet():
        data = request.json
        pkt = PacketParser.from_dict(data)
        result = fw.process_packet(pkt)
        return jsonify(result)

    # ---- Traffic Simulation ----
    @app.route("/api/simulate", methods=["POST"])
    def simulate_traffic():
        data = request.json
        traffic_type = data.get("type", "normal")
        count = min(int(data.get("count", 50)), 500)

        if traffic_type == "normal":
            packets = traffic_gen.generate_normal_traffic(count)
        elif traffic_type == "handshake":
            packets = traffic_gen.generate_tcp_handshake(
                data.get("src_ip", "192.168.1.10"),
                data.get("dst_ip", "8.8.8.8"),
                data.get("src_port", 54321),
                int(data.get("dst_port", 443)),
            )
        else:
            packets = traffic_gen.generate_attack_traffic(traffic_type, count)

        results = fw.process_batch(packets)
        
        allowed = sum(1 for r in results if r["action"] == "ALLOW")
        denied = sum(1 for r in results if r["action"] in ("DENY", "DROP"))

        return jsonify({
            "total": len(results),
            "allowed": allowed,
            "denied": denied,
            "results": results[-100:],  # Last 100 for display
        })

    @app.route("/api/simulate/stream", methods=["POST"])
    def toggle_stream():
        global simulation_running, simulation_thread
        data = request.json
        action = data.get("action", "start")

        if action == "start" and not simulation_running:
            simulation_running = True
            pps = float(data.get("pps", 5))

            def stream_traffic():
                global simulation_running
                gen = traffic_gen.generate_stream(pps)
                while simulation_running:
                    try:
                        pkt = next(gen)
                        fw.process_packet(pkt)
                    except StopIteration:
                        break

            simulation_thread = threading.Thread(target=stream_traffic, daemon=True)
            simulation_thread.start()
            return jsonify({"status": "started", "pps": pps})

        elif action == "stop":
            simulation_running = False
            return jsonify({"status": "stopped"})

        return jsonify({"status": "running" if simulation_running else "stopped"})

    print(f"\n  [*] Firewall Dashboard at http://localhost:{port}")
    print(f"  [*] Rules loaded: {len(fw.rule_engine.rules)}")
    print(f"  [*] Press Ctrl+C to stop\n")
    app.run(host=host, port=port, debug=False)


def main():
    parser = argparse.ArgumentParser(description="Firewall Simulator - Project 2")
    parser.add_argument("--web", "-w", action="store_true", help="Start web dashboard")
    parser.add_argument("--port", type=int, default=5001, help="Web server port")
    parser.add_argument("--simulate", "-s", action="store_true", help="Run traffic simulation")
    parser.add_argument("--demo", "-d", action="store_true", help="Run interactive demo")

    args = parser.parse_args()

    if args.web:
        start_web_server(port=args.port)
    elif args.simulate:
        banner()
        fw = init_firewall()
        print("[*] Running traffic simulation (200 packets)...")
        packets = traffic_gen.generate_normal_traffic(150)
        packets += traffic_gen.generate_attack_traffic("port_scan", 25)
        packets += traffic_gen.generate_attack_traffic("ot_intrusion", 25)
        results = fw.process_batch(packets)
        stats = fw.get_stats()
        print(f"[*] Results: {stats['allowed']} allowed, {stats['denied']} denied, {stats['dropped']} dropped")
    else:
        run_demo()


if __name__ == "__main__":
    main()
