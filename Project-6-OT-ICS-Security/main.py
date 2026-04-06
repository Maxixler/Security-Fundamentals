"""
OT/ICS Security Monitor - Main Application
=============================================
Comprehensive OT/ICS security monitoring platform with industrial
PLC simulation, Modbus traffic analysis, anomaly detection, and
SCADA HMI-style real-time dashboard.

This tool provides:
    1. Multi-Unit PLC Simulation (Boiler, Pump, Cooling, SIS)
    2. Physics-Based Process Dynamics
    3. 5-Layer OT Anomaly Detection
    4. Attack Simulation (Register manipulation, sabotage)
    5. IEC 62443 / NIST 800-82 Compliance Concepts
    6. Industrial SCADA-Style Dashboard

Usage:
    python main.py                 # Interactive mode
    python main.py --web           # Start SCADA HMI dashboard
    python main.py --simulate      # Run simulation only (CLI)
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

from simulation.plc_simulator import PLCSimulator
from monitor.anomaly_detector import OTAnomalyDetector


# ─── Application State ─────────────────────────────────────────────────
plc = PLCSimulator()
detector = OTAnomalyDetector()

ot_event_log = []
MAX_EVENTS = 60
simulation_running = False


def banner():
    print("""
    +---------------------------------------------------------------+
    |                                                               |
    |   OT / ICS SECURITY MONITOR                                  |
    |   OT/ICS Security Monitor v2.0                               |
    |   Security-Fundamentals Project 6                             |
    |                                                               |
    +---------------------------------------------------------------+
    """)


# ─── Simulation & Attack Engine ─────────────────────────────────────────

_ATTACK_SCENARIOS = [
    {"name": "Register Overwrite", "fc": 6, "address": 201, "value_range": (3500, 5000),
     "source": "45.2.3.11", "description": "Attempt to set pump RPM to dangerous level"},
    {"name": "Boiler Temperature Sabotage", "fc": 6, "address": 103, "value_range": (90, 100),
     "source": "91.205.174.26", "description": "Max-out fuel rate to overheat boiler"},
    {"name": "SIS Override Attack", "fc": 6, "address": 402, "value_range": (1, 1),
     "source": "103.11.22.44", "description": "Enable maintenance override during attack"},
    {"name": "Valve Manipulation", "fc": 6, "address": 102, "value_range": (0, 5),
     "source": "185.15.2.14", "description": "Close outlet valve to build pressure"},
    {"name": "Cooling Fan Disable", "fc": 6, "address": 301, "value_range": (0, 5),
     "source": "198.51.100.23", "description": "Disable cooling fans to cause overheating"},
]


def run_simulation():
    """Background thread: PLC physics + random Modbus traffic + attacks."""
    global simulation_running
    simulation_running = True
    print("  [*] OT simulation engine started")
    print("  [*] Units: Boiler | Pump | Cooling | SIS")
    print(f"  [*] {len(plc.REGISTER_MAP)} registers active\n")

    tick_count = 0
    while simulation_running:
        time.sleep(random.uniform(0.5, 2.0))
        tick_count += 1

        # Update PLC physics
        tick_result = plc.tick(dt=1.0)

        # Generate normal Modbus traffic (reads + safe writes)
        if random.random() > 0.3:
            _simulate_normal_operation()

        # Attack simulation (15% chance each tick)
        if random.random() > 0.85:
            _simulate_attack()

        # Log alarms
        for alarm in tick_result.get("alarms", []):
            event = {
                "time": time.strftime("%H:%M:%S"),
                "type": "ALARM",
                "severity": alarm["severity"],
                "message": alarm["message"],
            }
            ot_event_log.insert(0, event)
            if len(ot_event_log) > MAX_EVENTS:
                ot_event_log.pop()


def _simulate_normal_operation():
    """Simulate normal SCADA operations (reads and safe writes)."""
    # Normal register read
    address = random.choice(list(plc.REGISTER_MAP.keys()))
    value = plc.read_register(address)

    # Occasional safe writes from authorized HMI
    if random.random() > 0.7:
        writable = [a for a, c in plc.REGISTER_MAP.items() if not c["readonly"]]
        addr = random.choice(writable)
        config = plc.REGISTER_MAP[addr]
        safe_value = random.randint(config["min"], config["max"])

        command = {
            "function_code": 6,
            "address": addr,
            "value": safe_value,
            "source_ip": "10.0.0.5",
        }
        analysis = detector.analyze_command(command, plc.REGISTER_MAP)
        if not analysis["is_alert"]:
            plc.write_register(addr, safe_value)

        event = {
            "time": time.strftime("%H:%M:%S"),
            "type": "WRITE" if not analysis["is_alert"] else "BLOCKED",
            "severity": "Info" if not analysis["is_alert"] else analysis["severity"],
            "message": f"HMI Write: Reg {addr} = {safe_value} ({analysis['message'][:60]})",
        }
        ot_event_log.insert(0, event)
        if len(ot_event_log) > MAX_EVENTS:
            ot_event_log.pop()


def _simulate_attack():
    """Simulate a malicious Modbus command."""
    scenario = random.choice(_ATTACK_SCENARIOS)
    value = random.randint(*scenario["value_range"])

    command = {
        "function_code": scenario["fc"],
        "address": scenario["address"],
        "value": value,
        "source_ip": scenario["source"],
    }

    analysis = detector.analyze_command(command, plc.REGISTER_MAP)

    # If detection failed (unlikely), apply the attack
    if not analysis["is_alert"]:
        plc.write_register(scenario["address"], value)

    event = {
        "time": time.strftime("%H:%M:%S"),
        "type": "ATTACK",
        "severity": analysis.get("severity", "High"),
        "message": f"⚠ {scenario['name']}: {scenario['description']} (SRC: {scenario['source']})",
    }
    ot_event_log.insert(0, event)
    if len(ot_event_log) > MAX_EVENTS:
        ot_event_log.pop()

    print(f"  [ATTACK] {scenario['name']} from {scenario['source']} — {analysis['action']}")


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
    state = plc.get_state()
    return jsonify({
        "plc": state,
        "security": {
            "alerts": detector.get_alerts()[:15],
            "stats": detector.get_stats(),
        },
        "events": ot_event_log[:20],
    })


@app.route("/api/write", methods=["POST"])
def write_register():
    """HMI write endpoint (simulates authenticated operator action)."""
    data = request.json or {}
    addr = data.get("address", 0)
    value = data.get("value", 0)

    command = {"function_code": 6, "address": addr, "value": value, "source_ip": "HMI"}
    analysis = detector.analyze_command(command, plc.REGISTER_MAP)

    if analysis["is_alert"]:
        return jsonify({"success": False, "message": analysis["message"]}), 400

    result = plc.write_register(addr, value)
    return jsonify(result)


@app.route("/api/reset-sis", methods=["POST"])
def reset_sis():
    """Reset Safety Instrumented System (emergency shutdown)."""
    plc.registers[400] = 0
    return jsonify({"success": True, "message": "SIS reset — system resuming normal operation"})


# ─── Interactive CLI ────────────────────────────────────────────────────
def interactive_mode():
    banner()
    sim_thread = threading.Thread(target=run_simulation, daemon=True)
    sim_thread.start()
    time.sleep(1)

    while True:
        print("\n" + "=" * 55)
        print("  OT/ICS SECURITY CONTROL PANEL")
        print("=" * 55)
        print("  1. View PLC Register State")
        print("  2. View Active Alarms")
        print("  3. View Security Alerts")
        print("  4. View Event Log")
        print("  5. Manual Register Write (HMI)")
        print("  6. Trigger Attack Simulation")
        print("  7. Start SCADA Dashboard (Web)")
        print("  8. Exit")
        print("=" * 55)

        choice = input("\n  Select option [1-8]: ").strip()

        if choice == "1":
            _cli_registers()
        elif choice == "2":
            _cli_alarms()
        elif choice == "3":
            _cli_security_alerts()
        elif choice == "4":
            _cli_events()
        elif choice == "5":
            _cli_write_register()
        elif choice == "6":
            _simulate_attack()
            print("  [*] Attack simulation triggered")
        elif choice == "7":
            _start_dashboard()
        elif choice == "8":
            print("\n  [*] OT monitor shutting down. Stay safe! 🏭")
            sys.exit(0)


def _cli_registers():
    print("\n  ─── PLC REGISTER STATE ───\n")
    for addr in sorted(plc.REGISTER_MAP.keys()):
        config = plc.REGISTER_MAP[addr]
        value = plc.registers.get(addr, 0)
        ro = "RO" if config["readonly"] else "RW"
        bar_len = int((value - config["min"]) / max(1, config["max"] - config["min"]) * 20)
        bar = "█" * bar_len + "░" * (20 - bar_len)
        print(f"  [{ro}] {addr:4d} {config['name']:25s} [{bar}] {value:6d} {config['unit']}")


def _cli_alarms():
    alarms = plc.alarm_log[:10]
    print(f"\n  ─── ACTIVE ALARMS ({len(alarms)}) ───\n")
    for a in alarms:
        icon = "🔴" if a["severity"] == "Critical" else "🟠" if a["severity"] == "High" else "🟡"
        print(f"  {icon} {a['message']}")


def _cli_security_alerts():
    alerts = detector.get_alerts()[:10]
    print(f"\n  ─── SECURITY ALERTS ({len(alerts)}) ───\n")
    for a in alerts:
        icon = "🔴" if a["severity"] == "Critical" else "🟠" if a["severity"] == "High" else "🟡"
        print(f"  {icon} [{a['severity']}] {a['message']}")
        print(f"     SRC: {a['source_ip']} | REG: {a['register']} | ACTION: {a['action']}")


def _cli_events():
    print(f"\n  ─── EVENT LOG ({len(ot_event_log)}) ───\n")
    for e in ot_event_log[:10]:
        icon = "🔴" if e["type"] == "ATTACK" else "🟡" if e["type"] == "ALARM" else "🟢"
        print(f"  {icon} [{e['time']}] {e['type']:8s} | {e['message'][:70]}")


def _cli_write_register():
    try:
        addr = int(input("\n  Register address: ").strip())
        value = int(input("  Value: ").strip())
        result = plc.write_register(addr, value)
        if result["success"]:
            print(f"  [+] Write successful: Reg {addr} = {value}")
        else:
            print(f"  [!] Write failed: {result['error']}")
    except ValueError:
        print("  [!] Invalid input.")


def _start_dashboard(port=5006):
    print(f"\n  [*] Starting SCADA HMI Dashboard on http://localhost:{port}")
    print("  [*] Press Ctrl+C to stop\n")
    app.run(host="0.0.0.0", port=port, debug=False)


# ─── Entry Point ────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="OT/ICS Security Monitor — Security-Fundamentals Project 6",
    )
    parser.add_argument("--web", "-w", action="store_true", help="Start SCADA dashboard")
    parser.add_argument("--port", type=int, default=5006, help="Dashboard port")
    parser.add_argument("--simulate", "-s", action="store_true", help="Run simulation only")

    args = parser.parse_args()

    sim_thread = threading.Thread(target=run_simulation, daemon=True)
    sim_thread.start()

    if args.web:
        banner()
        _start_dashboard(args.port)
    elif args.simulate:
        banner()
        print("  [*] Running OT simulation. Press Ctrl+C to stop.\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n  [*] Simulation stopped.")
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
