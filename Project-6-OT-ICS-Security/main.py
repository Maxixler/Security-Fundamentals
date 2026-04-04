"""
Main Execution Script for Project 6: OT/ICS Security Monitor
Provides a Flask web dashboard (HMI) that reads from the PLC and displays metrics & alerts.
"""

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
import os
import json
import threading
import sys
import argparse
import asyncio

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from simulation.modbus_server import RefineryPLCSimulator
from simulation.modbus_client import SCADAClient
from monitor.anomaly_detector import OTAnomalyDetector

app = Flask(__name__, static_folder='dashboard')
CORS(app)

# Global variables for bridging components
scada_client = SCADAClient()

@app.route('/')
def index():
    return send_from_directory('dashboard', 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory('dashboard', filename)

@app.route('/api/metrics')
def get_metrics():
    metrics = scada_client.read_metrics()
    if metrics:
        return jsonify({"status": "online", "data": metrics})
    return jsonify({"status": "offline", "data": None})

@app.route('/api/alerts')
def get_alerts():
    alert_file = os.path.join(os.path.dirname(__file__), "ot_alerts.json")
    if os.path.exists(alert_file):
        with open(alert_file, "r") as f:
            try:
                alerts = json.load(f)
                # Return newest first
                return jsonify({"alerts": alerts[::-1]})
            except:
                pass
    return jsonify({"alerts": []})

def start_plc_server():
    simulator = RefineryPLCSimulator()
    asyncio.run(simulator.run_server())

def start_ot_monitor():
    detector = OTAnomalyDetector()
    detector.monitor_loop()

def main():
    parser = argparse.ArgumentParser(description="Industrial OT/ICS Security Simulator")
    parser.add_argument("--web", action="store_true", help="Start Web HMI Dashboard")
    args = parser.parse_args()

    print("[*] Starting OT Security Environment...")
    
    # 1. Start Modbus PLC in background
    plc_thread = threading.Thread(target=start_plc_server, daemon=True)
    plc_thread.start()
    
    # 2. Start OT Monitor in background
    monitor_thread = threading.Thread(target=start_ot_monitor, daemon=True)
    monitor_thread.start()

    # 3. Start Web Dashboard if requested
    if args.web:
        print("[*] Starting Web HMI on http://localhost:5002")
        app.run(host="0.0.0.0", port=5002, debug=False)
    else:
        print("[*] Running in standalone mode. Press Ctrl+C to exit.")
        try:
            while True:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Shutting down OT environment.")

if __name__ == "__main__":
    main()
