"""
Main Orchestrator for Project 3: Enterprise SIEM & SOC Dashboard
Runs the web dashboard and a background log simulator to feed the SIEM.
"""
from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
import threading
import time
import random
import os
import argparse

from siem.log_aggregator import LogAggregator
from siem.correlation_engine import CorrelationEngine

app = Flask(__name__, static_folder='dashboard')
CORS(app)

aggregator = LogAggregator()
correlator = CorrelationEngine()

# Global state for UI to access
system_alerts = []
historical_logs = []

def generate_simulated_logs():
    """Background simulator acting as various enterprise systems."""
    print(">> Starting Log Generation Simulation...")
    
    ips = ["192.168.1.100", "10.0.0.5", "185.15.2.14", "45.2.3.11", "8.8.8.8"]
    
    while True:
        time.sleep(random.randint(1, 3))
        
        scenario = random.choice(["normal_fw", "bad_fw", "ad_brute", "ad_success"])
        
        raw_log = ""
        log_type = ""
        
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        if scenario == "normal_fw":
            log_type = "firewall"
            raw_log = f"{timestamp} [FIREWALL] ALLOW SRC=10.0.0.50 DST=10.0.0.5 DPORT=443"
            
        elif scenario == "bad_fw":
            log_type = "firewall"
            attacker = random.choice(["185.15.2.14", "103.11.22.44"])
            raw_log = f"{timestamp} [FIREWALL] DENY SRC={attacker} DST=10.0.0.5 DPORT=3389"
            
        elif scenario == "ad_brute":
            log_type = "active_directory"
            attacker = "45.2.3.11"
            # Simulate a burst of brute force attempts
            for _ in range(3):
                raw_log = f'{{"EventID": 4625, "TimeCreated": "{timestamp}", "TargetUserName": "admin", "IpAddress": "{attacker}"}}'
                norm = aggregator.ingest_log(log_type, raw_log)
                if norm:
                    historical_logs.insert(0, norm)
                    correlator.analyze(norm)
            continue # Already analyzed the burst

        elif scenario == "ad_success":
            log_type = "active_directory"
            raw_log = f'{{"EventID": 4624, "TimeCreated": "{timestamp}", "TargetUserName": "jdoe", "IpAddress": "192.168.1.100"}}'

        # Process the single log
        norm = aggregator.ingest_log(log_type, raw_log)
        if norm:
            historical_logs.insert(0, norm)
            if len(historical_logs) > 50: historical_logs.pop()
            correlator.analyze(norm)
            
        # Pull any generated alerts
        new_incidents = correlator.get_new_incidents()
        for inc in new_incidents:
            inc["timestamp"] = time.strftime("%H:%M:%S")
            system_alerts.insert(0, inc)
        if len(system_alerts) > 20: system_alerts.pop()


# --- API Routes ---
@app.route('/')
def index():
    return send_from_directory('dashboard', 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory('dashboard', filename)

@app.route('/api/status')
def get_status():
    return jsonify({
        "alerts": system_alerts,
        "recent_logs": historical_logs[:10]
    })

def main():
    parser = argparse.ArgumentParser(description="Enterprise SIEM Simulator")
    parser.add_argument("--web", action="store_true", help="Start Web Dashboard")
    args = parser.parse_args()

    # Start simulation thread
    threading.Thread(target=generate_simulated_logs, daemon=True).start()

    if args.web:
        print("[*] Starting SIEM SOC Dashboard on http://localhost:5003")
        app.run(host="0.0.0.0", port=5003, debug=False)
    else:
        print("[*] Running purely in terminal. Press Ctrl+C to exit.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    main()
