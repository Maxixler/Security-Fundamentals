"""
OT Anomaly Detector
This monitor continuously polls the PLC (simulating a passive OT IDS)
and checks for suspicious changes in safety registers, alerting security teams.
"""
import time
import json
import os
from datetime import datetime
from simulation.modbus_client import SCADAClient

LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "ot_alerts.json")

class OTAnomalyDetector:
    def __init__(self, host="127.0.0.1", port=5020):
        self.scada = SCADAClient(host, port)
        self.baseline_temp_threshold = 450
        self.baseline_press_threshold = 80
        self.alerts = []

    def log_alert(self, severity, message, details):
        alert = {
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "message": message,
            "details": details
        }
        self.alerts.append(alert)
        print(f"[{severity.upper()}] {message}")
        
        # Save to file for dashboard
        with open(LOG_FILE, "w") as f:
            json.dump(self.alerts[-50:], f) # Keep last 50 alerts

    def monitor_loop(self):
        print("Starting OT Security Monitor...")
        while not self.scada.connect():
            print("Waiting for PLC to come online...")
            time.sleep(2)
            
        print("Connected to OT Network. Baseline established.")
        
        while True:
            metrics = self.scada.read_metrics()
            if not metrics:
                self.log_alert("CRITICAL", "Loss of View", "Could not read metrics from PLC. Possible DoS or network failure.")
                time.sleep(2)
                continue

            # 1. Check for Safety Threshold Manipulation
            if metrics["threshold_temp"] != self.baseline_temp_threshold:
                self.log_alert("CRITICAL", "Safety Threshold Altered!", 
                              f"Max Temperature changed from {self.baseline_temp_threshold} to {metrics['threshold_temp']}")
                self.baseline_temp_threshold = metrics["threshold_temp"]

            if metrics["threshold_pressure"] != self.baseline_press_threshold:
                self.log_alert("CRITICAL", "Safety Threshold Altered!", 
                              f"Max Pressure changed from {self.baseline_press_threshold} to {metrics['threshold_pressure']}")
                self.baseline_press_threshold = metrics["threshold_pressure"]

            # 2. Check for physical anomalies
            if metrics["temperature"] > 400:
                self.log_alert("HIGH", "Physical Anomaly", f"Boiler temperature dangerously high: {metrics['temperature']}C")

            time.sleep(1)

if __name__ == "__main__":
    detector = OTAnomalyDetector()
    detector.monitor_loop()
