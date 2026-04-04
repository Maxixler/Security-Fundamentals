import os
import threading
from flask import Flask, jsonify, request, send_from_directory
from collectors import SyslogCollector, AuthLogCollector, FirewallLogCollector
from engine import Normalizer, Alerter, Correlator
from database.sqlite_manager import DatabaseManager

app = Flask(__name__, static_folder="dashboard")
db = DatabaseManager(db_path=":memory:")
alerter = Alerter()
correlator = Correlator(alerter)

# Load Rules
rules_path = os.path.join(os.path.dirname(__file__), "rules", "detection_rules.json")
correlator.load_rules(rules_path)

# Ensure alerts are stored
alerter.on_alert_generated = db.insert_alert

# Create Collectors
col_syslog = SyslogCollector()
col_auth = AuthLogCollector()
col_fw = FirewallLogCollector()

def handle_log(raw_log):
    normalized = Normalizer.normalize(raw_log)
    db.insert_event(normalized)
    correlator.process_event(normalized)

@app.route("/")
def index():
    return send_from_directory("dashboard", "index.html")

@app.route("/<path:path>")
def serve_static(path):
    return send_from_directory("dashboard", path)

@app.route("/api/events")
def get_events():
    return jsonify(db.get_recent_events(100))

@app.route("/api/alerts")
def get_alerts():
    return jsonify(db.get_recent_alerts(50))

@app.route("/api/stats")
def get_stats():
    events = db.get_recent_events(1000)
    alerts = db.get_recent_alerts(1000)
    counts_by_source = {}
    for e in events:
        counts_by_source[e["source_type"]] = counts_by_source.get(e["source_type"], 0) + 1
    
    return jsonify({
        "total_events": len(events),
        "total_alerts": len(alerts),
        "by_source": counts_by_source
    })

def start_siem():
    col_syslog.start(handle_log)
    col_auth.start(handle_log)
    col_fw.start(handle_log)

if __name__ == "__main__":
    start_siem()
    print("[*] SIEM Engine started. Dashboard at http://localhost:5002")
    app.run(host="0.0.0.0", port=5002, use_reloader=False)
