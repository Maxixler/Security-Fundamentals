import os
import threading
from flask import Flask, jsonify, request, send_from_directory
from engine.packet_sniffer import MockPacketSniffer
from engine.signature_matcher import SignatureMatcher
from engine.ips_blocker import IPSBlocker

app = Flask(__name__, static_folder="dashboard")

sniffer = MockPacketSniffer()
matcher = SignatureMatcher()
ips = IPSBlocker()

# Sınırlı log saklama (son 50 log)
live_logs = []
MAX_LOGS = 50

def handle_packet(packet):
    src_ip = packet["src_ip"]
    
    # IPS Control: Zaten engelli mi?
    if ips.is_blocked(src_ip):
        packet["status"] = "BLOCKED"
        packet["reason"] = "IP is on hardware blacklist"
    else:
        # IDS Control: Yeni paket tehlikeli mi?
        matches = matcher.analyze_packet(packet)
        if matches:
            packet["status"] = "THREAT DETECTED"
            # En riskli aksiyonu seç
            actions = [m["action"] for m in matches]
            if "DROP" in actions:
                ips.block_ip(src_ip)
                packet["reason"] = f"Dropped and IP Banned: {matches[0]['msg']}"
            else:
                packet["reason"] = f"Alert Triggered: {matches[0]['msg']}"
        else:
            packet["status"] = "PASSED"
            packet["reason"] = "Clean Traffic"
            
    live_logs.append(packet)
    if len(live_logs) > MAX_LOGS:
        live_logs.pop(0)

@app.route("/")
def index():
    return send_from_directory("dashboard", "index.html")

@app.route("/<path:path>")
def serve_static(path):
    return send_from_directory("dashboard", path)

@app.route("/api/logs")
def get_logs():
    return jsonify({
        "logs": live_logs,
        "banned_ips": ips.get_active_bans()
    })

def start_ids():
    sniffer.start(handle_packet)

if __name__ == "__main__":
    start_ids()
    print("[*] IDS/IPS Live Tracker started. UI at http://localhost:5004")
    app.run(host="0.0.0.0", port=5004, use_reloader=False)
