"""
SIEM Dashboard - Main Application
====================================
Enterprise Security Information & Event Management system with
real-time log aggregation, correlation, anomaly detection, and
threat intelligence enrichment.

This tool provides:
    1. Multi-Source Log Collection (Firewall, AD, Web, DNS, VPN, Syslog)
    2. CEF Normalization & Parsing
    3. Correlation Engine with MITRE ATT&CK Mapping
    4. Statistical Anomaly Detection (Z-Score Baseline)
    5. Threat Intelligence Enrichment (IP reputation, GeoIP)
    6. Real-Time SOC Dashboard with Alert Management

Usage:
    python main.py                 # Interactive mode
    python main.py --web           # Start web dashboard
    python main.py --simulate      # Run log simulator only (CLI)

DISCLAIMER: This is a portfolio demonstration of SIEM concepts.
It simulates enterprise log sources for educational purposes.
"""

import argparse
import json
import sys
import os
import threading
import time
import random
from typing import Callable, Tuple, Optional, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS

from siem.application import get_application_state
from siem.log_aggregator import LogAggregator, NormalizedEvent
from siem.correlation_engine import CorrelationEngine
from siem.threat_intel import ThreatIntelFeed
from siem.anomaly_detector import AnomalyDetector


# ─── Application State ─────────────────────────────────────────────────
app_state = get_application_state()


def banner():
    print("""
    +---------------------------------------------------------------+
    |                                                               |
    |   ____  ___ _____ __  __                                      |
    |  / ___|/ _ \\_   _|  \\/  |                                     |
    |  \\___ \\  __/ | | | |\\/| |                                     |
    |  |___/ \\___| |_| |_|  |_|                                     |
    |                                                               |
    |   Enterprise SOC / SIEM Dashboard v2.0                        |
    |   Security-Fundamentals Project 3                             |
    |                                                               |
    +---------------------------------------------------------------+
    """)


# ─── Log Simulation Engine ─────────────────────────────────────────────
# Simulates various enterprise log sources feeding the SIEM

_INTERNAL_IPS = ["10.0.0.5", "10.0.0.10", "10.0.0.50", "10.0.0.200",
                 "192.168.1.100", "192.168.1.150", "172.16.0.50"]
_EXTERNAL_IPS = ["185.15.2.14", "45.2.3.11", "103.11.22.44", "91.205.174.26",
                 "198.51.100.23", "8.8.8.8", "1.1.1.1"]
_USERS = ["admin", "jdoe", "ssmith", "mwilson", "klee", "cjohnson", "root", "service_acct"]
_WEB_URIS = [
    "/index.html", "/api/users", "/login", "/dashboard", "/images/logo.png",
    "/api/reports", "/static/app.js", "/health", "/admin/settings",
]
_MALICIOUS_URIS = [
    "/search?q=1' OR 1=1--", "/admin?cmd=<script>alert(1)</script>",
    "/../../../../etc/passwd", "/wp-admin/install.php", "/.env",
    "/api/users?id=1 UNION SELECT * FROM credentials",
]
_DOMAINS = [
    "google.com", "microsoft.com", "github.com", "internal.corp",
    "evil-c2.tk", "suspicious-domain.xyz", "phishing-bank.ml",
    "a" * 70 + ".tunnel.io",  # DNS tunnel candidate (long domain)
]


def _generate_firewall_log() -> tuple:
    """Generate a simulated firewall log entry."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    scenario = random.random()

    if scenario > 0.85:
        # Malicious: external → internal, critical ports
        src = random.choice(_EXTERNAL_IPS[:4])
        dst = random.choice(_INTERNAL_IPS[:4])
        port = random.choice([22, 3389, 445, 502, 1433, 5432])
        action = "DENY"
    elif scenario > 0.7:
        # Suspicious: external → internal, common ports
        src = random.choice(_EXTERNAL_IPS)
        dst = random.choice(_INTERNAL_IPS)
        port = random.choice([80, 443, 8080, 8443])
        action = random.choice(["ALLOW", "DENY"])
    else:
        # Normal: internal traffic
        src = random.choice(_INTERNAL_IPS)
        dst = random.choice(_INTERNAL_IPS)
        port = random.choice([80, 443, 53, 88, 389, 636])
        action = "ALLOW"

    raw = f"{ts} [FIREWALL] {action} SRC={src} DST={dst} DPORT={port}"
    return "firewall", raw


def _generate_ad_log() -> tuple:
    """Generate a simulated Active Directory event log."""
    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
    scenario = random.random()

    if scenario > 0.85:
        # Failed login from suspicious IP
        event_id = 4625
        user = random.choice(["admin", "root", "administrator", "sa"])
        ip = random.choice(_EXTERNAL_IPS[:4])
    elif scenario > 0.7:
        # Failed login from internal
        event_id = 4625
        user = random.choice(_USERS)
        ip = random.choice(_INTERNAL_IPS)
    elif scenario > 0.6:
        # Account changes
        event_id = random.choice([4720, 4726, 4732])
        user = random.choice(_USERS)
        ip = random.choice(_INTERNAL_IPS[:4])
    else:
        # Successful login
        event_id = 4624
        user = random.choice(_USERS)
        ip = random.choice(_INTERNAL_IPS)

    raw = json.dumps({
        "EventID": event_id,
        "TimeCreated": ts,
        "TargetUserName": user,
        "IpAddress": ip,
        "WorkstationName": f"WS-{random.randint(100, 999)}",
        "LogonType": random.choice([2, 3, 10]),
    })
    return "active_directory", raw


def _generate_web_log() -> tuple:
    """Generate a simulated web server log entry."""
    ts = time.strftime("%d/%b/%Y:%H:%M:%S +0000")
    scenario = random.random()

    if scenario > 0.9:
        # Malicious request
        ip = random.choice(_EXTERNAL_IPS[:4])
        uri = random.choice(_MALICIOUS_URIS)
        status = random.choice([403, 500, 200])
        method = "GET"
    elif scenario > 0.8:
        # Recon attempt
        ip = random.choice(_EXTERNAL_IPS)
        uri = random.choice(["/.env", "/wp-admin", "/phpmyadmin", "/.git/config"])
        status = 404
        method = "GET"
    else:
        # Normal request
        ip = random.choice(_INTERNAL_IPS + _EXTERNAL_IPS[4:])
        uri = random.choice(_WEB_URIS)
        status = random.choice([200, 200, 200, 301, 304])
        method = random.choice(["GET", "GET", "GET", "POST"])

    user = random.choice(["-", "-", "-", "jdoe", "admin"])
    bytes_sent = random.randint(200, 50000)
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    raw = f'{ip} - {user} [{ts}] "{method} {uri} HTTP/1.1" {status} {bytes_sent} "-" "{ua}"'
    return "web_server", raw


def _generate_dns_log() -> tuple:
    """Generate a simulated DNS query log."""
    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
    ip = random.choice(_INTERNAL_IPS + _EXTERNAL_IPS[4:])
    domain = random.choice(_DOMAINS)
    qtype = random.choice(["A", "A", "AAAA", "MX", "TXT"])
    port = random.randint(49152, 65535)
    raw = f"{ts} {ip}#{port} query: {domain} {qtype} IN"
    return "dns", raw


def _generate_vpn_log() -> tuple:
    """Generate a simulated VPN authentication log."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    scenario = random.random()

    if scenario > 0.8:
        action = "AUTH_FAIL"
        user = random.choice(["admin", "root", "service_acct"])
        ip = random.choice(_EXTERNAL_IPS[:3])
    elif scenario > 0.3:
        action = "CONNECT"
        user = random.choice(_USERS)
        ip = random.choice(_EXTERNAL_IPS[4:] + _INTERNAL_IPS[:3])
    else:
        action = "DISCONNECT"
        user = random.choice(_USERS)
        ip = random.choice(_INTERNAL_IPS)

    raw = f"{ts} [VPN] {action} USER={user} IP={ip} TUNNEL=ipsec-corp"
    return "vpn", raw


_LOG_GENERATORS = [
    (_generate_firewall_log, 3),    # Weight 3 — most common
    (_generate_ad_log, 2),          # Weight 2
    (_generate_web_log, 2),         # Weight 2
    (_generate_dns_log, 2),         # Weight 2
    (_generate_vpn_log, 1),         # Weight 1 — least common
]


def _pick_generator():
    """Weighted random selection of log generator."""
    choices = []
    for gen, weight in _LOG_GENERATORS:
        choices.extend([gen] * weight)
    return random.choice(choices)


def run_simulation() -> None:
    """
    Background thread that continuously generates simulated enterprise logs,
    feeds them through the aggregator → correlator → anomaly detector pipeline,
    and populates the alert/log buffers for the dashboard.
    """
    app_state.start_simulation()
    print("  [*] Log simulation engine started (5 sources active)")

    while app_state.is_simulation_running():
        # Random delay to simulate realistic log arrival patterns
        time.sleep(random.uniform(0.3, 2.0))

        # Occasionally generate bursts (simulate attacks)
        burst_count: int = 1
        if random.random() > 0.92:
            burst_count = random.randint(3, 8)  # Attack burst

        for _ in range(burst_count):
            generator: Callable[[], Tuple[str, str]] = _pick_generator()
            log_type: str
            raw_log: str
            log_type, raw_log = generator()

            # Step 1: Ingest & normalize
            event: Optional[NormalizedEvent] = app_state.aggregator.ingest_log(log_type, raw_log)
            if not event:
                continue

            # Add to historical log buffer
            event_dict: Dict[str, Any] = event.to_dict()
            app_state.add_log(event_dict)

            app_state.increment_events_processed()

            # Step 2: Anomaly detection (both statistical and ML)
            app_state.anomaly_detector.process_event(event_dict)

            # Also process with ML detector if trained
            if app_state.ml_anomaly_detector.is_trained:
                ml_is_anomaly: bool
                ml_confidence: float
                ml_details: Dict[str, Any]
                ml_is_anomaly, ml_confidence, ml_details = app_state.ml_anomaly_detector.predict_anomaly(event_dict)
                # Optionally log ML predictions for debugging
                if ml_is_anomaly and ml_confidence > 0.7:
                    print(f"  [ML] High confidence anomaly detected: {ml_confidence:.2f}")

            # Add event to ML training buffer for continuous learning
            app_state.add_event_for_ml_training(event_dict)

            # Step 3: Correlation
            incident: Optional[Incident] = app_state.correlator.analyze(event)
            if incident:
                alert_data: Dict[str, Any] = incident.to_dict()
                app_state.add_alert(alert_data)


# ─── Flask Web Application ─────────────────────────────────────────────
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
    """Main polling endpoint for the dashboard."""
    return jsonify({
        "alerts": app_state.get_alerts(limit=20),
        "recent_logs": app_state.get_logs(limit=15),
        "stats": app_state.get_stats(),
    })


@app.route("/api/alerts")
def get_alerts():
    """Get all alerts with optional severity filter."""
    severity = request.args.get("severity", "").lower()
    alerts = app_state.get_alerts(severity_filter=severity if severity else None)
    return jsonify({"alerts": alerts, "total": len(alerts)})


@app.route("/api/logs")
def get_logs():
    """Get recent logs with optional source filter."""
    source = request.args.get("source", "")
    count = min(int(request.args.get("count", 50)), 100)  # MAX_LOGS from ApplicationState
    logs = app_state.get_logs(limit=count, source_filter=source if source else None)
    return jsonify({"logs": logs, "total": app_state.get_log_count()})


@app.route("/api/search", methods=["POST"])
def search_logs():
    """Full-text search across historical logs."""
    data = request.json or {}
    query = data.get("query", "").lower()
    source_filter = data.get("source", "")
    severity_min = data.get("severity_min", 0)

    results = []
    for log in historical_logs:
        # Source filter
        if source_filter and log.get("source_type") != source_filter:
            continue
        # Severity filter
        if log.get("severity", 0) < severity_min:
            continue
        # Text search
        if query:
            searchable = json.dumps(log).lower()
            if query not in searchable:
                continue
        results.append(log)

    return jsonify({"results": results[:50], "total": len(results)})


@app.route("/api/mitre")
def get_mitre_map():
    """Get MITRE ATT&CK mapping from detected incidents."""
    from siem.correlation_engine import MITRE_MAPPING
    # Count detections per technique from alerts
    technique_counts = {}
    for alert in system_alerts:
        mitre = alert.get("mitre", {})
        tech_id = mitre.get("technique", "")
        if tech_id:
            if tech_id not in technique_counts:
                technique_counts[tech_id] = {**mitre, "count": 0}
            technique_counts[tech_id]["count"] += 1

    return jsonify({"mapping": list(technique_counts.values())})


@app.route("/api/threat-intel/<ip>")
def get_ti_details(ip):
    """Get detailed threat intelligence for a specific IP."""
    ti = ThreatIntelFeed()
    return jsonify(ti.check_ip(ip))


# ─── Interactive CLI Mode ───────────────────────────────────────────────
def interactive_mode():
    """Run the SIEM in interactive terminal mode."""
    banner()
    print("  [*] Enterprise SIEM System — Interactive Mode")
    print("  [*] Log simulation running in background\n")

    # Start simulation thread
    sim_thread = threading.Thread(target=run_simulation, daemon=True)
    sim_thread.start()

    time.sleep(1)  # Let simulation warm up

    while True:
        print("\n" + "=" * 55)
        print("  SIEM CONTROL PANEL")
        print("=" * 55)
        print("  1. View Recent Alerts")
        print("  2. View Recent Logs")
        print("  3. View Ingestion Statistics")
        print("  4. Search Logs")
        print("  5. View Threat Intelligence Report")
        print("  6. View Anomaly Baselines")
        print("  7. Start Web Dashboard")
        print("  8. Exit")
        print("=" * 55)

        choice = input("\n  Select option [1-8]: ").strip()

        if choice == "1":
            _cli_view_alerts()
        elif choice == "2":
            _cli_view_logs()
        elif choice == "3":
            _cli_view_stats()
        elif choice == "4":
            _cli_search_logs()
        elif choice == "5":
            _cli_threat_intel()
        elif choice == "6":
            _cli_anomaly_baselines()
        elif choice == "7":
            _start_web_dashboard()
        elif choice == "8":
            print("\n  [*] Shutting down SIEM system. Stay vigilant! 🛡️")
            sys.exit(0)
        else:
            print("  [!] Invalid option. Try again.")


def _cli_view_alerts():
    """Display recent security alerts in the terminal."""
    print(f"\n  ─── SECURITY ALERTS ({len(system_alerts)} total) ───\n")
    if not system_alerts:
        print("  No alerts yet. Monitoring active...")
        return
    for alert in system_alerts[:10]:
        sev = alert.get("severity", "?")
        desc = alert.get("description", "")
        src = alert.get("src_ip", "")
        mitre = alert.get("mitre", {}).get("technique", "")
        icon = "🔴" if sev == "Critical" else "🟠" if sev == "High" else "🟡"
        print(f"  {icon} [{sev:8s}] {desc}")
        if mitre:
            print(f"            MITRE: {mitre} | SRC: {src}")


def _cli_view_logs():
    """Display recent normalized logs."""
    print(f"\n  ─── RECENT LOGS ({len(historical_logs)} buffered) ───\n")
    for log in historical_logs[:10]:
        ts = log.get("timestamp", "?")
        src = log.get("source_type", "?")
        evt = log.get("event_type", "?")
        act = log.get("action", "?")
        ip = log.get("src_ip", "?")
        ts_short = ts.split("T")[-1][:8] if "T" in ts else ts.split(" ")[-1][:8]
        print(f"  [{ts_short}] {src:18s} | {evt:20s} | {act:8s} | {ip}")


def _cli_view_stats():
    """Display ingestion statistics."""
    stats = aggregator.get_stats()
    print("\n  ─── INGESTION STATISTICS ───\n")
    for key, val in stats.items():
        print(f"    {key:20s}: {val}")


def _cli_search_logs():
    """Interactive log search."""
    query = input("\n  Search query: ").strip()
    if not query:
        print("  [!] Empty query.")
        return

    results = []
    query_lower = query.lower()
    for log in historical_logs:
        if query_lower in json.dumps(log).lower():
            results.append(log)

    print(f"\n  Found {len(results)} matching logs:\n")
    for log in results[:10]:
        print(f"    {log.get('timestamp', '?')} | {log.get('source_type', '?')} | {log.get('description', '?')}")


def _cli_threat_intel():
    """Display threat intelligence report."""
    ti = ThreatIntelFeed()
    print("\n  ─── THREAT INTELLIGENCE REPORT ───\n")

    test_ips = ["185.15.2.14", "45.2.3.11", "103.11.22.44", "91.205.174.26", "198.51.100.23"]
    for ip in test_ips:
        data = ti.check_ip(ip)
        icon = "🔴" if data["threat_score"] >= 80 else "🟠" if data["threat_score"] >= 50 else "🟡"
        print(f"  {icon} {ip:20s} Score: {data['threat_score']:3d} | "
              f"{data['country']:5s} | {data['threat_type']:20s} | Actor: {data.get('actor', 'N/A')}")


def _cli_anomaly_baselines():
    """Display anomaly detection baselines."""
    baselines = anomaly_detector.get_baseline_status()
    print("\n  ─── ANOMALY DETECTION BASELINES ───\n")
    for name, status in baselines.items():
        print(f"    {name:25s}: mean={status['mean']:8.2f} | "
              f"std={status['std_dev']:8.2f} | obs={status['total_observations']}")


def _start_web_dashboard(port=5003):
    """Start the Flask web dashboard."""
    print(f"\n  [*] Starting SIEM SOC Dashboard on http://localhost:{port}")
    print("  [*] Press Ctrl+C to stop\n")
    app.run(host="0.0.0.0", port=port, debug=False)


# ─── Entry Point ────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Enterprise SIEM & SOC Dashboard — Security-Fundamentals Project 3",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--web", "-w", action="store_true", help="Start web dashboard directly")
    parser.add_argument("--port", type=int, default=5003, help="Web dashboard port (default: 5003)")
    parser.add_argument("--simulate", "-s", action="store_true", help="Run log simulator only (terminal)")

    args = parser.parse_args()

    # Always start the simulation thread
    sim_thread = threading.Thread(target=run_simulation, daemon=True)
    sim_thread.start()

    if args.web:
        banner()
        _start_web_dashboard(args.port)
    elif args.simulate:
        banner()
        print("  [*] Running log simulator in terminal mode. Press Ctrl+C to stop.\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n  [*] Simulation stopped.")
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
