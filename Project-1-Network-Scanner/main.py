"""
Network Scanner - Main Application
===================================
A comprehensive network scanning tool for security professionals.

This tool performs:
1. Host Discovery - Find active devices on the network
2. Port Scanning - Identify open ports on discovered hosts
3. Service Detection - Determine what services are running
4. Banner Grabbing - Get service version information
5. Security Analysis - Identify potential security risks
6. Report Generation - Create professional HTML/JSON reports

Usage:
    python main.py                    # Interactive mode
    python main.py --target 192.168.1.0/24  # Direct scan
    python main.py --web              # Start web dashboard

DISCLAIMER: This tool is for authorized security testing only.
Unauthorized scanning of networks is illegal and unethical.
"""

import argparse
import json
import sys
import os
import asyncio

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.host_discovery import HostDiscovery
from scanner.port_scanner import PortScanner
from scanner.service_detector import ServiceDetector
from scanner.credential_scanner import CredentialScanner
from utils.ip_utils import parse_target, get_subnet_info, get_local_ip, get_local_subnet
from utils.report_generator import ReportGenerator


def banner():
    print("""
    +======================================================================+
    |                                                                      |
    |   Network Scanner & Port Analyzer v1.0                               |
    |   Security-Fundamentals Project 1                                    |
    |                                                                      |
    +======================================================================+
    """)


def interactive_mode():
    """Run the scanner in interactive mode with menu options."""
    banner()

    local_ip = get_local_ip()
    local_subnet = get_local_subnet()
    print(f"  [*] Your IP: {local_ip}")
    print(f"  [*] Your Subnet: {local_subnet}")
    print()

    while True:
        print("\n" + "=" * 50)
        print("  MAIN MENU")
        print("=" * 50)
        print("  1. Discover Hosts on Network")
        print("  2. Scan Ports on a Target")
        print("  3. Full Scan (Discovery + Ports + Services)")
        print("  4. Subnet Calculator")
        print("  5. Start Web Dashboard")
        print("  6. Exit")
        print("=" * 50)

        choice = input("\n  Select option [1-6]: ").strip()

        if choice == "1":
            _host_discovery_menu(local_subnet)
        elif choice == "2":
            _port_scan_menu()
        elif choice == "3":
            _full_scan_menu(local_subnet)
        elif choice == "4":
            _subnet_calculator()
        elif choice == "5":
            start_web_server()
        elif choice == "6":
            print("\n  [*] Goodbye! Stay secure. 🛡️")
            sys.exit(0)
        else:
            print("  [!] Invalid option. Try again.")


def _host_discovery_menu(default_subnet):
    """Host discovery sub-menu."""
    print("\n--- HOST DISCOVERY ---")
    target = input(f"  Target (default: {default_subnet}): ").strip()
    if not target:
        target = default_subnet

    targets = parse_target(target)
    if not targets:
        print("  [!] Invalid target specification.")
        return

    print(f"  [*] Parsed {len(targets)} target IPs")

    method = input("  Method [tcp/icmp] (default: tcp): ").strip().lower()
    if method not in ("tcp", "icmp"):
        method = "tcp"

    discoverer = HostDiscovery(timeout=1.0, max_threads=100)
    hosts = discoverer.scan_network(targets, method=method)

    if hosts:
        print(f"\n  [+] Found {len(hosts)} active hosts:")
        for h in hosts:
            print(f"      {h['ip']} (RTT: {h['rtt_ms']}ms)")

    return hosts


def _port_scan_menu():
    """Port scanning sub-menu."""
    print("\n--- PORT SCANNER ---")
    target = input("  Target IP: ").strip()
    if not target:
        print("  [!] No target specified.")
        return

    print("  Profiles: quick (1-1024) | common (top services) | top100 | full (all 65535)")
    profile = input("  Profile (default: common): ").strip().lower()
    if profile not in ("quick", "common", "top100", "full"):
        profile = "common"

    scanner = PortScanner(timeout=1.0, max_threads=200)
    results = scanner.scan_host(target, profile=profile)

    # Service detection on open ports
    if results["open_ports"]:
        detect = input("\n  Run service detection? [Y/n]: ").strip().lower()
        if detect != "n":
            detector = ServiceDetector(timeout=3.0)
            services = detector.detect_services(target, results["open_ports"])
            results["services"] = services

    # Generate report
    report = input("\n  Generate report? [Y/n]: ").strip().lower()
    if report != "n":
        gen = ReportGenerator()
        gen.generate_html_report(results)
        gen.generate_json_report(results)

    return results


def _full_scan_menu(default_subnet):
    """Full scan: discovery + ports + services."""
    print("\n--- FULL NETWORK SCAN ---")
    target = input(f"  Target network (default: {default_subnet}): ").strip()
    if not target:
        target = default_subnet

    targets = parse_target(target)
    if not targets:
        print("  [!] Invalid target specification.")
        return

    # Phase 1: Host Discovery
    print("\n[Phase 1/3] Host Discovery")
    discoverer = HostDiscovery(timeout=1.0, max_threads=100)
    hosts = discoverer.scan_network(targets, method="tcp")

    if not hosts:
        print("  [!] No hosts found.")
        return

    all_results = {
        "scan_type": "full",
        "target_network": target,
        "discovered_hosts": hosts,
        "host_scans": [],
    }

    # Phase 2 & 3: Port Scan + Service Detection for each host
    scanner = PortScanner(timeout=1.0, max_threads=200)
    detector = ServiceDetector(timeout=3.0)
    cred_scanner = CredentialScanner()

    for host in hosts:
        ip = host["ip"]
        print(f"\n[Phase 2/3] Scanning ports on {ip}")
        port_results = scanner.scan_host(ip, profile="common")

        if port_results["open_ports"]:
            print(f"[Phase 3/3] Service detection on {ip}")
            services = detector.detect_services(ip, port_results["open_ports"])
            port_results["services"] = services

            # Phase 3.4: CVE Vulnerability Intelligence
            print(f"[Phase 3.4/3] CVE vulnerability intelligence on {ip}")
            cve_integrator = CVEIntegrator()
            services_with_cve = cve_integrator.enrich_services_with_cve(services)
            port_results["services"] = services_with_cve

            # Show CVE summary
            total_cves = sum(len(s.get("cves", [])) for s in services_with_cve)
            critical_cves = sum(1 for s in services_with_cve for cve in s.get("cves", []) if cve.get("cvss", 0) >= 9.0)
            if total_cves > 0:
                print(f"  [!] Found {total_cves} CVEs ({critical_cves} critical)")

            # Phase 3.5: Credential-based scanning
            print(f"[Phase 3.5/3] Credential-based scanning on {ip}")
            cred_results = asyncio.run(cred_scanner.scan_services(ip, services_with_cve))
            port_results["credential_scan_results"] = cred_results

            if cred_results:
                print(f"  [!] Found {len(cred_results)} credential-based vulnerabilities")

        all_results["host_scans"].append(port_results)

    # Generate reports
    gen = ReportGenerator()
    gen.generate_html_report(all_results)
    gen.generate_json_report(all_results)

    print("\n[*] Full scan complete!")
    return all_results


def _subnet_calculator():
    """Interactive subnet calculator - educational tool."""
    print("\n--- SUBNET CALCULATOR ---")
    print("  Learn about IP subnetting!")

    cidr = input("  Enter CIDR (e.g., 192.168.1.0/24): ").strip()
    info = get_subnet_info(cidr)

    if "error" in info:
        print(f"  [!] Error: {info['error']}")
        return

    print(f"\n  Network Address:    {info['network_address']}")
    print(f"  Broadcast Address:  {info['broadcast_address']}")
    print(f"  Subnet Mask:        {info['subnet_mask']}")
    print(f"  Wildcard Mask:      {info['wildcard_mask']}")
    print(f"  Prefix Length:      /{info['prefix_length']}")
    print(f"  Total Addresses:    {info['total_hosts']}")
    print(f"  Usable Hosts:       {info['usable_hosts']}")
    print(f"  First Usable Host:  {info['first_host']}")
    print(f"  Last Usable Host:   {info['last_host']}")
    print(f"  Network Class:      {info['network_class']}")
    print(f"  Private Network:    {'Yes' if info['is_private'] else 'No'}")


def start_web_server(host="0.0.0.0", port=5000):
    """Start the Flask web dashboard."""
    try:
        from flask import Flask, send_from_directory, jsonify, request
        from flask_cors import CORS
    except ImportError:
        print("  [!] Flask not installed. Run: pip install flask flask-cors")
        return

    app = Flask(__name__, static_folder="web_dashboard")
    CORS(app)

    @app.route("/")
    def index():
        return send_from_directory("web_dashboard", "index.html")

    @app.route("/<path:filename>")
    def serve_static(filename):
        return send_from_directory("web_dashboard", filename)

    @app.route("/api/local-info")
    def local_info():
        return jsonify({
            "local_ip": get_local_ip(),
            "local_subnet": get_local_subnet(),
            "subnet_info": get_subnet_info(get_local_subnet()),
        })

    @app.route("/api/subnet-info")
    def subnet_info():
        cidr = request.args.get("cidr", get_local_subnet())
        return jsonify(get_subnet_info(cidr))

    @app.route("/api/discover", methods=["POST"])
    def discover_hosts():
        data = request.json
        target = data.get("target", get_local_subnet())
        method = data.get("method", "tcp")
        timeout = float(data.get("timeout", 1.0))

        targets = parse_target(target)
        if not targets:
            return jsonify({"error": "Invalid target"}), 400

        discoverer = HostDiscovery(timeout=timeout, max_threads=100)
        hosts = discoverer.scan_network(targets, method=method)
        return jsonify({"hosts": hosts, "count": len(hosts)})

    @app.route("/api/scan", methods=["POST"])
    def scan_ports():
        data = request.json
        target = data.get("target", "")
        profile = data.get("profile", "common")
        timeout = float(data.get("timeout", 1.0))

        if not target:
            return jsonify({"error": "No target specified"}), 400

        scanner = PortScanner(timeout=timeout, max_threads=200)
        results = scanner.scan_host(target, profile=profile)
        return jsonify(results)

    @app.route("/api/detect-services", methods=["POST"])
    def detect_services():
        data = request.json
        target = data.get("target", "")
        ports = data.get("ports", [])

        if not target or not ports:
            return jsonify({"error": "Target and ports required"}), 400

        detector = ServiceDetector(timeout=3.0)
        results = detector.detect_services(target, ports)
        return jsonify({"services": results})

    @app.route("/api/full-scan", methods=["POST"])
    def full_scan():
        data = request.json
        target = data.get("target", "")
        profile = data.get("profile", "common")

        if not target:
            return jsonify({"error": "No target specified"}), 400

        targets = parse_target(target)
        if not targets:
            return jsonify({"error": "Invalid target"}), 400

        # Host discovery
        discoverer = HostDiscovery(timeout=1.0, max_threads=100)
        hosts = discoverer.scan_network(targets, method="tcp")

        # Port scan + service detect each host
        scanner = PortScanner(timeout=1.0, max_threads=200)
        detector = ServiceDetector(timeout=3.0)

        host_scans = []
        for host in hosts:
            ip = host["ip"]
            port_results = scanner.scan_host(ip, profile=profile)
            if port_results["open_ports"]:
                services = detector.detect_services(ip, port_results["open_ports"])
                port_results["services"] = services
            host_scans.append(port_results)

        return jsonify({
            "discovered_hosts": hosts,
            "host_scans": host_scans,
            "total_hosts": len(hosts),
        })

    print(f"\n  [*] Starting Web Dashboard at http://localhost:{port}")
    print(f"  [*] Press Ctrl+C to stop\n")
    app.run(host=host, port=port, debug=False)


def main():
    parser = argparse.ArgumentParser(
        description="Network Scanner & Port Analyzer - Security Fundamentals Project 1",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target", "-t", help="Target IP, CIDR, or range")
    parser.add_argument("--ports", "-p", help="Ports to scan (e.g., 22,80,443 or 1-1024)")
    parser.add_argument("--profile", choices=["quick", "common", "top100", "full"], default="common")
    parser.add_argument("--discover", "-d", action="store_true", help="Run host discovery only")
    parser.add_argument("--services", "-s", action="store_true", help="Enable service detection")
    parser.add_argument("--udp", "-u", action="store_true", help="Enable UDP scanning")
    parser.add_argument("--web", "-w", action="store_true", help="Start web dashboard")
    parser.add_argument("--port", type=int, default=5000, help="Web dashboard port")
    parser.add_argument("--timeout", type=float, default=1.0, help="Scan timeout in seconds")
    parser.add_argument("--report", "-r", action="store_true", help="Generate HTML report")

    args = parser.parse_args()

    if args.web:
        start_web_server(port=args.port)
        return

    if not args.target:
        interactive_mode()
        return

    banner()

    targets = parse_target(args.target)
    if not targets:
        print("[!] Invalid target. Use IP, CIDR, or IP range.")
        sys.exit(1)

    if args.discover:
        discoverer = HostDiscovery(timeout=args.timeout)
        discoverer.scan_network(targets, method="tcp")
        return

    # Single target scan
    if len(targets) == 1:
        scanner = PortScanner(timeout=args.timeout)
        scan_type = "udp" if args.udp else "tcp"
        results = scanner.scan_host(targets[0], profile=args.profile, scan_type=scan_type)

        if args.services and results["open_ports"]:
            detector = ServiceDetector()
            services = detector.detect_services(targets[0], results["open_ports"])
            results["services"] = services

        if args.report:
            gen = ReportGenerator()
            gen.generate_html_report(results)
            gen.generate_json_report(results)
    else:
        # Multi-target: discover first, then scan each
        discoverer = HostDiscovery(timeout=args.timeout)
        hosts = discoverer.scan_network(targets, method="tcp")

        scanner = PortScanner(timeout=args.timeout)
        scan_type = "udp" if args.udp else "tcp"
        for host in hosts:
            scanner.scan_host(host["ip"], profile=args.profile, scan_type=scan_type)


if __name__ == "__main__":
    main()