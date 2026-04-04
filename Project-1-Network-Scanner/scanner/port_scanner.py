"""
Port Scanner Module
===================
Scans target hosts for open TCP/UDP ports using multiple techniques.

What is a Port?
- A port is a logical endpoint for network communication (0-65535)
- Think of IP address as a building address, and port as apartment number
- Multiple services can run on the same IP, each on a different port

Port Ranges:
- 0-1023: Well-known Ports (HTTP=80, HTTPS=443, SSH=22, DNS=53)
- 1024-49151: Registered Ports (MySQL=3306, RDP=3389, Modbus=502)
- 49152-65535: Dynamic/Private Ports (ephemeral, used for client connections)

Scan Techniques:
1. TCP Connect Scan: Full 3-way handshake → reliable but logged
2. TCP SYN Scan: Half-open → stealthier, requires admin privileges
3. UDP Scan: Connectionless → slower, used for DNS/DHCP/SNMP

Why Port Scanning Matters for Security:
- Every open port is a potential attack vector
- Unnecessary open ports should be closed (principle of least privilege)
- In an industrial environment, Modbus (502) and other OT ports must be
  carefully controlled between IT and OT network segments
"""

import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Optional

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.ip_utils import get_service_name


class PortScanner:
    """
    Multi-threaded TCP/UDP port scanner with configurable scan profiles.
    
    Supports:
    - TCP Connect Scan (full handshake)
    - Custom port ranges and profiles
    - Service name resolution
    - Concurrent scanning for speed
    """

    # Predefined scan profiles
    SCAN_PROFILES = {
        "quick": list(range(1, 1025)),  # Well-known ports only
        "common": [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389,
            443, 445, 465, 502, 514, 587, 636, 993, 995, 1080, 1433,
            1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
            9200, 27017, 47808
        ],
        "top100": [
            7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106,
            110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427,
            443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587,
            631, 636, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028,
            1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
            2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009,
            5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900,
            6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443,
            8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155,
            49156, 49157
        ],
        "full": list(range(1, 65536)),  # All ports (slow!)
    }

    # OT/ICS specific ports - critical for industrial security
    OT_PORTS = {
        102: "Siemens S7 (ISO-TSAP)",
        502: "Modbus TCP",
        530: "RPC",
        593: "HTTP RPC",
        789: "Crimson v3",
        1089: "FF Annunciation",
        1090: "FF Fieldbus Message",
        1091: "FF System Mgmt",
        1541: "FoxAPI",
        2222: "EtherNet/IP",
        2404: "IEC 60870-5-104",
        4000: "Emerson ROC",
        4840: "OPC UA",
        4911: "Niagara Fox",
        9600: "OMRON FINS",
        18245: "GE SRTP",
        20000: "DNP3",
        20547: "ProConOS",
        34962: "PROFINET RT",
        34963: "PROFINET RT",
        34964: "PROFINET Context Manager",
        44818: "EtherNet/IP (explicit)",
        47808: "BACnet/IP",
        55000: "FL-net",
        55003: "FL-net",
    }

    def __init__(self, timeout: float = 1.0, max_threads: int = 200):
        """
        Args:
            timeout: Connection timeout in seconds for each port
            max_threads: Maximum number of concurrent scanning threads
        """
        self.timeout = timeout
        self.max_threads = max_threads
        self.results = []
        self._lock = threading.Lock()
        self.scan_start_time = None
        self.scan_end_time = None

    def tcp_connect_scan(self, ip: str, port: int) -> dict:
        """
        Perform a TCP Connect scan on a single port.
        
        TCP Three-Way Handshake:
        ┌────────┐                    ┌────────┐
        │ Client │                    │ Server │
        └───┬────┘                    └───┬────┘
            │         SYN (seq=x)         │
            │ ──────────────────────────> │  Step 1: Client initiates
            │                             │
            │     SYN-ACK (seq=y,ack=x+1) │
            │ <────────────────────────── │  Step 2: Server acknowledges
            │                             │
            │      ACK (ack=y+1)          │
            │ ──────────────────────────> │  Step 3: Connection established
            │                             │
        
        Port States:
        - OPEN: SYN-ACK received → service is listening
        - CLOSED: RST received → no service, but host is alive
        - FILTERED: No response → firewall is dropping packets
        """
        result = {
            "port": port,
            "state": "closed",
            "service": "",
            "description": "",
            "rtt_ms": None,
            "is_ot_port": port in self.OT_PORTS,
            "ot_protocol": self.OT_PORTS.get(port, ""),
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            start_time = time.time()
            conn_result = sock.connect_ex((ip, port))
            end_time = time.time()
            
            rtt = round((end_time - start_time) * 1000, 2)

            if conn_result == 0:
                # Connection succeeded → port is OPEN
                result["state"] = "open"
                result["rtt_ms"] = rtt
                service_name, description = get_service_name(port)
                result["service"] = service_name
                result["description"] = description
            elif rtt < (self.timeout * 1000 * 0.9):
                # Quick RST response → port is CLOSED (but host is alive)
                result["state"] = "closed"
                result["rtt_ms"] = rtt
            else:
                # Timeout → port is FILTERED (firewall dropping packets)
                result["state"] = "filtered"

            sock.close()

        except socket.timeout:
            result["state"] = "filtered"
        except ConnectionRefusedError:
            result["state"] = "closed"
        except OSError as e:
            result["state"] = "error"
            result["description"] = str(e)

        return result

    def scan_host(self, ip: str, ports: list = None, profile: str = "common") -> dict:
        """
        Scan all specified ports on a single host.
        
        Args:
            ip: Target IP address
            ports: List of ports to scan (overrides profile)
            profile: Scan profile ('quick', 'common', 'top100', 'full')
            
        Returns:
            dict: Scan results with open, closed, and filtered ports
        """
        if ports is None:
            ports = self.SCAN_PROFILES.get(profile, self.SCAN_PROFILES["common"])

        self.scan_start_time = datetime.now()
        open_ports = []
        closed_count = 0
        filtered_count = 0

        print(f"\n[*] Scanning {ip} | {len(ports)} ports | Profile: {profile}")
        print(f"[*] Timeout: {self.timeout}s | Threads: {self.max_threads}")
        print("-" * 60)

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self.tcp_connect_scan, ip, port): port 
                for port in ports
            }

            completed = 0
            for future in as_completed(futures):
                completed += 1
                try:
                    result = future.result()
                    if result["state"] == "open":
                        open_ports.append(result)
                        ot_flag = " [OT/ICS!]" if result["is_ot_port"] else ""
                        print(f"  [+] {result['port']:>5}/tcp  OPEN    {result['service']:<16} {result['description']}{ot_flag}")
                    elif result["state"] == "filtered":
                        filtered_count += 1
                    else:
                        closed_count += 1
                except Exception:
                    pass

                if completed % 500 == 0:
                    print(f"  [*] Progress: {completed}/{len(ports)} ports scanned...")

        self.scan_end_time = datetime.now()
        elapsed = (self.scan_end_time - self.scan_start_time).total_seconds()

        # Sort open ports by port number
        open_ports.sort(key=lambda x: x["port"])

        scan_result = {
            "target": ip,
            "scan_time": self.scan_start_time.isoformat(),
            "duration_seconds": round(elapsed, 2),
            "ports_scanned": len(ports),
            "open_ports": open_ports,
            "open_count": len(open_ports),
            "closed_count": closed_count,
            "filtered_count": filtered_count,
            "profile": profile,
        }

        print("-" * 60)
        print(f"[*] Scan complete in {elapsed:.2f}s")
        print(f"[*] Results: {len(open_ports)} open | {closed_count} closed | {filtered_count} filtered")
        
        # Security warnings
        self._security_analysis(open_ports)

        return scan_result

    def _security_analysis(self, open_ports: list):
        """
        Provide basic security analysis of discovered open ports.
        
        This simulates what a security analyst would check:
        - High-risk services (Telnet, FTP, etc.)
        - OT/ICS ports exposed to IT network
        - Database ports accessible externally
        """
        warnings = []
        
        risky_ports = {
            23: "Telnet is UNENCRYPTED - use SSH instead",
            21: "FTP transmits credentials in cleartext",
            139: "NetBIOS can leak system information",
            445: "SMB - frequent target for ransomware (WannaCry, NotPetya)",
            3389: "RDP - common brute force target, ensure NLA is enabled",
            1433: "MSSQL exposed - ensure strong authentication",
            3306: "MySQL exposed - should not be accessible externally",
            5432: "PostgreSQL exposed - verify access controls",
            161: "SNMP can leak device configuration - use SNMPv3",
            502: "Modbus has NO authentication - critical OT security risk!",
        }

        for port_info in open_ports:
            port = port_info["port"]
            if port in risky_ports:
                warnings.append(f"  [!] WARNING Port {port}: {risky_ports[port]}")
            if port_info["is_ot_port"]:
                warnings.append(f"  [!] OT/ICS Port {port} ({port_info['ot_protocol']}) is accessible!")

        if warnings:
            print("\n[!] === SECURITY WARNINGS ===")
            for w in warnings:
                print(w)
            print()
