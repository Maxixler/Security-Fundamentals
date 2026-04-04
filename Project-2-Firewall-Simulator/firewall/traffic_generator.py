"""
Traffic Generator
=================
Generates simulated network traffic for testing the firewall.

This module creates realistic traffic patterns including:
- Normal web browsing (HTTP/HTTPS)
- Email traffic (SMTP/IMAP)
- DNS queries
- SSH connections
- Database access
- OT/ICS traffic (Modbus, OPC-UA)
- Attack simulations (port scans, brute force, etc.)

Why Simulate Traffic?
- Test firewall rules without needing a real network
- Verify that rules work as expected before deployment
- Train security teams to recognize attack patterns
- Validate that legitimate traffic is not blocked
"""

import random
import time
from typing import List, Generator
from .packet_parser import Packet, Protocol


class TrafficGenerator:
    """
    Generates realistic network traffic for firewall testing.
    
    Traffic profiles simulate real-world scenarios you'd find
    in a typical industrial enterprise network.
    """

    # Network topology simulation
    NETWORKS = {
        "internet": ["8.8.8.8", "1.1.1.1", "203.0.113.50", "198.51.100.25",
                      "93.184.216.34", "151.101.1.140", "104.244.42.1"],
        "dmz": ["172.16.0.10", "172.16.0.11", "172.16.0.20", "172.16.0.30"],
        "trusted": ["192.168.1.10", "192.168.1.20", "192.168.1.50",
                     "192.168.1.100", "192.168.2.15", "192.168.2.30"],
        "ot_network": ["10.10.1.10", "10.10.1.20", "10.10.2.100",
                        "10.10.2.200", "10.10.3.50"],
        "management": ["10.0.0.5", "10.0.0.10", "10.0.0.15"],
    }

    # Service definitions
    SERVICES = {
        "web_browsing": {"protocol": "TCP", "dst_ports": [80, 443], "description": "HTTP/HTTPS"},
        "dns": {"protocol": "UDP", "dst_ports": [53], "description": "DNS Queries"},
        "email": {"protocol": "TCP", "dst_ports": [25, 465, 587, 993], "description": "Email"},
        "ssh": {"protocol": "TCP", "dst_ports": [22], "description": "SSH Remote Access"},
        "rdp": {"protocol": "TCP", "dst_ports": [3389], "description": "Remote Desktop"},
        "smb": {"protocol": "TCP", "dst_ports": [445], "description": "File Sharing"},
        "database": {"protocol": "TCP", "dst_ports": [1433, 3306, 5432], "description": "Database"},
        "modbus": {"protocol": "TCP", "dst_ports": [502], "description": "Modbus (OT/ICS)"},
        "opcua": {"protocol": "TCP", "dst_ports": [4840], "description": "OPC-UA (OT/ICS)"},
        "snmp": {"protocol": "UDP", "dst_ports": [161, 162], "description": "SNMP Monitoring"},
        "syslog": {"protocol": "UDP", "dst_ports": [514], "description": "Syslog"},
        "ntp": {"protocol": "UDP", "dst_ports": [123], "description": "Time Sync"},
    }

    def __init__(self):
        self.generated_count = 0

    def _random_src_port(self) -> int:
        """Generate a random ephemeral source port (49152-65535)."""
        return random.randint(49152, 65535)

    def _make_packet(self, src_ip, dst_ip, protocol, src_port, dst_port,
                     tcp_flags=None, direction="OUTBOUND", size=None, payload="") -> Packet:
        """Create a packet with given parameters."""
        self.generated_count += 1
        return Packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=Protocol[protocol] if isinstance(protocol, str) else protocol,
            src_port=src_port,
            dst_port=dst_port,
            tcp_flags=tcp_flags or [],
            direction=direction,
            size=size or random.randint(40, 1500),
            payload=payload,
            timestamp=time.time(),
        )

    def generate_normal_traffic(self, count: int = 100) -> List[Packet]:
        """
        Generate realistic normal enterprise traffic mix.
        
        Traffic distribution mirrors a typical corporate network:
        - 40% Web browsing (HTTP/HTTPS)
        - 15% DNS queries
        - 10% Email
        - 10% Database access
        - 10% File sharing (SMB)
        - 5% SSH/RDP administration
        - 5% Monitoring (SNMP/Syslog)
        - 5% OT traffic (Modbus/OPC-UA)
        """
        packets = []
        traffic_mix = [
            ("web_browsing", 0.40, "trusted", "internet"),
            ("dns", 0.15, "trusted", "dmz"),
            ("email", 0.10, "trusted", "dmz"),
            ("database", 0.10, "trusted", "trusted"),
            ("smb", 0.10, "trusted", "trusted"),
            ("ssh", 0.03, "management", "trusted"),
            ("rdp", 0.02, "management", "trusted"),
            ("snmp", 0.03, "management", "trusted"),
            ("syslog", 0.02, "trusted", "management"),
            ("modbus", 0.03, "ot_network", "ot_network"),
            ("opcua", 0.02, "ot_network", "ot_network"),
        ]

        for _ in range(count):
            # Choose traffic type based on distribution
            r = random.random()
            cumulative = 0
            chosen = traffic_mix[0]
            for mix in traffic_mix:
                cumulative += mix[1]
                if r <= cumulative:
                    chosen = mix
                    break

            service_name, _, src_zone, dst_zone = chosen
            service = self.SERVICES[service_name]

            src_ip = random.choice(self.NETWORKS[src_zone])
            dst_ip = random.choice(self.NETWORKS[dst_zone])
            dst_port = random.choice(service["dst_ports"])
            protocol = service["protocol"]

            # TCP connections start with SYN
            flags = ["SYN"] if protocol == "TCP" else []

            pkt = self._make_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                src_port=self._random_src_port(),
                dst_port=dst_port,
                tcp_flags=flags,
                direction="OUTBOUND",
            )
            packets.append(pkt)

        return packets

    def generate_tcp_handshake(self, src_ip, dst_ip, src_port, dst_port) -> List[Packet]:
        """
        Generate a complete TCP 3-way handshake.
        This shows how stateful tracking works.
        """
        return [
            # Step 1: Client -> Server SYN
            self._make_packet(src_ip, dst_ip, "TCP", src_port, dst_port,
                              tcp_flags=["SYN"], direction="OUTBOUND", size=54),
            # Step 2: Server -> Client SYN-ACK
            self._make_packet(dst_ip, src_ip, "TCP", dst_port, src_port,
                              tcp_flags=["SYN", "ACK"], direction="INBOUND", size=54),
            # Step 3: Client -> Server ACK
            self._make_packet(src_ip, dst_ip, "TCP", src_port, dst_port,
                              tcp_flags=["ACK"], direction="OUTBOUND", size=54),
            # Step 4: Data transfer
            self._make_packet(src_ip, dst_ip, "TCP", src_port, dst_port,
                              tcp_flags=["PSH", "ACK"], direction="OUTBOUND", size=1200),
            # Step 5: Response
            self._make_packet(dst_ip, src_ip, "TCP", dst_port, src_port,
                              tcp_flags=["PSH", "ACK"], direction="INBOUND", size=800),
        ]

    def generate_attack_traffic(self, attack_type: str = "port_scan", count: int = 50) -> List[Packet]:
        """
        Generate simulated attack traffic for testing IDS rules.
        
        Attack types:
        - port_scan: Rapid probing of many ports
        - brute_force: Many SSH login attempts
        - syn_flood: DDoS using SYN packets
        - ot_intrusion: Unauthorized Modbus access
        - lateral_movement: Internal network traversal
        """
        packets = []
        attacker_ip = random.choice(self.NETWORKS["internet"])

        if attack_type == "port_scan":
            # Port scan: Same IP hitting many different ports rapidly
            target_ip = random.choice(self.NETWORKS["trusted"])
            for port in random.sample(range(1, 1025), min(count, 1024)):
                pkt = self._make_packet(
                    src_ip=attacker_ip,
                    dst_ip=target_ip,
                    protocol="TCP",
                    src_port=self._random_src_port(),
                    dst_port=port,
                    tcp_flags=["SYN"],
                    direction="INBOUND",
                    size=54,
                )
                packets.append(pkt)

        elif attack_type == "brute_force":
            # SSH brute force: Many connection attempts to port 22
            target_ip = random.choice(self.NETWORKS["dmz"])
            for _ in range(count):
                pkt = self._make_packet(
                    src_ip=attacker_ip,
                    dst_ip=target_ip,
                    protocol="TCP",
                    src_port=self._random_src_port(),
                    dst_port=22,
                    tcp_flags=["SYN"],
                    direction="INBOUND",
                    size=54,
                )
                packets.append(pkt)

        elif attack_type == "syn_flood":
            # SYN Flood DDoS: Massive SYN packets with spoofed source IPs
            target_ip = random.choice(self.NETWORKS["dmz"])
            for _ in range(count):
                spoofed_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                pkt = self._make_packet(
                    src_ip=spoofed_ip,
                    dst_ip=target_ip,
                    protocol="TCP",
                    src_port=self._random_src_port(),
                    dst_port=80,
                    tcp_flags=["SYN"],
                    direction="INBOUND",
                    size=54,
                )
                packets.append(pkt)

        elif attack_type == "ot_intrusion":
            # Unauthorized Modbus access from IT to OT network
            it_ip = random.choice(self.NETWORKS["trusted"])
            ot_ip = random.choice(self.NETWORKS["ot_network"])
            for _ in range(count):
                pkt = self._make_packet(
                    src_ip=it_ip,
                    dst_ip=ot_ip,
                    protocol="TCP",
                    src_port=self._random_src_port(),
                    dst_port=502,  # Modbus
                    tcp_flags=["SYN"],
                    direction="FORWARD",
                    payload="Modbus Write Coil Request",
                    size=66,
                )
                packets.append(pkt)

        elif attack_type == "lateral_movement":
            # Lateral movement: Compromised host scanning internal network
            compromised_ip = random.choice(self.NETWORKS["trusted"])
            for _ in range(count):
                target = random.choice(
                    self.NETWORKS["trusted"] + self.NETWORKS["ot_network"]
                )
                pkt = self._make_packet(
                    src_ip=compromised_ip,
                    dst_ip=target,
                    protocol="TCP",
                    src_port=self._random_src_port(),
                    dst_port=random.choice([22, 445, 3389, 135, 139, 502]),
                    tcp_flags=["SYN"],
                    direction="FORWARD",
                    size=54,
                )
                packets.append(pkt)

        return packets

    def generate_stream(self, packets_per_second: float = 10) -> Generator:
        """Generate a continuous stream of mixed traffic (generator function)."""
        while True:
            # 80% normal, 20% potentially malicious
            if random.random() < 0.8:
                packets = self.generate_normal_traffic(1)
            else:
                attack = random.choice(["port_scan", "brute_force", "ot_intrusion"])
                packets = self.generate_attack_traffic(attack, 1)

            for pkt in packets:
                yield pkt
            
            time.sleep(1.0 / packets_per_second)
