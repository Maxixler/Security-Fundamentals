"""
Packet Parser Module
====================
Parses network packets into structured data for firewall rule evaluation.

What is a Network Packet?
- A packet is a unit of data transmitted over a network
- It consists of HEADERS (metadata) + PAYLOAD (actual data)
- Each network layer adds its own header (encapsulation)

Packet Structure (simplified):
┌──────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                           │
│  - Destination MAC (6B) | Source MAC (6B) | Type (2B)│
├──────────────────────────────────────────────────────┤
│ IP Header (20-60 bytes)                              │
│  - Version | IHL | TOS | Total Length                │
│  - ID | Flags | Fragment Offset                      │
│  - TTL | Protocol | Header Checksum                  │
│  - Source IP Address (4B)                            │
│  - Destination IP Address (4B)                       │
├──────────────────────────────────────────────────────┤
│ TCP Header (20-60 bytes) or UDP Header (8 bytes)     │
│  TCP: Src Port | Dst Port | Seq | Ack | Flags       │
│  UDP: Src Port | Dst Port | Length | Checksum        │
├──────────────────────────────────────────────────────┤
│ Payload (application data)                           │
└──────────────────────────────────────────────────────┘

Security Relevance:
- Firewalls inspect packet headers to make allow/deny decisions
- Deep Packet Inspection (DPI) also examines the payload
- Understanding packet structure is fundamental to network security
"""

import time
import ipaddress
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class Protocol(Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    OTHER = "OTHER"


class TCPFlag(Enum):
    """
    TCP Flags control connection behavior.
    Understanding these is critical for firewall rules.
    
    SYN  = Synchronize: initiates a connection
    ACK  = Acknowledge: confirms receipt of data
    FIN  = Finish: gracefully closes a connection  
    RST  = Reset: abruptly terminates a connection
    PSH  = Push: send data immediately (don't buffer)
    URG  = Urgent: marks data as high priority
    """
    SYN = "SYN"
    ACK = "ACK"
    FIN = "FIN"
    RST = "RST"
    PSH = "PSH"
    URG = "URG"
    SYN_ACK = "SYN-ACK"


@dataclass
class Packet:
    """
    Represents a parsed network packet.
    
    This is the core data structure that the firewall engine processes.
    Every packet flowing through the firewall is parsed into this format
    so rules can match against its properties.
    """
    # Layer 3 - Network
    src_ip: str = "0.0.0.0"
    dst_ip: str = "0.0.0.0"
    protocol: Protocol = Protocol.TCP
    ttl: int = 64
    
    # Layer 4 - Transport
    src_port: int = 0
    dst_port: int = 0
    tcp_flags: list = field(default_factory=list)
    
    # Metadata
    timestamp: float = field(default_factory=time.time)
    size: int = 0
    payload: str = ""
    direction: str = "INBOUND"   # INBOUND / OUTBOUND / FORWARD
    interface: str = "eth0"
    
    # Firewall decision (filled after processing)
    action: Optional[str] = None      # ALLOW / DENY / DROP / LOG
    matched_rule_id: Optional[int] = None
    zone_src: Optional[str] = None
    zone_dst: Optional[str] = None

    def __str__(self):
        flags = ",".join(self.tcp_flags) if self.tcp_flags else "-"
        return (f"[{self.protocol.value}] {self.src_ip}:{self.src_port} -> "
                f"{self.dst_ip}:{self.dst_port} flags={flags} "
                f"size={self.size}B action={self.action}")

    def to_dict(self):
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol.value,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "tcp_flags": self.tcp_flags,
            "ttl": self.ttl,
            "size": self.size,
            "direction": self.direction,
            "timestamp": self.timestamp,
            "action": self.action,
            "matched_rule_id": self.matched_rule_id,
            "zone_src": self.zone_src,
            "zone_dst": self.zone_dst,
            "payload_preview": self.payload[:100] if self.payload else "",
        }


class PacketParser:
    """
    Parses raw packet data or simulated packet dictionaries into
    Packet objects for firewall processing.
    """

    @staticmethod
    def from_dict(data: dict) -> Packet:
        """Create a Packet from a dictionary (used by traffic generator and API)."""
        protocol_map = {
            "TCP": Protocol.TCP,
            "UDP": Protocol.UDP,
            "ICMP": Protocol.ICMP,
        }
        return Packet(
            src_ip=data.get("src_ip", "0.0.0.0"),
            dst_ip=data.get("dst_ip", "0.0.0.0"),
            protocol=protocol_map.get(data.get("protocol", "TCP").upper(), Protocol.OTHER),
            src_port=int(data.get("src_port", 0)),
            dst_port=int(data.get("dst_port", 0)),
            tcp_flags=data.get("tcp_flags", []),
            ttl=int(data.get("ttl", 64)),
            size=int(data.get("size", 0)),
            payload=data.get("payload", ""),
            direction=data.get("direction", "INBOUND"),
            interface=data.get("interface", "eth0"),
            timestamp=data.get("timestamp", time.time()),
        )

    @staticmethod
    def from_scapy(scapy_pkt) -> Optional[Packet]:
        """
        Parse a Scapy packet object into our Packet dataclass.
        Used when capturing real network traffic.
        """
        try:
            from scapy.all import IP, TCP, UDP, ICMP as ScapyICMP

            if not scapy_pkt.haslayer(IP):
                return None

            ip_layer = scapy_pkt[IP]
            pkt = Packet(
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                ttl=ip_layer.ttl,
                size=len(scapy_pkt),
                timestamp=time.time(),
            )

            if scapy_pkt.haslayer(TCP):
                tcp = scapy_pkt[TCP]
                pkt.protocol = Protocol.TCP
                pkt.src_port = tcp.sport
                pkt.dst_port = tcp.dport
                # Parse TCP flags
                flags = []
                flag_str = str(tcp.flags)
                if 'S' in flag_str: flags.append("SYN")
                if 'A' in flag_str: flags.append("ACK")
                if 'F' in flag_str: flags.append("FIN")
                if 'R' in flag_str: flags.append("RST")
                if 'P' in flag_str: flags.append("PSH")
                if 'U' in flag_str: flags.append("URG")
                pkt.tcp_flags = flags

            elif scapy_pkt.haslayer(UDP):
                udp = scapy_pkt[UDP]
                pkt.protocol = Protocol.UDP
                pkt.src_port = udp.sport
                pkt.dst_port = udp.dport

            elif scapy_pkt.haslayer(ScapyICMP):
                pkt.protocol = Protocol.ICMP

            return pkt

        except Exception:
            return None

    @staticmethod
    def validate_ip(ip_str: str) -> bool:
        """Validate an IP address or CIDR notation."""
        try:
            if '/' in ip_str:
                ipaddress.IPv4Network(ip_str, strict=False)
            else:
                ipaddress.IPv4Address(ip_str)
            return True
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            return False

    @staticmethod
    def ip_in_network(ip: str, network: str) -> bool:
        """
        Check if an IP address belongs to a CIDR network.
        Example: ip_in_network("192.168.1.5", "192.168.1.0/24") -> True
        
        This is how firewalls check if traffic comes from a specific subnet.
        """
        try:
            if network == "any" or network == "0.0.0.0/0":
                return True
            ip_addr = ipaddress.IPv4Address(ip)
            net = ipaddress.IPv4Network(network, strict=False)
            return ip_addr in net
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            return ip == network
