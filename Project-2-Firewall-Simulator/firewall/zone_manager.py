"""
Zone Manager Module
===================
Manages network security zones for zone-based firewall policies.

What are Security Zones?
- Zones group network interfaces by trust level
- Traffic between zones is controlled by policies
- This is the foundation of defense-in-depth architecture

Common Zones:
┌────────────────────────────────────────────────────────┐
│                    INTERNET                            │
│                   (Untrusted)                          │
├──────────────────────┬─────────────────────────────────┤
│       FIREWALL       │                                 │
├────────┬─────────────┼────────────────┬────────────────┤
│  DMZ   │  TRUSTED    │    OT ZONE     │   MANAGEMENT   │
│ (Web   │  (Office    │  (Industrial   │   (Admin       │
│  svrs) │   network)  │   control)     │    access)     │
├────────┴─────────────┼────────────────┴────────────────┤
│                      │                                 │
│  Web server, Mail    │   SCADA, PLC, HMI              │
│  Reverse proxy       │   Modbus/OPC-UA devices        │
└──────────────────────┴─────────────────────────────────┘

Tupras Context - Purdue Model:
Level 5: Enterprise Network (IT)
Level 4: Business Planning (IT/OT boundary)
Level 3.5: DMZ (data diode, historians)
Level 3: Operations (HMI, engineering stations)
Level 2: Control (PLCs, DCS)
Level 1: Field devices (sensors, actuators)
Level 0: Physical process (actual refinery equipment)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from .packet_parser import PacketParser


@dataclass
class Zone:
    """
    A security zone represents a logical network segment
    with a specific trust level.
    """
    name: str = ""
    description: str = ""
    trust_level: int = 0          # 0 (untrusted) to 100 (most trusted)
    networks: list = field(default_factory=list)   # CIDR ranges in this zone
    interfaces: list = field(default_factory=list)  # Network interfaces
    color: str = "#6366f1"        # For dashboard display

    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "trust_level": self.trust_level,
            "networks": self.networks,
            "interfaces": self.interfaces,
            "color": self.color,
        }

    def contains_ip(self, ip: str) -> bool:
        """Check if an IP belongs to this zone."""
        for network in self.networks:
            if PacketParser.ip_in_network(ip, network):
                return True
        return False


@dataclass
class ZonePolicy:
    """
    Defines the default policy for traffic between two zones.
    
    Example: DMZ -> Trusted = DENY (web servers can't access internal network)
             Trusted -> DMZ = ALLOW (internal users can access web servers)
    """
    src_zone: str = ""
    dst_zone: str = ""
    default_action: str = "DENY"
    description: str = ""

    def to_dict(self):
        return {
            "src_zone": self.src_zone,
            "dst_zone": self.dst_zone,
            "default_action": self.default_action,
            "description": self.description,
        }


class ZoneManager:
    """
    Manages security zones and inter-zone policies.
    
    Provides:
    - Zone CRUD operations
    - IP-to-zone lookup
    - Inter-zone policy enforcement
    - Zone matrix visualization
    """

    def __init__(self):
        self.zones: Dict[str, Zone] = {}
        self.policies: List[ZonePolicy] = []
        self._setup_default_zones()

    def _setup_default_zones(self):
        """
        Create default zones that simulate an industrial network.
        These represent the Purdue Model levels used at Tupras.
        """
        default_zones = [
            Zone(
                name="untrusted",
                description="External / Internet - No trust",
                trust_level=0,
                networks=["0.0.0.0/0"],  # Catch-all for unknown
                color="#ef4444",
            ),
            Zone(
                name="dmz",
                description="DMZ - Public-facing servers (web, mail, DNS)",
                trust_level=25,
                networks=["172.16.0.0/24"],
                color="#f59e0b",
            ),
            Zone(
                name="trusted",
                description="Internal corporate network - Office/IT",
                trust_level=75,
                networks=["192.168.1.0/24", "192.168.2.0/24"],
                color="#22c55e",
            ),
            Zone(
                name="ot_network",
                description="OT/ICS Network - Industrial control systems",
                trust_level=90,
                networks=["10.10.0.0/16"],
                color="#a855f7",
            ),
            Zone(
                name="management",
                description="Management VLAN - Admin/security tools",
                trust_level=100,
                networks=["10.0.0.0/24"],
                color="#3b82f6",
            ),
        ]

        for zone in default_zones:
            self.zones[zone.name] = zone

        # Default inter-zone policies
        default_policies = [
            ZonePolicy("untrusted", "dmz", "ALLOW", "Internet can reach DMZ services"),
            ZonePolicy("untrusted", "trusted", "DENY", "Block internet to internal"),
            ZonePolicy("untrusted", "ot_network", "DENY", "CRITICAL: Block internet to OT"),
            ZonePolicy("dmz", "trusted", "DENY", "DMZ cannot access internal"),
            ZonePolicy("dmz", "ot_network", "DENY", "DMZ cannot access OT"),
            ZonePolicy("trusted", "dmz", "ALLOW", "Internal users can access DMZ"),
            ZonePolicy("trusted", "untrusted", "ALLOW", "Internal users can access internet"),
            ZonePolicy("trusted", "ot_network", "DENY", "IT cannot directly access OT"),
            ZonePolicy("ot_network", "trusted", "DENY", "OT cannot access IT"),
            ZonePolicy("ot_network", "untrusted", "DENY", "CRITICAL: OT cannot reach internet"),
            ZonePolicy("management", "trusted", "ALLOW", "Admins can access IT"),
            ZonePolicy("management", "ot_network", "ALLOW", "Security team can monitor OT"),
            ZonePolicy("management", "dmz", "ALLOW", "Admins can manage DMZ"),
        ]

        self.policies = default_policies

    def add_zone(self, zone: Zone) -> Zone:
        self.zones[zone.name] = zone
        return zone

    def remove_zone(self, name: str) -> bool:
        if name in self.zones:
            del self.zones[name]
            self.policies = [p for p in self.policies
                             if p.src_zone != name and p.dst_zone != name]
            return True
        return False

    def get_zone_for_ip(self, ip: str) -> Optional[str]:
        """
        Determine which zone an IP address belongs to.
        
        The lookup checks specific zones first (higher trust = higher priority),
        falls back to 'untrusted' if no match.
        """
        # Check specific zones first (exclude untrusted catch-all)
        candidates = sorted(
            [z for z in self.zones.values() if z.name != "untrusted"],
            key=lambda z: z.trust_level,
            reverse=True
        )
        for zone in candidates:
            if zone.contains_ip(ip):
                return zone.name
        return "untrusted"

    def get_policy(self, src_zone: str, dst_zone: str) -> str:
        """
        Get the default policy for traffic between two zones.
        
        If no explicit policy exists, return DENY (zero-trust approach).
        Same-zone traffic is allowed by default.
        """
        if src_zone == dst_zone:
            return "ALLOW"  # Intra-zone traffic allowed

        for policy in self.policies:
            if policy.src_zone == src_zone and policy.dst_zone == dst_zone:
                return policy.default_action
        
        return "DENY"  # Default deny for undefined zone pairs

    def set_policy(self, src_zone: str, dst_zone: str, action: str, description: str = ""):
        """Set or update the policy between two zones."""
        for policy in self.policies:
            if policy.src_zone == src_zone and policy.dst_zone == dst_zone:
                policy.default_action = action.upper()
                policy.description = description
                return

        self.policies.append(ZonePolicy(src_zone, dst_zone, action.upper(), description))

    def get_zone_matrix(self) -> dict:
        """
        Generate a zone-to-zone policy matrix for visualization.
        
        Returns a matrix like:
                    | untrusted | dmz  | trusted | ot_network | management
        untrusted   |   -       | ALLOW| DENY    | DENY       | DENY
        dmz         |  ALLOW    |  -   | DENY    | DENY       | DENY
        trusted     |  ALLOW    | ALLOW|  -      | DENY       | ALLOW
        """
        zone_names = list(self.zones.keys())
        matrix = {}
        for src in zone_names:
            matrix[src] = {}
            for dst in zone_names:
                if src == dst:
                    matrix[src][dst] = "SELF"
                else:
                    matrix[src][dst] = self.get_policy(src, dst)
        return matrix

    def get_all_zones(self) -> list:
        return [z.to_dict() for z in self.zones.values()]

    def get_all_policies(self) -> list:
        return [p.to_dict() for p in self.policies]
