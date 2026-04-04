"""
Firewall Rule Engine
====================
Evaluates packets against an ordered list of firewall rules.

How Firewall Rules Work:
- Rules are evaluated TOP-DOWN (first match wins)
- Each rule defines conditions: source/dst IP, ports, protocol, direction
- If a packet matches all conditions, the rule's action is applied
- If no rule matches, the DEFAULT policy applies (usually DENY)

Rule Structure:
┌─────────────────────────────────────────────────────┐
│  Rule #1 (Priority: 100)                            │
│  Action: ALLOW                                      │
│  Protocol: TCP                                      │
│  Source: 192.168.1.0/24 (any port)                 │
│  Destination: any (port 443)                        │
│  Direction: OUTBOUND                                │
│  Description: "Allow HTTPS traffic to internet"     │
├─────────────────────────────────────────────────────┤
│  Rule #2 (Priority: 200)                            │
│  Action: DENY                                       │
│  Protocol: TCP                                      │
│  Source: any                                        │
│  Destination: 10.0.1.0/24 (port 22)                │
│  Direction: INBOUND                                 │
│  Description: "Block SSH from external networks"    │
├─────────────────────────────────────────────────────┤
│  DEFAULT POLICY: DENY ALL                           │
└─────────────────────────────────────────────────────┘

Enterprise Context:
- Firewalls sit between IT and OT networks
- Rules control what traffic can cross between zones
- Modbus (port 502) from IT to OT must be strictly controlled
- Alper Bey managed Forcepoint Web Security at VakifBank
"""

import json
import os
import time
from dataclasses import dataclass, field
from typing import List, Optional
from .packet_parser import Packet, Protocol, PacketParser


@dataclass
class FirewallRule:
    """
    A single firewall rule.
    
    Fields explained:
    - rule_id: Unique identifier
    - priority: Lower number = higher priority (evaluated first)
    - action: ALLOW, DENY, DROP, LOG
      - ALLOW: Let the packet through
      - DENY: Block and send rejection (RST for TCP, ICMP unreachable)
      - DROP: Silently discard (no response - attacker doesn't know if host exists)
      - LOG: Allow but log for monitoring
    - protocol: TCP, UDP, ICMP, or ANY
    - src_ip/dst_ip: Source/destination IP or CIDR ("any" = match all)
    - src_port/dst_port: Port number or 0 for any
    - direction: INBOUND, OUTBOUND, FORWARD, or ANY
    - enabled: Whether the rule is active
    """
    rule_id: int = 0
    name: str = ""
    priority: int = 1000
    action: str = "DENY"
    protocol: str = "ANY"          # TCP, UDP, ICMP, ANY
    src_ip: str = "any"
    dst_ip: str = "any"
    src_port: int = 0              # 0 = any
    dst_port: int = 0              # 0 = any
    direction: str = "ANY"         # INBOUND, OUTBOUND, FORWARD, ANY
    tcp_flags: list = field(default_factory=list)  # Optional: match specific flags
    zone_src: str = ""             # Source zone (e.g., "trusted", "dmz")
    zone_dst: str = ""             # Destination zone
    log: bool = False
    enabled: bool = True
    description: str = ""
    hit_count: int = 0
    created_at: float = field(default_factory=time.time)

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "priority": self.priority,
            "action": self.action,
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "direction": self.direction,
            "tcp_flags": self.tcp_flags,
            "zone_src": self.zone_src,
            "zone_dst": self.zone_dst,
            "log": self.log,
            "enabled": self.enabled,
            "description": self.description,
            "hit_count": self.hit_count,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'FirewallRule':
        return cls(
            rule_id=data.get("rule_id", 0),
            name=data.get("name", ""),
            priority=data.get("priority", 1000),
            action=data.get("action", "DENY").upper(),
            protocol=data.get("protocol", "ANY").upper(),
            src_ip=data.get("src_ip", "any"),
            dst_ip=data.get("dst_ip", "any"),
            src_port=int(data.get("src_port", 0)),
            dst_port=int(data.get("dst_port", 0)),
            direction=data.get("direction", "ANY").upper(),
            tcp_flags=data.get("tcp_flags", []),
            zone_src=data.get("zone_src", ""),
            zone_dst=data.get("zone_dst", ""),
            log=data.get("log", False),
            enabled=data.get("enabled", True),
            description=data.get("description", ""),
        )


class RuleEngine:
    """
    Firewall Rule Engine - evaluates packets against rules.
    
    The engine maintains an ordered list of rules and evaluates
    each packet against them. First matching rule wins.
    """

    def __init__(self, default_policy: str = "DENY"):
        """
        Args:
            default_policy: Action when no rule matches.
                           "DENY" (recommended for security) or "ALLOW"
                           
        Security Best Practice:
        - Default DENY (whitelist approach): Only allow explicitly permitted traffic
        - Default ALLOW (blacklist approach): Block only known bad traffic
        - Enterprise networks use Default DENY for maximum security
        """
        self.rules: List[FirewallRule] = []
        self.default_policy = default_policy.upper()
        self._next_id = 1

    def add_rule(self, rule: FirewallRule) -> FirewallRule:
        """Add a new rule and re-sort by priority."""
        if rule.rule_id == 0:
            rule.rule_id = self._next_id
            self._next_id += 1
        else:
            self._next_id = max(self._next_id, rule.rule_id + 1)
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority)
        return rule

    def remove_rule(self, rule_id: int) -> bool:
        """Remove a rule by its ID."""
        before = len(self.rules)
        self.rules = [r for r in self.rules if r.rule_id != rule_id]
        return len(self.rules) < before

    def update_rule(self, rule_id: int, updates: dict) -> Optional[FirewallRule]:
        """Update an existing rule's fields."""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                for key, value in updates.items():
                    if hasattr(rule, key) and key != "rule_id":
                        setattr(rule, key, value)
                self.rules.sort(key=lambda r: r.priority)
                return rule
        return None

    def get_rule(self, rule_id: int) -> Optional[FirewallRule]:
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule
        return None

    def evaluate(self, packet: Packet) -> str:
        """
        Evaluate a packet against all rules.
        
        Process:
        1. Iterate through rules sorted by priority (lowest first)
        2. For each enabled rule, check if ALL conditions match
        3. First matching rule determines the action
        4. If no rule matches, apply default policy
        
        Returns:
            str: Action to take (ALLOW, DENY, DROP, LOG)
        """
        for rule in self.rules:
            if not rule.enabled:
                continue

            if self._matches(rule, packet):
                rule.hit_count += 1
                packet.action = rule.action
                packet.matched_rule_id = rule.rule_id
                return rule.action

        # No rule matched -> default policy
        packet.action = self.default_policy
        packet.matched_rule_id = -1
        return self.default_policy

    def _matches(self, rule: FirewallRule, packet: Packet) -> bool:
        """
        Check if a packet matches ALL conditions of a rule.
        ALL conditions must be True for a match (logical AND).
        """
        # Direction check
        if rule.direction != "ANY":
            if rule.direction != packet.direction:
                return False

        # Protocol check
        if rule.protocol != "ANY":
            if rule.protocol != packet.protocol.value:
                return False

        # Source IP check
        if rule.src_ip != "any":
            if not PacketParser.ip_in_network(packet.src_ip, rule.src_ip):
                return False

        # Destination IP check
        if rule.dst_ip != "any":
            if not PacketParser.ip_in_network(packet.dst_ip, rule.dst_ip):
                return False

        # Source port check (0 = any)
        if rule.src_port != 0:
            if packet.src_port != rule.src_port:
                return False

        # Destination port check (0 = any)
        if rule.dst_port != 0:
            if packet.dst_port != rule.dst_port:
                return False

        # TCP flags check (if specified)
        if rule.tcp_flags:
            if not all(f in packet.tcp_flags for f in rule.tcp_flags):
                return False

        # Zone checks (if specified)
        if rule.zone_src and packet.zone_src:
            if rule.zone_src != packet.zone_src:
                return False
        if rule.zone_dst and packet.zone_dst:
            if rule.zone_dst != packet.zone_dst:
                return False

        return True

    def load_rules(self, filepath: str):
        """Load rules from a JSON file."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            rules_data = data.get("rules", data) if isinstance(data, dict) else data
            if isinstance(rules_data, dict):
                rules_data = rules_data.get("rules", [])
            
            for rule_data in rules_data:
                rule = FirewallRule.from_dict(rule_data)
                self.add_rule(rule)

            if isinstance(data, dict) and "default_policy" in data:
                self.default_policy = data["default_policy"].upper()

            print(f"[*] Loaded {len(rules_data)} rules from {filepath}")
        except FileNotFoundError:
            print(f"[!] Rule file not found: {filepath}")
        except json.JSONDecodeError as e:
            print(f"[!] Invalid JSON in rule file: {e}")

    def save_rules(self, filepath: str):
        """Save current rules to a JSON file."""
        data = {
            "default_policy": self.default_policy,
            "rules": [r.to_dict() for r in self.rules],
        }
        os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"[*] Saved {len(self.rules)} rules to {filepath}")

    def get_stats(self) -> dict:
        """Get rule engine statistics."""
        return {
            "total_rules": len(self.rules),
            "enabled_rules": sum(1 for r in self.rules if r.enabled),
            "disabled_rules": sum(1 for r in self.rules if not r.enabled),
            "default_policy": self.default_policy,
            "top_hit_rules": sorted(
                [{"id": r.rule_id, "name": r.name, "hits": r.hit_count, "action": r.action}
                 for r in self.rules if r.hit_count > 0],
                key=lambda x: x["hits"], reverse=True
            )[:10],
        }
