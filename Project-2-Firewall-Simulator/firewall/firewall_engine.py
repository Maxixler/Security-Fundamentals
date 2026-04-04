"""
Firewall Engine
===============
The main firewall engine that combines:
- Rule-based packet filtering 
- Stateful connection tracking
- Zone-based security policies
- Traffic logging and statistics

This is the central piece that ties all modules together.
In a real enterprise, this engine would be
running on dedicated hardware processing millions of packets/second.
"""

import time
import threading
import json
import os
from datetime import datetime
from typing import List, Optional
from .packet_parser import Packet, PacketParser, Protocol
from .rule_engine import RuleEngine, FirewallRule
from .stateful_tracker import StatefulTracker, ConnectionState
from .zone_manager import ZoneManager


class FirewallEngine:
    """
    Complete firewall engine with stateful inspection and zone-based policies.
    
    Processing Pipeline:
    1. Parse packet
    2. Determine source/destination zones
    3. Check zone policy (inter-zone default)
    4. Check stateful connection table  
    5. Evaluate firewall rules (first match wins)
    6. Apply default policy if no match
    7. Log the decision
    """

    def __init__(self, rules_file: str = None, stateful: bool = True):
        self.rule_engine = RuleEngine(default_policy="DENY")
        self.state_tracker = StatefulTracker() if stateful else None
        self.zone_manager = ZoneManager()
        self.stateful = stateful

        # Statistics
        self._lock = threading.Lock()
        self.stats = {
            "total_packets": 0,
            "allowed": 0,
            "denied": 0,
            "dropped": 0,
            "logged": 0,
            "invalid_state": 0,
            "start_time": time.time(),
        }

        # Packet log (circular buffer)
        self.packet_log: List[dict] = []
        self.max_log_size = 1000
        self.log_file = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "logs", "firewall.log"
        )
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

        # Load rules if provided
        if rules_file and os.path.exists(rules_file):
            self.rule_engine.load_rules(rules_file)

    def process_packet(self, packet: Packet) -> dict:
        """
        Process a single packet through the firewall pipeline.
        
        Returns a dict with the decision and metadata.
        """
        result = {
            "timestamp": datetime.now().isoformat(),
            "packet": packet.to_dict(),
            "action": "DENY",
            "reason": "",
            "rule_id": None,
            "conn_state": None,
            "zone_src": None,
            "zone_dst": None,
        }

        with self._lock:
            self.stats["total_packets"] += 1

        # Step 1: Zone classification
        zone_src = self.zone_manager.get_zone_for_ip(packet.src_ip)
        zone_dst = self.zone_manager.get_zone_for_ip(packet.dst_ip)
        packet.zone_src = zone_src
        packet.zone_dst = zone_dst
        result["zone_src"] = zone_src
        result["zone_dst"] = zone_dst

        # Step 2: Zone policy check
        zone_policy = self.zone_manager.get_policy(zone_src, zone_dst)
        
        # Step 3: Stateful inspection
        conn_state = None
        if self.stateful and self.state_tracker:
            conn_state = self.state_tracker.track_packet(packet)
            result["conn_state"] = conn_state

            # ESTABLISHED connections are automatically allowed
            if conn_state == ConnectionState.ESTABLISHED:
                result["action"] = "ALLOW"
                result["reason"] = "Stateful: ESTABLISHED connection"
                packet.action = "ALLOW"
                self._record_decision(result)
                return result

            # INVALID state packets are dropped
            if conn_state == ConnectionState.INVALID:
                result["action"] = "DROP"
                result["reason"] = "Stateful: INVALID packet (no matching connection)"
                packet.action = "DROP"
                with self._lock:
                    self.stats["invalid_state"] += 1
                self._record_decision(result)
                return result

        # Step 4: Rule evaluation
        action = self.rule_engine.evaluate(packet)
        result["action"] = action
        result["rule_id"] = packet.matched_rule_id

        if packet.matched_rule_id and packet.matched_rule_id > 0:
            rule = self.rule_engine.get_rule(packet.matched_rule_id)
            result["reason"] = f"Rule #{packet.matched_rule_id}: {rule.name}" if rule else f"Rule #{packet.matched_rule_id}"
        elif zone_policy == "DENY" and action == "DENY":
            result["reason"] = f"Zone policy: {zone_src} -> {zone_dst} = DENY"
        else:
            result["reason"] = f"Default policy: {self.rule_engine.default_policy}"

        self._record_decision(result)
        return result

    def process_batch(self, packets: List[Packet]) -> List[dict]:
        """Process multiple packets."""
        return [self.process_packet(p) for p in packets]

    def _record_decision(self, result: dict):
        """Record the decision in stats and log."""
        action = result["action"]
        with self._lock:
            if action == "ALLOW" or action == "LOG":
                self.stats["allowed"] += 1
            elif action == "DENY":
                self.stats["denied"] += 1
            elif action == "DROP":
                self.stats["dropped"] += 1
            
            if action == "LOG":
                self.stats["logged"] += 1

            # Add to packet log (circular buffer)
            self.packet_log.append(result)
            if len(self.packet_log) > self.max_log_size:
                self.packet_log = self.packet_log[-self.max_log_size:]

        # Write to log file
        self._write_log(result)

    def _write_log(self, result: dict):
        """Append a log entry to the firewall log file."""
        try:
            pkt = result["packet"]
            entry = (
                f"{result['timestamp']} "
                f"{result['action']:>5} "
                f"{pkt['protocol']:>4} "
                f"{pkt['src_ip']:>15}:{pkt['src_port']:<5} -> "
                f"{pkt['dst_ip']:>15}:{pkt['dst_port']:<5} "
                f"zone={result.get('zone_src','?')}->{result.get('zone_dst','?')} "
                f"state={result.get('conn_state','N/A')} "
                f"rule={result.get('rule_id','default')} "
                f"| {result['reason']}\n"
            )
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(entry)
        except Exception:
            pass

    def get_stats(self) -> dict:
        """Get comprehensive firewall statistics."""
        with self._lock:
            uptime = time.time() - self.stats["start_time"]
            total = self.stats["total_packets"]
            return {
                **self.stats,
                "uptime_seconds": round(uptime, 1),
                "packets_per_second": round(total / max(uptime, 1), 2),
                "allow_rate": round(self.stats["allowed"] / max(total, 1) * 100, 1),
                "deny_rate": round(self.stats["denied"] / max(total, 1) * 100, 1),
                "drop_rate": round(self.stats["dropped"] / max(total, 1) * 100, 1),
                "rule_stats": self.rule_engine.get_stats(),
                "connection_stats": self.state_tracker.get_stats() if self.state_tracker else {},
                "zone_matrix": self.zone_manager.get_zone_matrix(),
            }

    def get_recent_logs(self, count: int = 50) -> list:
        """Get recent packet log entries."""
        with self._lock:
            return list(reversed(self.packet_log[-count:]))

    def get_log_summary(self) -> dict:
        """Get a summary of recent log activity by action, protocol, and zone."""
        with self._lock:
            recent = self.packet_log[-200:]

        summary = {
            "by_action": {},
            "by_protocol": {},
            "by_zone_pair": {},
            "top_src_ips": {},
            "top_dst_ports": {},
            "recent_denies": [],
        }

        for entry in recent:
            pkt = entry["packet"]
            action = entry["action"]
            proto = pkt["protocol"]
            zone_pair = f"{entry.get('zone_src','?')} -> {entry.get('zone_dst','?')}"

            summary["by_action"][action] = summary["by_action"].get(action, 0) + 1
            summary["by_protocol"][proto] = summary["by_protocol"].get(proto, 0) + 1
            summary["by_zone_pair"][zone_pair] = summary["by_zone_pair"].get(zone_pair, 0) + 1
            summary["top_src_ips"][pkt["src_ip"]] = summary["top_src_ips"].get(pkt["src_ip"], 0) + 1
            
            dst_key = f"{pkt['dst_port']}/{proto}"
            summary["top_dst_ports"][dst_key] = summary["top_dst_ports"].get(dst_key, 0) + 1

            if action in ("DENY", "DROP"):
                summary["recent_denies"].append({
                    "time": entry["timestamp"],
                    "src": f"{pkt['src_ip']}:{pkt['src_port']}",
                    "dst": f"{pkt['dst_ip']}:{pkt['dst_port']}",
                    "proto": proto,
                    "reason": entry["reason"],
                })

        # Keep only top entries
        summary["top_src_ips"] = dict(sorted(summary["top_src_ips"].items(), key=lambda x: x[1], reverse=True)[:10])
        summary["top_dst_ports"] = dict(sorted(summary["top_dst_ports"].items(), key=lambda x: x[1], reverse=True)[:10])
        summary["recent_denies"] = summary["recent_denies"][-20:]

        return summary
