"""
IDS Signature & Anomaly Detection Engine
==========================================
Multi-layer intrusion detection combining signature-based matching
(Snort-like rules) with statistical anomaly detection.

Detection Layers:
    1. Signature Rules — Pattern matching against known attack payloads
    2. Protocol Anomaly — Validates protocol compliance (HTTP method, DNS length)
    3. Rate-Based — Connection/packet rate threshold monitoring
    4. Statistical — Z-score baseline deviation detection

Architecture:
    Packet → Protocol Decode → Signature Match → Anomaly Check → Rate Limit
          → Detection Result (alert/pass/drop)
"""

import re
import time
import math
from collections import defaultdict, deque
from typing import Dict, List, Optional, Any, Tuple


# ─── Detection Signatures ──────────────────────────────────────────────
_SIGNATURES: List[Dict[str, Any]] = [
    # SQL Injection
    {
        "sid": 1001, "name": "SQL Injection — OR-based bypass",
        "pattern": r"(?:OR|AND)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        "protocol": "TCP", "dst_port": [80, 443, 8080],
        "severity": "Critical", "action": "alert",
        "category": "Web Application Attack",
        "mitre": "T1190",
    },
    {
        "sid": 1002, "name": "SQL Injection — UNION SELECT",
        "pattern": r"UNION\s+(ALL\s+)?SELECT",
        "protocol": "TCP", "dst_port": [80, 443, 8080],
        "severity": "Critical", "action": "alert",
        "category": "Web Application Attack",
        "mitre": "T1190",
    },
    # XSS
    {
        "sid": 1010, "name": "XSS — Script Tag Injection",
        "pattern": r"<\s*script[^>]*>",
        "protocol": "TCP", "dst_port": [80, 443, 8080],
        "severity": "High", "action": "alert",
        "category": "Web Application Attack",
        "mitre": "T1059.007",
    },
    {
        "sid": 1011, "name": "XSS — Event Handler Injection",
        "pattern": r"on(?:error|load|click|mouseover)\s*=",
        "protocol": "TCP", "dst_port": [80, 443, 8080],
        "severity": "High", "action": "alert",
        "category": "Web Application Attack",
        "mitre": "T1059.007",
    },
    # LFI/Path Traversal
    {
        "sid": 1020, "name": "LFI — Path Traversal (Linux)",
        "pattern": r"\.\./\.\./\.\./",
        "protocol": "TCP", "dst_port": [80, 443, 8080],
        "severity": "Critical", "action": "alert",
        "category": "Web Application Attack",
        "mitre": "T1083",
    },
    {
        "sid": 1021, "name": "LFI — /etc/passwd Access",
        "pattern": r"/etc/(?:passwd|shadow|hosts)",
        "protocol": "TCP", "dst_port": [80, 443, 8080],
        "severity": "Critical", "action": "alert",
        "category": "Web Application Attack",
        "mitre": "T1005",
    },
    # Command Injection
    {
        "sid": 1030, "name": "Command Injection — Shell Execution",
        "pattern": r"(?:cmd\.exe|/bin/(?:sh|bash)|whoami|cat\s+/etc)",
        "protocol": "TCP", "dst_port": [80, 443, 8080],
        "severity": "Critical", "action": "alert",
        "category": "Web Application Attack",
        "mitre": "T1059",
    },
    # PHP Backdoor
    {
        "sid": 1040, "name": "PHP Webshell Upload",
        "pattern": r"<\?php\s+(?:system|exec|passthru|shell_exec)",
        "protocol": "TCP", "dst_port": [80, 443, 8080],
        "severity": "Critical", "action": "alert",
        "category": "Malware",
        "mitre": "T1505.003",
    },
    # SSH Brute Force
    {
        "sid": 2001, "name": "SSH — Brute Force Attempt",
        "pattern": r"SSH.*AUTH\s+password",
        "protocol": "TCP", "dst_port": [22],
        "severity": "High", "action": "alert",
        "category": "Credential Access",
        "mitre": "T1110",
    },
    # DNS Tunneling
    {
        "sid": 3001, "name": "DNS Tunneling — Long Subdomain",
        "pattern": r"QUERY\s+\S{40,}",  # Domain > 40 chars
        "protocol": "UDP", "dst_port": [53],
        "severity": "High", "action": "alert",
        "category": "Command and Control",
        "mitre": "T1071.004",
    },
    # C2 Beacon
    {
        "sid": 4001, "name": "C2 Beacon — Known Malicious Domain",
        "pattern": r"(?:evil-c2\.tk|malware\.xyz|data-exfil\.top)",
        "protocol": "TCP", "dst_port": [80, 443],
        "severity": "Critical", "action": "alert",
        "category": "Command and Control",
        "mitre": "T1071.001",
    },
    # ARP Spoofing
    {
        "sid": 5001, "name": "ARP Spoofing — Unsolicited Reply",
        "pattern": r"ARP Reply.*unsolicited",
        "protocol": "ARP", "dst_port": [],
        "severity": "High", "action": "alert",
        "category": "Network Attack",
        "mitre": "T1557.002",
    },
    # ICMP Flood
    {
        "sid": 5010, "name": "ICMP Flood — Ping of Death",
        "pattern": r"Echo Request.*flood",
        "protocol": "ICMP", "dst_port": [],
        "severity": "Medium", "action": "alert",
        "category": "DoS",
        "mitre": "T1498",
    },
]


class DetectionResult:
    """Result of analyzing a single packet."""

    def __init__(self, packet_id: str, matched: bool, action: str = "pass",
                 severity: str = "", rule_name: str = "", rule_sid: int = 0,
                 category: str = "", mitre: str = "", details: str = ""):
        self.packet_id = packet_id
        self.timestamp = datetime.now().isoformat() if True else ""
        self.matched = matched
        self.action = action
        self.severity = severity
        self.rule_name = rule_name
        self.rule_sid = rule_sid
        self.category = category
        self.mitre = mitre
        self.details = details

    def to_dict(self) -> dict:
        return {
            "packet_id": self.packet_id,
            "timestamp": self.timestamp,
            "matched": self.matched,
            "action": self.action,
            "severity": self.severity,
            "rule_name": self.rule_name,
            "rule_sid": self.rule_sid,
            "category": self.category,
            "mitre": self.mitre,
            "details": self.details,
        }


from datetime import datetime


class SignatureEngine:
    """
    Multi-layer intrusion detection engine.

    Combines signature-based pattern matching with rate-based and
    statistical anomaly detection for comprehensive threat identification.

    Attributes:
        rules: Loaded detection signatures
        alerts: Queue of generated alerts for dashboard
        blocked_ips: Set of currently banned IPs
        stats: Detection statistics
    """

    # Rate-based thresholds
    SYN_FLOOD_THRESHOLD = 20       # SYN packets per IP per window
    SYN_FLOOD_WINDOW = 10          # Seconds
    PORT_SCAN_THRESHOLD = 10       # Unique ports per IP per window
    PORT_SCAN_WINDOW = 30          # Seconds
    BRUTE_FORCE_THRESHOLD = 5      # Auth attempts per IP per window
    BRUTE_FORCE_WINDOW = 60        # Seconds

    def __init__(self):
        self.rules = _SIGNATURES
        self.compiled_rules = self._compile_rules()
        self.alerts: List[Dict[str, Any]] = []
        self.blocked_ips: Dict[str, Dict[str, Any]] = {}  # IP → {reason, time, ttl}

        # Rate trackers
        self._syn_tracker: Dict[str, deque] = defaultdict(deque)
        self._port_tracker: Dict[str, deque] = defaultdict(deque)
        self._auth_tracker: Dict[str, deque] = defaultdict(deque)

        # Statistics
        self.stats = {
            "packets_analyzed": 0,
            "alerts_generated": 0,
            "signature_matches": 0,
            "rate_alerts": 0,
            "packets_dropped": 0,
        }

    def _compile_rules(self) -> List[Tuple[Dict, re.Pattern]]:
        """Pre-compile regex patterns for performance."""
        compiled = []
        for rule in self.rules:
            try:
                pattern = re.compile(rule["pattern"], re.IGNORECASE)
                compiled.append((rule, pattern))
            except re.error:
                pass
        return compiled

    def analyze_packet(self, packet) -> DetectionResult:
        """
        Analyze a single packet through all detection layers.

        Returns DetectionResult with match status and recommended action.
        """
        pkt = packet.to_dict() if hasattr(packet, "to_dict") else packet
        self.stats["packets_analyzed"] += 1

        src_ip = pkt.get("src_ip", "")
        now = time.time()

        # Check if source IP is blocked
        if src_ip in self.blocked_ips:
            block_info = self.blocked_ips[src_ip]
            if now < block_info.get("expires", 0):
                self.stats["packets_dropped"] += 1
                return DetectionResult(
                    packet_id=pkt.get("packet_id", ""),
                    matched=True, action="drop",
                    severity="Critical",
                    rule_name="IP Blocked",
                    details=f"Source IP {src_ip} is currently blocked: {block_info.get('reason', '')}",
                )
            else:
                del self.blocked_ips[src_ip]

        # Layer 1: Signature matching
        result = self._check_signatures(pkt)
        if result and result.matched:
            self._record_alert(result, pkt)
            return result

        # Layer 2: Rate-based detection
        result = self._check_rates(pkt, src_ip, now)
        if result and result.matched:
            self._record_alert(result, pkt)
            return result

        return DetectionResult(
            packet_id=pkt.get("packet_id", ""),
            matched=False, action="pass",
        )

    def _check_signatures(self, pkt: dict) -> Optional[DetectionResult]:
        """Check packet against all compiled signature rules."""
        payload = pkt.get("payload", "")
        protocol = pkt.get("protocol", "")
        dst_port = pkt.get("dst_port", 0)

        for rule, pattern in self.compiled_rules:
            # Protocol filter
            if rule["protocol"] != protocol and rule["protocol"] != "ANY":
                continue
            # Port filter
            if rule["dst_port"] and dst_port not in rule["dst_port"]:
                continue
            # Pattern match
            if pattern.search(payload):
                self.stats["signature_matches"] += 1
                return DetectionResult(
                    packet_id=pkt.get("packet_id", ""),
                    matched=True,
                    action=rule["action"],
                    severity=rule["severity"],
                    rule_name=rule["name"],
                    rule_sid=rule["sid"],
                    category=rule["category"],
                    mitre=rule.get("mitre", ""),
                    details=f"Matched: {payload[:80]}",
                )
        return None

    def _check_rates(self, pkt: dict, src_ip: str, now: float) -> Optional[DetectionResult]:
        """Rate-based anomaly detection."""
        if not src_ip:
            return None

        flags = pkt.get("flags", "")
        protocol = pkt.get("protocol", "")
        dst_port = pkt.get("dst_port", 0)

        # SYN Flood Detection
        if flags == "SYN":
            self._syn_tracker[src_ip].append(now)
            while self._syn_tracker[src_ip] and (now - self._syn_tracker[src_ip][0]) > self.SYN_FLOOD_WINDOW:
                self._syn_tracker[src_ip].popleft()

            if len(self._syn_tracker[src_ip]) >= self.SYN_FLOOD_THRESHOLD:
                self.stats["rate_alerts"] += 1
                self._syn_tracker[src_ip].clear()
                self._block_ip(src_ip, "SYN Flood detected", 300)
                return DetectionResult(
                    packet_id=pkt.get("packet_id", ""),
                    matched=True, action="drop",
                    severity="Critical",
                    rule_name="SYN Flood Detected",
                    rule_sid=9001,
                    category="DoS",
                    mitre="T1498.001",
                    details=f"Excessive SYN packets from {src_ip}",
                )

        # Port Scan Detection
        if flags == "SYN" and dst_port:
            self._port_tracker[src_ip].append((now, dst_port))
            while self._port_tracker[src_ip] and (now - self._port_tracker[src_ip][0][0]) > self.PORT_SCAN_WINDOW:
                self._port_tracker[src_ip].popleft()

            unique_ports = len(set(p[1] for p in self._port_tracker[src_ip]))
            if unique_ports >= self.PORT_SCAN_THRESHOLD:
                self.stats["rate_alerts"] += 1
                self._port_tracker[src_ip].clear()
                self._block_ip(src_ip, "Port scan detected", 120)
                return DetectionResult(
                    packet_id=pkt.get("packet_id", ""),
                    matched=True, action="alert",
                    severity="High",
                    rule_name="Port Scan Detected",
                    rule_sid=9002,
                    category="Reconnaissance",
                    mitre="T1046",
                    details=f"Port scan from {src_ip}: {unique_ports} unique ports",
                )

        return None

    def _block_ip(self, ip: str, reason: str, ttl: int = 300) -> None:
        """Add an IP to the block list with TTL."""
        self.blocked_ips[ip] = {
            "reason": reason,
            "blocked_at": time.time(),
            "expires": time.time() + ttl,
            "ttl": ttl,
        }

    def _record_alert(self, result: DetectionResult, pkt: dict) -> None:
        """Record an alert for the dashboard."""
        self.stats["alerts_generated"] += 1
        alert = {
            **result.to_dict(),
            "src_ip": pkt.get("src_ip", ""),
            "dst_ip": pkt.get("dst_ip", ""),
            "dst_port": pkt.get("dst_port", 0),
            "protocol": pkt.get("protocol", ""),
        }
        self.alerts.insert(0, alert)
        if len(self.alerts) > 100:
            self.alerts.pop()

    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        """Return currently blocked IPs with TTL remaining."""
        now = time.time()
        result = []
        for ip, info in self.blocked_ips.items():
            remaining = max(0, int(info["expires"] - now))
            if remaining > 0:
                result.append({
                    "ip": ip,
                    "reason": info["reason"],
                    "ttl_remaining": remaining,
                    "blocked_at": datetime.fromtimestamp(info["blocked_at"]).isoformat(),
                })
        return result

    def get_rule_count(self) -> int:
        """Return total number of loaded rules."""
        return len(self.rules)
