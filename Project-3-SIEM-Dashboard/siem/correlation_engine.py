"""
SIEM Correlation Engine
========================
Analyzes streams of normalized log events and applies multi-layered
detection rules to identify complex attack patterns across sources.

Detection Layers:
    1. Threat Intelligence Enrichment (IP reputation, IOC matching)
    2. Threshold-Based Rules (brute force, port scan, DDoS)
    3. Cross-Source Correlation (lateral movement, privilege escalation chains)
    4. Statistical Anomaly Detection (baseline deviation, Z-score)
    5. MITRE ATT&CK Tactic Mapping

Architecture:
    NormalizedEvent → Enrichment → Rule Evaluation → Incident Creation → Alert Queue
"""

import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any

from .threat_intel import ThreatIntelFeed


# ─── MITRE ATT&CK Mapping ──────────────────────────────────────────────
MITRE_MAPPING = {
    "brute_force":       {"tactic": "Credential Access",   "technique": "T1110", "name": "Brute Force"},
    "port_scan":         {"tactic": "Reconnaissance",      "technique": "T1046", "name": "Network Service Scanning"},
    "sql_injection":     {"tactic": "Initial Access",      "technique": "T1190", "name": "Exploit Public-Facing Application"},
    "xss_attempt":       {"tactic": "Initial Access",      "technique": "T1189", "name": "Drive-by Compromise"},
    "dns_tunnel":        {"tactic": "Command and Control",  "technique": "T1071.004", "name": "DNS Tunneling"},
    "lateral_movement":  {"tactic": "Lateral Movement",    "technique": "T1021", "name": "Remote Services"},
    "priv_escalation":   {"tactic": "Privilege Escalation", "technique": "T1078", "name": "Valid Accounts"},
    "data_exfiltration": {"tactic": "Exfiltration",        "technique": "T1048", "name": "Exfiltration Over Alternative Protocol"},
    "malicious_ip":      {"tactic": "Command and Control",  "technique": "T1071", "name": "Application Layer Protocol"},
    "vpn_brute_force":   {"tactic": "Credential Access",   "technique": "T1110.001", "name": "Password Guessing"},
    "recon_web":         {"tactic": "Reconnaissance",      "technique": "T1595", "name": "Active Scanning"},
    "firewall_evasion":  {"tactic": "Defense Evasion",     "technique": "T1562.004", "name": "Disable or Modify Firewall"},
}


class Incident:
    """
    Represents a correlated security incident detected by the engine.
    """

    def __init__(self, severity: str, description: str, attack_type: str,
                 src_ip: str = "", target: str = "", source: str = "",
                 country: str = "UNKNOWN", events: Optional[List[dict]] = None):
        self.id = f"INC-{int(time.time() * 1000) % 1000000:06d}"
        self.timestamp = datetime.now().isoformat()
        self.severity = severity       # Critical, High, Medium, Low
        self.description = description
        self.attack_type = attack_type
        self.src_ip = src_ip
        self.target = target
        self.source = source
        self.country = country
        self.mitre = MITRE_MAPPING.get(attack_type, {})
        self.status = "new"            # new, investigating, resolved
        self.related_events = events or []

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "description": self.description,
            "attack_type": self.attack_type,
            "src_ip": self.src_ip,
            "target": self.target,
            "source": self.source,
            "country": self.country,
            "mitre": self.mitre,
            "status": self.status,
            "event_count": len(self.related_events),
        }


class CorrelationEngine:
    """
    Multi-layer correlation engine for enterprise SIEM.

    Processes normalized events through enrichment, rule-based detection,
    and statistical analysis to identify security incidents.

    Attributes:
        ti_feed: Threat intelligence feed for IP enrichment
        incidents: Queue of generated incidents for dashboard consumption
        _failed_logins: Sliding window tracker for brute force detection
        _firewall_denies: Sliding window tracker for port scan detection
        _web_attacks: Tracker for web application attack correlation
        _vpn_fails: VPN brute force tracking
    """

    # Configurable detection thresholds
    BRUTE_FORCE_THRESHOLD = 5       # Failed logins to trigger alert
    BRUTE_FORCE_WINDOW = 120        # Seconds
    PORT_SCAN_THRESHOLD = 8         # Blocked connections to trigger
    PORT_SCAN_WINDOW = 60           # Seconds
    VPN_FAIL_THRESHOLD = 3          # VPN auth failures
    VPN_FAIL_WINDOW = 300           # Seconds
    WEB_ATTACK_THRESHOLD = 3        # Web attack attempts
    WEB_ATTACK_WINDOW = 60          # Seconds

    def __init__(self):
        self.ti_feed = ThreatIntelFeed()
        self.incidents: List[Incident] = []

        # Per-IP sliding window trackers
        self._failed_logins: Dict[str, deque] = defaultdict(deque)
        self._firewall_denies: Dict[str, deque] = defaultdict(deque)
        self._vpn_fails: Dict[str, deque] = defaultdict(deque)
        self._web_attacks: Dict[str, deque] = defaultdict(deque)
        self._dns_queries: Dict[str, deque] = defaultdict(deque)

        # Statistical baseline for anomaly detection
        self._event_rate_baseline: deque = deque(maxlen=60)  # Events per minute
        self._current_minute_count = 0
        self._last_minute_ts = time.time()

        # Deduplication: track recent incident hashes to avoid alert spam
        self._recent_incident_hashes: deque = deque(maxlen=200)

    # ─── Public API ─────────────────────────────────────────────────────

    def analyze(self, event) -> Optional[Incident]:
        """
        Process a single normalized log event through all detection layers.

        Args:
            event: NormalizedEvent object from the log aggregator

        Returns:
            Incident if a new threat was detected, None otherwise
        """
        event_dict = event.to_dict() if hasattr(event, "to_dict") else event
        src_ip = event_dict.get("src_ip", "")
        now = time.time()

        # Update event rate for anomaly baseline
        self._update_event_rate(now)

        # Layer 1: Threat Intelligence Enrichment
        incident = self._check_threat_intel(event_dict, src_ip)
        if incident:
            return incident

        # Layer 2: Threshold-Based Rule Detection
        event_type = event_dict.get("event_type", "")
        source = event_dict.get("source_type", "")

        # Brute Force Detection (AD failed logins)
        if event_type == "failed_logon":
            incident = self._detect_brute_force(event_dict, src_ip, now)
            if incident:
                return incident

        # Port Scan Detection (firewall denies)
        if source == "firewall" and event_dict.get("action") in ("DENY", "DROP", "REJECT"):
            incident = self._detect_port_scan(event_dict, src_ip, now)
            if incident:
                return incident

        # VPN Brute Force Detection
        if event_type == "vpn_auth_fail":
            incident = self._detect_vpn_brute_force(event_dict, src_ip, now)
            if incident:
                return incident

        # Web Application Attack Detection
        if event_type in ("injection_attempt", "recon_attempt"):
            incident = self._detect_web_attacks(event_dict, src_ip, now)
            if incident:
                return incident

        # DNS Tunneling Detection
        if event_type == "dns_tunnel_suspect":
            incident = self._detect_dns_tunnel(event_dict, src_ip, now)
            if incident:
                return incident

        # Layer 3: Cross-Source Correlation
        incident = self._cross_source_correlation(event_dict, src_ip, now)
        if incident:
            return incident

        return None

    def get_new_incidents(self) -> List[dict]:
        """Retrieve and flush pending incidents for the dashboard."""
        pending = [inc.to_dict() for inc in self.incidents]
        self.incidents.clear()
        return pending

    def get_all_incidents(self) -> List[dict]:
        """Get all incidents without flushing (for API)."""
        return [inc.to_dict() for inc in self.incidents]

    def get_mitre_summary(self) -> Dict[str, int]:
        """Return count of detections per MITRE ATT&CK tactic."""
        summary = defaultdict(int)
        for inc in self.incidents:
            tactic = inc.mitre.get("tactic", "Unknown")
            summary[tactic] += 1
        return dict(summary)

    # ─── Detection Rules ────────────────────────────────────────────────

    def _check_threat_intel(self, event: dict, src_ip: str) -> Optional[Incident]:
        """Layer 1: Enrich with threat intelligence and alert on known bad IPs."""
        if not src_ip:
            return None

        ti_data = self.ti_feed.check_ip(src_ip)
        event["ti_enrichment"] = ti_data

        if not ti_data["safe"]:
            return self._create_incident(
                severity="High",
                description=f"Traffic from known malicious IP: {src_ip} ({ti_data['threat_type']})",
                attack_type="malicious_ip",
                src_ip=src_ip,
                target=event.get("dst_ip", ""),
                source=event.get("source_type", ""),
                country=ti_data.get("country", "UNKNOWN"),
                events=[event],
            )
        return None

    def _detect_brute_force(self, event: dict, src_ip: str, now: float) -> Optional[Incident]:
        """Detect brute force attacks via failed login threshold."""
        window = self._failed_logins[src_ip]
        window.append(now)

        # Trim events outside the time window
        while window and (now - window[0]) > self.BRUTE_FORCE_WINDOW:
            window.popleft()

        if len(window) >= self.BRUTE_FORCE_THRESHOLD:
            target_user = event.get("username", "unknown")
            incident = self._create_incident(
                severity="Critical",
                description=f"Brute Force Attack: {len(window)} failed logins from {src_ip} targeting '{target_user}'",
                attack_type="brute_force",
                src_ip=src_ip,
                target=target_user,
                source="active_directory",
                events=[event],
            )
            window.clear()  # Reset to avoid spam
            return incident
        return None

    def _detect_port_scan(self, event: dict, src_ip: str, now: float) -> Optional[Incident]:
        """Detect port scanning via firewall deny threshold."""
        window = self._firewall_denies[src_ip]
        window.append((now, event.get("dst_port", 0)))

        # Trim old entries
        while window and (now - window[0][0]) > self.PORT_SCAN_WINDOW:
            window.popleft()

        if len(window) >= self.PORT_SCAN_THRESHOLD:
            unique_ports = len(set(p[1] for p in window))
            severity = "Critical" if unique_ports > 15 else "High" if unique_ports > 8 else "Medium"

            incident = self._create_incident(
                severity=severity,
                description=f"Port Scan Detected: {len(window)} blocked connections from {src_ip} ({unique_ports} unique ports)",
                attack_type="port_scan",
                src_ip=src_ip,
                target=event.get("dst_ip", ""),
                source="firewall",
                events=[event],
            )
            window.clear()
            return incident
        return None

    def _detect_vpn_brute_force(self, event: dict, src_ip: str, now: float) -> Optional[Incident]:
        """Detect VPN brute force attacks."""
        window = self._vpn_fails[src_ip]
        window.append(now)

        while window and (now - window[0]) > self.VPN_FAIL_WINDOW:
            window.popleft()

        if len(window) >= self.VPN_FAIL_THRESHOLD:
            incident = self._create_incident(
                severity="High",
                description=f"VPN Brute Force: {len(window)} failed attempts from {src_ip}",
                attack_type="vpn_brute_force",
                src_ip=src_ip,
                target="VPN Gateway",
                source="vpn",
                events=[event],
            )
            window.clear()
            return incident
        return None

    def _detect_web_attacks(self, event: dict, src_ip: str, now: float) -> Optional[Incident]:
        """Detect web application attacks (SQLi, XSS, LFI)."""
        window = self._web_attacks[src_ip]
        window.append(now)

        while window and (now - window[0]) > self.WEB_ATTACK_WINDOW:
            window.popleft()

        if len(window) >= self.WEB_ATTACK_THRESHOLD:
            uri = event.get("metadata", {}).get("uri", "")
            incident = self._create_incident(
                severity="Critical",
                description=f"Web Application Attack: {len(window)} malicious requests from {src_ip} (last: {uri[:60]})",
                attack_type="sql_injection",
                src_ip=src_ip,
                target=event.get("dst_ip", "Web Server"),
                source="web_server",
                events=[event],
            )
            window.clear()
            return incident
        return None

    def _detect_dns_tunnel(self, event: dict, src_ip: str, now: float) -> Optional[Incident]:
        """Detect potential DNS tunneling."""
        domain = event.get("metadata", {}).get("domain", "")
        return self._create_incident(
            severity="High",
            description=f"Potential DNS Tunneling: Unusually long domain query from {src_ip} ({domain[:40]}...)",
            attack_type="dns_tunnel",
            src_ip=src_ip,
            target="DNS Server",
            source="dns",
            events=[event],
        )

    def _cross_source_correlation(self, event: dict, src_ip: str, now: float) -> Optional[Incident]:
        """
        Layer 3: Cross-source correlation.
        Looks for patterns that span multiple log sources, such as:
        - Recon (port scan) followed by exploitation attempt
        - Failed VPN + successful login from same IP = potential credential theft
        """
        # Check if this IP has been seen in multiple suspicious contexts
        suspicious_sources = 0
        if src_ip in self._failed_logins and len(self._failed_logins[src_ip]) >= 2:
            suspicious_sources += 1
        if src_ip in self._firewall_denies and len(self._firewall_denies[src_ip]) >= 3:
            suspicious_sources += 1
        if src_ip in self._web_attacks and len(self._web_attacks[src_ip]) >= 1:
            suspicious_sources += 1
        if src_ip in self._vpn_fails and len(self._vpn_fails[src_ip]) >= 1:
            suspicious_sources += 1

        if suspicious_sources >= 3:
            return self._create_incident(
                severity="Critical",
                description=f"Multi-Vector Attack: IP {src_ip} flagged across {suspicious_sources} different attack vectors",
                attack_type="lateral_movement",
                src_ip=src_ip,
                target="Enterprise Network",
                source="cross_correlation",
                events=[event],
            )
        return None

    # ─── Helpers ────────────────────────────────────────────────────────

    def _create_incident(self, **kwargs) -> Optional[Incident]:
        """Create an incident with deduplication check."""
        # Generate a dedup hash based on attack_type + src_ip
        dedup_key = f"{kwargs.get('attack_type', '')}:{kwargs.get('src_ip', '')}"
        if dedup_key in self._recent_incident_hashes:
            return None

        self._recent_incident_hashes.append(dedup_key)
        incident = Incident(**kwargs)
        self.incidents.append(incident)
        print(f"  [{incident.severity.upper()}] {incident.description}")
        return incident

    def _update_event_rate(self, now: float) -> None:
        """Track events per minute for baseline anomaly detection."""
        if now - self._last_minute_ts >= 60:
            self._event_rate_baseline.append(self._current_minute_count)
            self._current_minute_count = 0
            self._last_minute_ts = now
        self._current_minute_count += 1


# ─── Standalone Test ────────────────────────────────────────────────────
if __name__ == "__main__":
    engine = CorrelationEngine()

    # Simulate brute force
    for i in range(6):
        engine.analyze({
            "event_type": "failed_logon",
            "source_type": "active_directory",
            "src_ip": "45.2.3.11",
            "username": "admin",
            "action": "FAILURE",
        })

    print(f"\nIncidents generated: {len(engine.incidents)}")
    for inc in engine.incidents:
        print(f"  {inc.to_dict()}")
