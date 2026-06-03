"""
Log Aggregator & Normalization Engine
=======================================
Collects raw logs from heterogeneous sources (Firewall, Active Directory,
Web Server, DNS, VPN, Syslog) and normalizes them into a unified
Common Event Format (CEF) structure for downstream correlation.

Supported Log Sources:
    - Firewall (iptables/pf style syslog)
    - Windows Active Directory (Event Log JSON)
    - Web Server (Apache/Nginx combined log format)
    - DNS Query Logs
    - VPN Authentication Logs
    - Generic Syslog (RFC 5424)

Architecture:
    Raw Log → Source-Specific Parser → CEF Normalization → Output Queue
"""

import json
import re
import time
import hashlib
from datetime import datetime
from typing import Optional, Dict, List, Any


# ─── CEF Severity Mapping ──────────────────────────────────────────────
CEF_SEVERITY_MAP: Dict[str, int] = {
    "EMERGENCY": 10, "ALERT": 9, "CRITICAL": 8,
    "ERROR": 7, "WARNING": 6, "NOTICE": 5,
    "INFO": 4, "DEBUG": 3,
}


class NormalizedEvent:
    """
    Common Event Format (CEF) normalized log event.
    All log sources are transformed into this uniform schema
    to enable cross-source correlation in the SIEM engine.
    """

    __slots__ = (
        "event_id", "timestamp", "source_type", "event_type",
        "severity", "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "action", "username", "hostname",
        "description", "raw_log", "metadata",
    )

    def __init__(self, **kwargs):
        self.event_id: str = kwargs.get("event_id", self._generate_id())
        self.timestamp: str = kwargs.get("timestamp", datetime.now().isoformat())
        self.source_type: str = kwargs.get("source_type", "unknown")
        self.event_type: str = kwargs.get("event_type", "generic")
        self.severity: int = kwargs.get("severity", 4)
        self.src_ip: str = kwargs.get("src_ip", "")
        self.dst_ip: str = kwargs.get("dst_ip", "")
        self.src_port: int = kwargs.get("src_port", 0)
        self.dst_port: int = kwargs.get("dst_port", 0)
        self.protocol: str = kwargs.get("protocol", "")
        self.action: str = kwargs.get("action", "")
        self.username: str = kwargs.get("username", "")
        self.hostname: str = kwargs.get("hostname", "")
        self.description: str = kwargs.get("description", "")
        self.raw_log: str = kwargs.get("raw_log", "")
        self.metadata: Dict[str, Any] = kwargs.get("metadata", {})

    @staticmethod
    def _generate_id() -> str:
        """Generate a unique event ID using timestamp + random hash."""
        raw = f"{time.time()}-{id(object())}".encode()
        return hashlib.sha256(raw).hexdigest()[:16]

    def to_dict(self) -> dict:
        """Serialize the normalized event to a dictionary."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "source_type": self.source_type,
            "event_type": self.event_type,
            "severity": self.severity,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "action": self.action,
            "username": self.username,
            "hostname": self.hostname,
            "description": self.description,
            "raw_log": self.raw_log,
            "metadata": self.metadata,
        }

    def __repr__(self) -> str:
        return (
            f"<Event {self.event_id[:8]} | {self.source_type} | "
            f"{self.event_type} | {self.action} | sev={self.severity}>"
        )


# ─── Regex Patterns for Log Parsing ────────────────────────────────────
_FW_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s+"
    r"\[FIREWALL\]\s+(?P<action>ALLOW|DENY|DROP|REJECT)\s+"
    r"SRC=(?P<src_ip>\S+)\s+DST=(?P<dst_ip>\S+)\s+"
    r"(?:SPORT=(?P<sport>\d+)\s+)?DPORT=(?P<dport>\d+)"
    r"(?:\s+PROTO=(?P<proto>\S+))?"
)

_SYSLOG_PATTERN = re.compile(
    r"<(?P<pri>\d+)>"
    r"(?P<version>\d+)?\s*"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<appname>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<msg>.*)"
)

_WEBLOG_PATTERN = re.compile(
    r'(?P<src_ip>\S+)\s+-\s+(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<uri>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d+)\s+(?P<bytes>\d+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

_DNS_PATTERN = re.compile(
    r"(?P<timestamp>\S+)\s+(?P<client_ip>\S+)#\d+\s+"
    r"query:\s+(?P<domain>\S+)\s+(?P<qtype>\S+)\s+(?P<qclass>\S+)"
)

_VPN_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s+"
    r"\[VPN\]\s+(?P<action>CONNECT|DISCONNECT|AUTH_FAIL)\s+"
    r"USER=(?P<user>\S+)\s+IP=(?P<src_ip>\S+)"
    r"(?:\s+TUNNEL=(?P<tunnel>\S+))?"
)


class LogAggregator:
    """
    Central log collection and normalization engine.

    Receives raw log strings from various sources, applies source-specific
    parsing, normalizes to CEF format, and maintains an in-memory event
    buffer for consumption by the correlation engine.

    Attributes:
        events: List of normalized events (bounded buffer)
        stats: Per-source ingestion statistics
        max_buffer: Maximum events to retain in memory
    """

    def __init__(self, max_buffer: int = 500) -> None:
        self.events: List[NormalizedEvent] = []
        self.max_buffer = max_buffer
        self.stats: Dict[str, int] = {
            "firewall": 0, "active_directory": 0, "web_server": 0,
            "dns": 0, "vpn": 0, "syslog": 0, "unknown": 0,
            "parse_errors": 0,
        }

    # ─── Public API ─────────────────────────────────────────────────────

    def ingest_log(self, log_type: str, raw_data: str) -> Optional[NormalizedEvent]:
        """
        Entry point for incoming raw logs.

        Args:
            log_type: Source identifier (firewall, active_directory, web_server, dns, vpn, syslog)
            raw_data: Raw log string to parse and normalize

        Returns:
            NormalizedEvent if parsing succeeded, None otherwise
        """
        parser_map = {
            "firewall": self._parse_firewall,
            "active_directory": self._parse_ad_event,
            "web_server": self._parse_web_log,
            "dns": self._parse_dns_log,
            "vpn": self._parse_vpn_log,
            "syslog": self._parse_syslog,
        }

        parser = parser_map.get(log_type)
        if not parser:
            self.stats["unknown"] += 1
            return None

        try:
            event = parser(raw_data)
            if event:
                self._buffer_event(event)
                self.stats[log_type] = self.stats.get(log_type, 0) + 1
                return event
            else:
                self.stats["parse_errors"] += 1
                return None
        except Exception:
            self.stats["parse_errors"] += 1
            return None

    def get_recent_events(self, count: int = 20) -> List[Dict[str, Any]]:
        """Return the most recent N events as dictionaries."""
        return [e.to_dict() for e in self.events[-count:]]

    def get_stats(self) -> Dict[str, int]:
        """Return ingestion statistics per source."""
        return {**self.stats, "total_buffered": len(self.events)}

    # ─── Private Parsers ────────────────────────────────────────────────

    def _parse_firewall(self, raw: str) -> Optional[NormalizedEvent]:
        """
        Parse firewall syslog format.
        Example: "2026-04-05 10:00:01 [FIREWALL] DENY SRC=192.168.1.5 DST=10.0.0.5 DPORT=22"
        """
        match = _FW_PATTERN.search(raw)
        if not match:
            return None

        action = match.group("action")
        severity: int = 7 if action in ("DENY", "DROP", "REJECT") else 4

        return NormalizedEvent(
            timestamp=match.group("timestamp"),
            source_type="firewall",
            event_type="network_traffic",
            severity=severity,
            src_ip=match.group("src_ip"),
            dst_ip=match.group("dst_ip"),
            src_port=int(match.group("sport") or 0),
            dst_port=int(match.group("dport")),
            protocol=match.group("proto") or "TCP",
            action=action,
            description=f"Firewall {action}: {match.group('src_ip')} -> {match.group('dst_ip')}:{match.group('dport')}",
            raw_log=raw,
        )

    def _parse_ad_event(self, raw: str) -> Optional[NormalizedEvent]:
        """
        Parse Windows Active Directory Event Log JSON.
        Supports EventIDs: 4624 (success), 4625 (failed), 4720 (user created),
        4726 (user deleted), 4732 (member added to group).
        """
        try:
            data: Dict[str, Any] = json.loads(raw)
        except json.JSONDecodeError:
            return None

        event_id: int = data.get("EventID", 0)

        # Map Windows Event IDs to semantic types
        event_map: Dict[int, Tuple[str, str, int, str]] = {
            4624: ("successful_logon", "SUCCESS", 4, "Successful authentication"),
            4625: ("failed_logon", "FAILURE", 7, "Failed authentication attempt"),
            4720: ("user_created", "CREATE", 5, "New user account created"),
            4726: ("user_deleted", "DELETE", 6, "User account deleted"),
            4732: ("group_member_added", "MODIFY", 6, "Member added to security group"),
            4768: ("kerberos_tgt", "REQUEST", 4, "Kerberos TGT requested"),
            4769: ("kerberos_service", "REQUEST", 4, "Kerberos service ticket requested"),
            4771: ("kerberos_preauth_fail", "FAILURE", 7, "Kerberos pre-authentication failed"),
        }

        event_info: Tuple[str, str, int, str] = event_map.get(event_id, ("ad_generic", "INFO", 4, "AD event"))

        return NormalizedEvent(
            timestamp=data.get("TimeCreated", datetime.now().isoformat()),
            source_type="active_directory",
            event_type=event_info[0],
            severity=event_info[2],
            action=event_info[1],
            src_ip=data.get("IpAddress", ""),
            username=data.get("TargetUserName", ""),
            hostname=data.get("WorkstationName", ""),
            description=f"{event_info[3]} - User: {data.get('TargetUserName', 'N/A')}",
            raw_log=raw,
            metadata={"windows_event_id": event_id, "logon_type": data.get("LogonType", "")},
        )

    def _parse_web_log(self, raw: str) -> Optional[NormalizedEvent]:
        """
        Parse Apache/Nginx combined log format.
        Example: '192.168.1.10 - admin [05/Apr/2026:10:00:01 +0000] "GET /admin HTTP/1.1" 200 1234'
        """
        match = _WEBLOG_PATTERN.search(raw)
        if not match:
            return None

        status_code: int = int(match.group("status"))
        method: str = match.group("method")
        uri: str = match.group("uri")

        # Determine severity based on status code and URI patterns
        severity: int = 4
        event_type: str = "web_request"
        if status_code >= 500:
            severity = 7
            event_type = "server_error"
        elif status_code in (401, 403):
            severity = 6
            event_type = "access_denied"
        elif status_code == 404 and any(p in uri for p in [".env", "wp-admin", "phpmyadmin", ".git"]):
            severity = 6
            event_type = "recon_attempt"

        # Check for suspicious URI patterns (injection attempts)
        suspicious_patterns: List[str] = ["' OR ", "UNION SELECT", "<script>", "../", "etc/passwd", "cmd.exe"]
        if any(pat.lower() in uri.lower() for pat in suspicious_patterns):
            severity = 8
            event_type = "injection_attempt"

        return NormalizedEvent(
            timestamp=match.group("timestamp"),
            source_type="web_server",
            event_type=event_type,
            severity=severity,
            src_ip=match.group("src_ip"),
            action=method,
            username=match.group("user") if match.group("user") != "-" else "",
            description=f"{method} {uri} -> {status_code}",
            raw_log=raw,
            metadata={
                "method": method, "uri": uri, "status_code": status_code,
                "bytes": int(match.group("bytes")),
                "user_agent": match.group("ua") or "",
            },
        )

    def _parse_dns_log(self, raw: str) -> Optional[NormalizedEvent]:
        """
        Parse DNS query log format.
        Example: "2026-04-05T10:00:01 192.168.1.10#52341 query: evil.com A IN"
        """
        match: Optional[Match[str]] = _DNS_PATTERN.search(raw)
        if not match:
            return None

        domain: str = match.group("domain")
        severity: int = 4

        # Check for suspicious DNS patterns
        event_type: str = "dns_query"
        suspicious_tlds: List[str] = [".tk", ".ml", ".cf", ".xyz", ".top", ".buzz"]
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            severity: int = 6
            event_type: str = "suspicious_dns"
        if len(domain) > 60:
            severity: int = 7
            event_type: str = "dns_tunnel_suspect"

        return NormalizedEvent(
            timestamp=match.group("timestamp"),
            source_type="dns",
            event_type=event_type,
            severity=severity,
            src_ip=match.group("client_ip"),
            action="QUERY",
            description=f"DNS {match.group('qtype')} query: {domain}",
            raw_log=raw,
            metadata={"domain": domain, "query_type": match.group("qtype")},
        )

    def _parse_vpn_log(self, raw: str) -> Optional[NormalizedEvent]:
        """
        Parse VPN authentication log format.
        Example: "2026-04-05 10:00:01 [VPN] CONNECT USER=john IP=10.0.0.5"
        """
        match: Optional[Match[str]] = _VPN_PATTERN.search(raw)
        if not match:
            return None

        action: str = match.group("action")
        severity_map: Dict[str, int] = {"CONNECT": 4, "DISCONNECT": 4, "AUTH_FAIL": 7}

        return NormalizedEvent(
            timestamp=match.group("timestamp"),
            source_type="vpn",
            event_type=f"vpn_{action.lower()}",
            severity=severity_map.get(action, 4),
            src_ip=match.group("src_ip"),
            action=action,
            username=match.group("user"),
            description=f"VPN {action} - User: {match.group('user')} from {match.group('src_ip')}",
            raw_log=raw,
            metadata={"tunnel": match.group("tunnel") or "default"},
        )

    def _parse_syslog(self, raw: str) -> Optional[NormalizedEvent]:
        """
        Parse RFC 5424 syslog format.
        Example: "<134>1 2026-04-05T10:00:01Z server01 sshd 1234 - Connection closed"
        """
        match: Optional[Match[str]] = _SYSLOG_PATTERN.search(raw)
        if not match:
            # Fallback: treat as plain text syslog
            return NormalizedEvent(
                source_type="syslog",
                event_type="generic_syslog",
                severity=4,
                description=raw[:200],
                raw_log=raw,
            )

        # RFC 5424: PRI = facility * 8 + severity
        pri: int = int(match.group("pri"))
        syslog_severity: int = pri % 8
        # Map syslog severity (0-7, lower=more severe) to our scale (0-10, higher=more severe)
        severity: int = max(0, 10 - syslog_severity)

        return NormalizedEvent(
            timestamp=match.group("timestamp"),
            source_type="syslog",
            event_type="syslog_message",
            severity=severity,
            hostname=match.group("hostname"),
            description=match.group("msg").strip(),
            raw_log=raw,
            metadata={
                "facility": pri // 8,
                "appname": match.group("appname"),
                "procid": match.group("procid"),
            },
        )

    # ─── Buffer Management ──────────────────────────────────────────────

    def _buffer_event(self, event: NormalizedEvent) -> None:
        """Add event to buffer with overflow protection."""
        self.events.append(event)
        if len(self.events) > self.max_buffer:
            # Remove oldest 10% when buffer overflows
            trim_count = self.max_buffer // 10
            self.events = self.events[trim_count:]


# ─── Standalone Test ────────────────────────────────────────────────────
if __name__ == "__main__":
    agg = LogAggregator()

    # Test firewall log
    fw = "2026-05-01 12:00:00 [FIREWALL] DENY SRC=8.8.8.8 DST=10.0.0.10 DPORT=3389"
    result = agg.ingest_log("firewall", fw)
    print(f"Firewall: {result}")

    # Test AD log
    ad = '{"EventID": 4625, "TimeCreated": "2026-05-01 12:01:00", "TargetUserName": "admin", "IpAddress": "8.8.8.8"}'
    result = agg.ingest_log("active_directory", ad)
    print(f"AD:       {result}")

    # Test web log
    web = '192.168.1.10 - - [05/Apr/2026:10:00:01 +0000] "GET /admin HTTP/1.1" 403 512 "-" "Mozilla/5.0"'
    result = agg.ingest_log("web_server", web)
    print(f"Web:      {result}")

    # Test DNS log
    dns = "2026-04-05T10:00:01 192.168.1.10#52341 query: suspicious-domain.tk A IN"
    result = agg.ingest_log("dns", dns)
    print(f"DNS:      {result}")

    # Test VPN log
    vpn = "2026-04-05 10:00:01 [VPN] AUTH_FAIL USER=hacker IP=45.2.3.11"
    result = agg.ingest_log("vpn", vpn)
    print(f"VPN:      {result}")

    print(f"\nStats: {agg.get_stats()}")
