"""
Stateful Connection Tracker
============================
Tracks TCP connection states for stateful packet inspection.

Stateless vs Stateful Firewall:
- STATELESS: Examines each packet independently. Simple but limited.
  Must create rules for BOTH directions of a conversation.
- STATEFUL: Tracks connection state. Once a connection is established,
  return traffic is automatically allowed. Much more secure.

TCP Connection States:
  NEW         -> First SYN packet of a new connection
  SYN_SENT    -> SYN sent, waiting for SYN-ACK
  SYN_RECV    -> SYN-ACK received
  ESTABLISHED -> 3-way handshake complete, data flowing
  FIN_WAIT    -> FIN sent, closing connection
  CLOSED      -> Connection terminated

Why Stateful Inspection Matters:
- An attacker can't send a lone ACK packet to bypass firewall rules
  (because no matching connection exists in the state table)
- Return traffic for outbound connections is auto-allowed
- Reduces number of rules needed (no need for explicit return rules)
- Detects invalid packets that don't belong to any connection

Real-World Example:
  Your browser opens a connection to google.com:443 (OUTBOUND)
  Stateful FW automatically allows google.com's response (INBOUND)
  Without stateful tracking, you'd need explicit rules for responses
"""

import time
import threading
from dataclasses import dataclass, field
from typing import Dict, Optional
from .packet_parser import Packet, Protocol


class ConnectionState:
    NEW = "NEW"
    SYN_SENT = "SYN_SENT"
    SYN_RECV = "SYN_RECV"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT = "FIN_WAIT"
    CLOSE_WAIT = "CLOSE_WAIT"
    CLOSED = "CLOSED"
    RELATED = "RELATED"
    INVALID = "INVALID"


@dataclass
class Connection:
    """Represents a tracked network connection."""
    conn_id: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "TCP"
    state: str = ConnectionState.NEW
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0

    def to_dict(self):
        return {
            "conn_id": self.conn_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "state": self.state,
            "age_seconds": round(time.time() - self.created_at, 1),
            "last_seen_ago": round(time.time() - self.last_seen, 1),
            "packets_in": self.packets_in,
            "packets_out": self.packets_out,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
        }


class StatefulTracker:
    """
    Tracks TCP/UDP connection states for stateful packet inspection.
    
    Connection Table:
    - Stores all active connections with their state
    - Indexed by a connection key: (src_ip, dst_ip, src_port, dst_port, protocol)
    - Automatically expires idle connections (configurable timeout)
    
    In enterprise firewalls, the connection table could
    track millions of simultaneous connections across 4 refineries.
    """

    # Timeout values (seconds)
    TCP_ESTABLISHED_TIMEOUT = 3600     # 1 hour for active TCP
    TCP_SYN_TIMEOUT = 30               # 30s for half-open (SYN flood protection!)
    TCP_FIN_TIMEOUT = 60               # 1 min for closing connections
    UDP_TIMEOUT = 180                  # 3 min for UDP (connectionless)

    def __init__(self):
        self.connections: Dict[str, Connection] = {}
        self._lock = threading.Lock()
        self._stats = {
            "total_tracked": 0,
            "active_connections": 0,
            "expired_connections": 0,
            "invalid_packets": 0,
        }

    def _make_key(self, packet: Packet) -> str:
        """
        Create a unique connection key from packet fields.
        
        Important: We must handle bidirectional traffic!
        A connection from A:1234 -> B:80 should match
        the response from B:80 -> A:1234.
        
        We normalize by sorting the IP:port pairs so both
        directions produce the same key.
        """
        pair1 = (packet.src_ip, packet.src_port)
        pair2 = (packet.dst_ip, packet.dst_port)
        
        if pair1 > pair2:
            pair1, pair2 = pair2, pair1
        
        return f"{pair1[0]}:{pair1[1]}-{pair2[0]}:{pair2[1]}-{packet.protocol.value}"

    def _make_forward_key(self, packet: Packet) -> str:
        """Key with direction preserved (for state tracking)."""
        return f"{packet.src_ip}:{packet.src_port}->{packet.dst_ip}:{packet.dst_port}-{packet.protocol.value}"

    def track_packet(self, packet: Packet) -> str:
        """
        Process a packet and update connection state.
        
        Returns the connection state:
        - NEW: First packet of a new connection
        - ESTABLISHED: Part of an established connection
        - RELATED: Related to an existing connection
        - INVALID: Doesn't match any valid connection state
        """
        conn_key = self._make_key(packet)

        with self._lock:
            if conn_key in self.connections:
                return self._update_existing(conn_key, packet)
            else:
                return self._create_new(conn_key, packet)

    def _create_new(self, conn_key: str, packet: Packet) -> str:
        """Handle the first packet of a new connection."""
        
        if packet.protocol == Protocol.TCP:
            # Valid new TCP connection MUST start with SYN
            if "SYN" in packet.tcp_flags and "ACK" not in packet.tcp_flags:
                conn = Connection(
                    conn_id=conn_key,
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    src_port=packet.src_port,
                    dst_port=packet.dst_port,
                    protocol="TCP",
                    state=ConnectionState.SYN_SENT,
                    packets_out=1,
                    bytes_out=packet.size,
                )
                self.connections[conn_key] = conn
                self._stats["total_tracked"] += 1
                self._stats["active_connections"] = len(self.connections)
                return ConnectionState.NEW
            else:
                # Non-SYN first packet = INVALID
                # This could be a scan or an attack attempt
                self._stats["invalid_packets"] += 1
                return ConnectionState.INVALID

        elif packet.protocol == Protocol.UDP:
            # UDP is connectionless, but we track it for return traffic
            conn = Connection(
                conn_id=conn_key,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol="UDP",
                state=ConnectionState.NEW,
                packets_out=1,
                bytes_out=packet.size,
            )
            self.connections[conn_key] = conn
            self._stats["total_tracked"] += 1
            return ConnectionState.NEW

        elif packet.protocol == Protocol.ICMP:
            conn = Connection(
                conn_id=conn_key,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                protocol="ICMP",
                state=ConnectionState.NEW,
                packets_out=1,
                bytes_out=packet.size,
            )
            self.connections[conn_key] = conn
            self._stats["total_tracked"] += 1
            return ConnectionState.NEW

        return ConnectionState.NEW

    def _update_existing(self, conn_key: str, packet: Packet) -> str:
        """Update state for an existing tracked connection."""
        conn = self.connections[conn_key]
        conn.last_seen = time.time()

        # Determine if this is inbound or outbound relative to the connection
        is_reply = (packet.src_ip == conn.dst_ip and packet.src_port == conn.dst_port)

        if is_reply:
            conn.packets_in += 1
            conn.bytes_in += packet.size
        else:
            conn.packets_out += 1
            conn.bytes_out += packet.size

        if packet.protocol == Protocol.TCP:
            return self._update_tcp_state(conn, packet, is_reply)
        
        # For UDP / ICMP, if we see a reply it's ESTABLISHED
        if is_reply and conn.state == ConnectionState.NEW:
            conn.state = ConnectionState.ESTABLISHED
        
        return conn.state

    def _update_tcp_state(self, conn: Connection, packet: Packet, is_reply: bool) -> str:
        """
        TCP State Machine:
        
        SYN_SENT + SYN-ACK (reply)  -> SYN_RECV
        SYN_RECV + ACK              -> ESTABLISHED
        ESTABLISHED + FIN            -> FIN_WAIT
        FIN_WAIT + FIN-ACK          -> CLOSED
        Any + RST                   -> CLOSED
        """
        flags = packet.tcp_flags

        # RST always closes
        if "RST" in flags:
            conn.state = ConnectionState.CLOSED
            return ConnectionState.CLOSED

        current = conn.state

        if current == ConnectionState.SYN_SENT:
            if is_reply and "SYN" in flags and "ACK" in flags:
                conn.state = ConnectionState.SYN_RECV
                return ConnectionState.SYN_RECV
            
        elif current == ConnectionState.SYN_RECV:
            if not is_reply and "ACK" in flags:
                conn.state = ConnectionState.ESTABLISHED
                return ConnectionState.ESTABLISHED

        elif current == ConnectionState.ESTABLISHED:
            if "FIN" in flags:
                conn.state = ConnectionState.FIN_WAIT
                return ConnectionState.FIN_WAIT
            return ConnectionState.ESTABLISHED

        elif current == ConnectionState.FIN_WAIT:
            if "FIN" in flags and "ACK" in flags:
                conn.state = ConnectionState.CLOSED
                return ConnectionState.CLOSED
            elif "ACK" in flags:
                conn.state = ConnectionState.CLOSE_WAIT
                return ConnectionState.CLOSE_WAIT

        elif current == ConnectionState.CLOSE_WAIT:
            if "FIN" in flags:
                conn.state = ConnectionState.CLOSED
                return ConnectionState.CLOSED

        return conn.state

    def cleanup_expired(self):
        """Remove expired connections from the table."""
        now = time.time()
        expired = []

        with self._lock:
            for key, conn in self.connections.items():
                idle_time = now - conn.last_seen
                
                if conn.state == ConnectionState.CLOSED:
                    expired.append(key)
                elif conn.protocol == "TCP":
                    if conn.state in (ConnectionState.SYN_SENT, ConnectionState.SYN_RECV):
                        if idle_time > self.TCP_SYN_TIMEOUT:
                            expired.append(key)
                    elif conn.state in (ConnectionState.FIN_WAIT, ConnectionState.CLOSE_WAIT):
                        if idle_time > self.TCP_FIN_TIMEOUT:
                            expired.append(key)
                    elif idle_time > self.TCP_ESTABLISHED_TIMEOUT:
                        expired.append(key)
                elif conn.protocol == "UDP":
                    if idle_time > self.UDP_TIMEOUT:
                        expired.append(key)
                elif idle_time > self.UDP_TIMEOUT:
                    expired.append(key)

            for key in expired:
                del self.connections[key]
                self._stats["expired_connections"] += 1
            
            self._stats["active_connections"] = len(self.connections)

        return len(expired)

    def get_connection_table(self) -> list:
        """Get all active connections as a list of dicts."""
        with self._lock:
            return [c.to_dict() for c in self.connections.values()]

    def get_stats(self) -> dict:
        """Get tracker statistics."""
        with self._lock:
            state_counts = {}
            for conn in self.connections.values():
                state_counts[conn.state] = state_counts.get(conn.state, 0) + 1
            
            return {
                **self._stats,
                "active_connections": len(self.connections),
                "state_distribution": state_counts,
            }

    def is_established(self, packet: Packet) -> bool:
        """Check if a packet belongs to an ESTABLISHED connection."""
        conn_key = self._make_key(packet)
        with self._lock:
            conn = self.connections.get(conn_key)
            return conn is not None and conn.state == ConnectionState.ESTABLISHED
