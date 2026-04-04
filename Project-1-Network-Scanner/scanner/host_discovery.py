"""
Host Discovery Module
=====================
Discovers active hosts on a network using multiple techniques.

How Host Discovery Works:
1. ARP Scan (Layer 2) - Most reliable for local networks
   - Sends ARP "Who has <IP>?" broadcasts on the local network segment
   - If a device exists with that IP, it responds with its MAC address
   - Works only within the same subnet (broadcast domain)
   - Cannot be blocked by host-based firewalls

2. ICMP Ping (Layer 3) - Works across subnets
   - Sends ICMP Echo Request (Type 8) packets
   - If the host is alive and allows ICMP, it responds with Echo Reply (Type 0)
   - Some hosts/firewalls block ICMP, causing false negatives
   - Can work across different subnets/networks

3. TCP Ping (Layer 4) - Most firewall-evasive
   - Sends TCP SYN to a common port (80, 443)
   - If host is up, it responds with SYN-ACK (open) or RST (closed)
   - Both responses confirm the host is alive
   - Most likely to penetrate firewalls

Security Relevance:
- Asset inventory: You can't protect what you don't know exists
- Rogue device detection: Find unauthorized devices on the network
- Network mapping: Understand the topology before securing it
"""

import socket
import struct
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


class HostDiscovery:
    """
    Discovers active hosts on a network using multiple scanning techniques.
    
    In a large corporate environment (10,000+ clients, 500+ servers),
    asset discovery is the FIRST step in security management. You cannot
    secure devices you don't know about.
    """

    def __init__(self, timeout: float = 1.0, max_threads: int = 100):
        """
        Args:
            timeout: Seconds to wait for a response from each host
            max_threads: Maximum concurrent scanning threads
        """
        self.timeout = timeout
        self.max_threads = max_threads
        self.discovered_hosts = []
        self._lock = threading.Lock()

    def icmp_ping(self, ip: str) -> dict:
        """
        Send an ICMP Echo Request to check if host is alive.
        
        ICMP (Internet Control Message Protocol) operates at Layer 3 (Network).
        It's the protocol behind the 'ping' command.
        
        How it works:
        1. We craft an ICMP Echo Request packet (Type=8, Code=0)
        2. Send it to the target IP using a raw socket
        3. If the host is alive, it responds with ICMP Echo Reply (Type=0)
        4. We measure the round-trip time (RTT)
        
        Limitations:
        - Requires admin/root privileges for raw sockets
        - Some hosts block ICMP (Windows Firewall blocks by default)
        - Some networks block ICMP at the router level
        """
        result = {
            "ip": ip,
            "alive": False,
            "method": "ICMP",
            "rtt_ms": None,
            "timestamp": datetime.now().isoformat(),
        }

        try:
            # Create a raw ICMP socket
            # AF_INET = IPv4, SOCK_RAW = raw packets, IPPROTO_ICMP = ICMP protocol
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(self.timeout)

            # Build ICMP Echo Request packet
            # Type(8) | Code(0) | Checksum | ID | Sequence | Data
            icmp_type = 8  # Echo Request
            icmp_code = 0
            icmp_checksum = 0
            icmp_id = threading.current_thread().ident & 0xFFFF
            icmp_seq = 1
            icmp_data = b"SecurityFundamentals" * 2  # 40 bytes payload

            # Pack header without checksum first
            header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
            packet = header + icmp_data

            # Calculate and insert checksum
            icmp_checksum = self._calculate_checksum(packet)
            header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
            packet = header + icmp_data

            # Send and receive
            start_time = time.time()
            sock.sendto(packet, (ip, 0))
            
            response, addr = sock.recvfrom(1024)
            end_time = time.time()

            # Parse response - skip IP header (first 20 bytes)
            icmp_reply_type = response[20]
            if icmp_reply_type == 0:  # Echo Reply
                result["alive"] = True
                result["rtt_ms"] = round((end_time - start_time) * 1000, 2)

            sock.close()

        except socket.timeout:
            pass  # Host didn't respond - might be down or blocking ICMP
        except PermissionError:
            # Raw sockets require admin privileges
            # Fall back to TCP ping
            return self.tcp_ping(ip)
        except OSError:
            # Fallback to TCP ping on any socket error
            return self.tcp_ping(ip)

        return result

    def tcp_ping(self, ip: str, port: int = 80) -> dict:
        """
        Use TCP connection attempt to check if host is alive.
        
        How it works (TCP Three-Way Handshake):
        1. We send SYN (synchronize) to target port
        2. If host is up:
           - Port OPEN → responds with SYN-ACK → host is alive
           - Port CLOSED → responds with RST → host is alive
        3. If host is down → no response (timeout)
        
        This is more reliable than ICMP because:
        - TCP traffic is less likely to be blocked
        - Almost every host has at least one open TCP port
        - Doesn't require admin privileges
        """
        result = {
            "ip": ip,
            "alive": False,
            "method": "TCP",
            "rtt_ms": None,
            "timestamp": datetime.now().isoformat(),
        }

        # Try multiple common ports for better detection
        ports_to_try = [80, 443, 22, 445, 3389, 135]

        for try_port in ports_to_try:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                
                start_time = time.time()
                conn_result = sock.connect_ex((ip, try_port))
                end_time = time.time()
                
                sock.close()

                # connect_ex returns 0 if connection succeeded (port open)
                # Any other value means the connection was refused or timed out
                # BUT a refused connection (RST) still means the host is alive!
                if conn_result == 0:
                    result["alive"] = True
                    result["rtt_ms"] = round((end_time - start_time) * 1000, 2)
                    result["method"] = f"TCP/{try_port}"
                    return result
                elif (end_time - start_time) < self.timeout * 0.9:
                    # Got a quick RST response → host is alive but port closed
                    result["alive"] = True
                    result["rtt_ms"] = round((end_time - start_time) * 1000, 2)
                    result["method"] = f"TCP/{try_port}(RST)"
                    return result

            except socket.timeout:
                continue
            except OSError:
                continue

        return result

    def scan_network(self, targets: list, method: str = "tcp") -> list:
        """
        Scan a list of IP addresses for active hosts.
        
        Uses multi-threading for parallel scanning. In a large network
        like an industrial plant with thousands of devices, sequential scanning would
        take too long. With 100 threads, we can scan a /24 subnet 
        (254 hosts) in seconds.
        
        Args:
            targets: List of IP addresses to scan
            method: 'icmp' for ICMP ping, 'tcp' for TCP ping
            
        Returns:
            list: List of discovered host dictionaries
        """
        self.discovered_hosts = []
        scan_func = self.icmp_ping if method == "icmp" else self.tcp_ping

        print(f"\n[*] Starting host discovery on {len(targets)} targets using {method.upper()}...")
        print(f"[*] Timeout: {self.timeout}s | Threads: {self.max_threads}")
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(scan_func, ip): ip for ip in targets}
            
            completed = 0
            for future in as_completed(futures):
                completed += 1
                try:
                    result = future.result()
                    if result["alive"]:
                        with self._lock:
                            self.discovered_hosts.append(result)
                        print(f"  [+] {result['ip']} is UP (RTT: {result['rtt_ms']}ms, Method: {result['method']})")
                except Exception:
                    pass

                # Progress indicator
                if completed % 50 == 0 or completed == len(targets):
                    print(f"  [*] Progress: {completed}/{len(targets)} scanned")

        elapsed = round(time.time() - start_time, 2)
        print(f"\n[*] Host discovery complete: {len(self.discovered_hosts)} hosts up in {elapsed}s")

        # Sort by IP address
        self.discovered_hosts.sort(key=lambda x: [int(o) for o in x["ip"].split(".")])
        return self.discovered_hosts

    @staticmethod
    def _calculate_checksum(data: bytes) -> int:
        """
        Calculate the Internet Checksum (RFC 1071) for ICMP packets.
        
        The checksum is a simple error-detection mechanism:
        1. Split data into 16-bit words
        2. Sum all words
        3. Add any carry bits back
        4. Take one's complement (flip all bits)
        
        This ensures packet integrity during transmission.
        """
        if len(data) % 2:
            data += b'\x00'

        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word

        # Add carry bits
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += checksum >> 16

        return ~checksum & 0xFFFF
