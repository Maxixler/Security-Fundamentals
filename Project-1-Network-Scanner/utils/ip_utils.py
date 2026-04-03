"""
IP Utilities Module
===================
Provides helper functions for IP address manipulation, subnet calculation,
CIDR notation parsing, and network range generation.

Key Concepts:
- IP Address: A unique numerical label (e.g., 192.168.1.1) assigned to each
  device on a network. IPv4 uses 32-bit addresses.
- Subnet Mask: Determines which portion of an IP address is the network part
  and which part is the host part (e.g., 255.255.255.0 = /24).
- CIDR: Classless Inter-Domain Routing notation (e.g., 192.168.1.0/24) where
  /24 means first 24 bits are the network portion.
"""

import ipaddress
import socket
import struct
import re


def validate_ip(ip_str: str) -> bool:
    """
    Validate if a string is a valid IPv4 address.
    
    An IPv4 address consists of four octets (0-255) separated by dots.
    Example valid: '192.168.1.1', '10.0.0.1'
    Example invalid: '256.1.1.1', 'abc.def.ghi.jkl'
    """
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ipaddress.AddressValueError:
        return False


def validate_cidr(cidr_str: str) -> bool:
    """
    Validate if a string is a valid CIDR notation.
    
    CIDR notation combines an IP address with a prefix length.
    Example: '192.168.1.0/24' means a network with 256 addresses
    (192.168.1.0 to 192.168.1.255)
    """
    try:
        ipaddress.IPv4Network(cidr_str, strict=False)
        return True
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return False


def parse_target(target: str) -> list:
    """
    Parse a target specification and return a list of IP addresses to scan.
    
    Supported formats:
    - Single IP: '192.168.1.1'
    - CIDR notation: '192.168.1.0/24' (all 256 IPs in subnet)
    - IP range: '192.168.1.1-50' (IPs from .1 to .50)
    - Comma-separated: '192.168.1.1,192.168.1.2,192.168.1.3'
    
    Returns:
        list: List of IP address strings to scan
    """
    targets = []

    # Handle comma-separated targets
    if ',' in target and '/' not in target:
        parts = [t.strip() for t in target.split(',')]
        for part in parts:
            targets.extend(parse_target(part))
        return list(set(targets))

    # CIDR notation (e.g., 192.168.1.0/24)
    if '/' in target:
        try:
            network = ipaddress.IPv4Network(target, strict=False)
            # Skip network and broadcast addresses for /24 and larger
            if network.prefixlen < 31:
                targets = [str(ip) for ip in network.hosts()]
            else:
                targets = [str(ip) for ip in network]
            return targets
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            return []

    # IP range (e.g., 192.168.1.1-50)
    range_match = re.match(r'^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$', target)
    if range_match:
        base = range_match.group(1)
        start = int(range_match.group(2))
        end = int(range_match.group(3))
        for i in range(start, min(end + 1, 256)):
            ip = f"{base}{i}"
            if validate_ip(ip):
                targets.append(ip)
        return targets

    # Single IP
    if validate_ip(target):
        return [target]

    # Try to resolve hostname
    try:
        ip = socket.gethostbyname(target)
        return [ip]
    except socket.gaierror:
        return []


def get_subnet_info(cidr: str) -> dict:
    """
    Get detailed information about a subnet.
    
    This is essential for understanding network architecture.
    For example, 192.168.1.0/24:
    - Network Address: 192.168.1.0 (identifies the network)
    - Broadcast Address: 192.168.1.255 (sends to all hosts)
    - Usable Hosts: 192.168.1.1 to 192.168.1.254 (254 hosts)
    - Subnet Mask: 255.255.255.0
    """
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
        return {
            "network_address": str(network.network_address),
            "broadcast_address": str(network.broadcast_address),
            "subnet_mask": str(network.netmask),
            "wildcard_mask": str(network.hostmask),
            "prefix_length": network.prefixlen,
            "total_hosts": network.num_addresses,
            "usable_hosts": max(0, network.num_addresses - 2),
            "first_host": str(list(network.hosts())[0]) if network.num_addresses > 2 else str(network.network_address),
            "last_host": str(list(network.hosts())[-1]) if network.num_addresses > 2 else str(network.broadcast_address),
            "is_private": network.is_private,
            "network_class": _get_network_class(network.network_address),
        }
    except Exception as e:
        return {"error": str(e)}


def _get_network_class(ip):
    """
    Determine the traditional network class (A, B, C, D, E).
    
    While classful networking is largely obsolete (replaced by CIDR),
    understanding it is fundamental:
    - Class A: 1.0.0.0 - 126.255.255.255 (large networks, /8)
    - Class B: 128.0.0.0 - 191.255.255.255 (medium networks, /16)
    - Class C: 192.0.0.0 - 223.255.255.255 (small networks, /24)
    - Class D: 224.0.0.0 - 239.255.255.255 (multicast)
    - Class E: 240.0.0.0 - 255.255.255.255 (reserved)
    """
    first_octet = int(str(ip).split('.')[0])
    if first_octet < 128:
        return "A"
    elif first_octet < 192:
        return "B"
    elif first_octet < 224:
        return "C"
    elif first_octet < 240:
        return "D"
    else:
        return "E"


def ip_to_int(ip_str: str) -> int:
    """Convert IP address string to integer for fast comparison."""
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]


def int_to_ip(ip_int: int) -> str:
    """Convert integer back to IP address string."""
    return socket.inet_ntoa(struct.pack("!I", ip_int))


def get_local_ip() -> str:
    """
    Get the local machine's IP address.
    Creates a UDP socket to an external address to determine the
    interface that would be used for outgoing traffic.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def get_local_subnet() -> str:
    """
    Get the local subnet in CIDR notation.
    Attempts to detect the subnet mask of the active network interface.
    """
    local_ip = get_local_ip()
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    if addr.get('addr') == local_ip:
                        netmask = addr.get('netmask', '255.255.255.0')
                        network = ipaddress.IPv4Network(
                            f"{local_ip}/{netmask}", strict=False
                        )
                        return str(network)
    except ImportError:
        pass

    # Fallback: assume /24
    base = '.'.join(local_ip.split('.')[:3])
    return f"{base}.0/24"


# Well-known ports dictionary for quick reference
WELL_KNOWN_PORTS = {
    20: ("FTP-Data", "File Transfer Protocol - Data"),
    21: ("FTP", "File Transfer Protocol - Control"),
    22: ("SSH", "Secure Shell - Encrypted remote login"),
    23: ("Telnet", "Unencrypted remote login (INSECURE)"),
    25: ("SMTP", "Simple Mail Transfer Protocol"),
    53: ("DNS", "Domain Name System"),
    67: ("DHCP-Server", "Dynamic Host Configuration Protocol"),
    68: ("DHCP-Client", "Dynamic Host Configuration Protocol"),
    69: ("TFTP", "Trivial File Transfer Protocol"),
    80: ("HTTP", "Hypertext Transfer Protocol"),
    110: ("POP3", "Post Office Protocol v3"),
    111: ("RPCbind", "Remote Procedure Call"),
    123: ("NTP", "Network Time Protocol"),
    135: ("MS-RPC", "Microsoft RPC (often targeted)"),
    137: ("NetBIOS-NS", "NetBIOS Name Service"),
    138: ("NetBIOS-DGM", "NetBIOS Datagram Service"),
    139: ("NetBIOS-SSN", "NetBIOS Session Service"),
    143: ("IMAP", "Internet Message Access Protocol"),
    161: ("SNMP", "Simple Network Management Protocol"),
    162: ("SNMP-Trap", "SNMP Trap notifications"),
    389: ("LDAP", "Lightweight Directory Access Protocol"),
    443: ("HTTPS", "HTTP over TLS/SSL"),
    445: ("SMB", "Server Message Block / CIFS"),
    465: ("SMTPS", "SMTP over SSL"),
    502: ("Modbus", "Modbus Protocol (Industrial/SCADA)"),
    514: ("Syslog", "System Logging Protocol"),
    587: ("SMTP-Submit", "SMTP Message Submission"),
    636: ("LDAPS", "LDAP over SSL"),
    993: ("IMAPS", "IMAP over SSL"),
    995: ("POP3S", "POP3 over SSL"),
    1080: ("SOCKS", "SOCKS Proxy"),
    1433: ("MSSQL", "Microsoft SQL Server"),
    1521: ("Oracle", "Oracle Database"),
    2049: ("NFS", "Network File System"),
    3306: ("MySQL", "MySQL Database"),
    3389: ("RDP", "Remote Desktop Protocol"),
    5432: ("PostgreSQL", "PostgreSQL Database"),
    5900: ("VNC", "Virtual Network Computing"),
    6379: ("Redis", "Redis Key-Value Store"),
    8080: ("HTTP-Alt", "Alternative HTTP / Proxy"),
    8443: ("HTTPS-Alt", "Alternative HTTPS"),
    9200: ("Elasticsearch", "Elasticsearch REST API"),
    27017: ("MongoDB", "MongoDB Database"),
    47808: ("BACnet", "Building Automation Protocol (OT)"),
}


def get_service_name(port: int) -> tuple:
    """
    Get the service name and description for a well-known port.
    
    Returns:
        tuple: (service_name, description) or ('Unknown', 'Unknown service')
    """
    if port in WELL_KNOWN_PORTS:
        return WELL_KNOWN_PORTS[port]
    try:
        name = socket.getservbyport(port)
        return (name, f"Service on port {port}")
    except OSError:
        return ("Unknown", f"Unknown service on port {port}")
