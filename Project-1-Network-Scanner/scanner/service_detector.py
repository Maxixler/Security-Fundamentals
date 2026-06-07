"""
Service Detection & Banner Grabbing Module
===========================================
Identifies services running on open ports by grabbing their banners
and fingerprinting their responses.

What is Banner Grabbing?
- When you connect to a service, it often sends a "banner" - a text
  response identifying itself (software name, version, etc.)
- Example: Connecting to port 22 might return "SSH-2.0-OpenSSH_8.9p1"
- This information is used to:
  1. Identify the exact software and version
  2. Look up known vulnerabilities (CVEs) for that version
  3. Verify if the service is authorized/expected

What is OS Fingerprinting?
- Different operating systems have characteristic network behaviors
- TTL (Time To Live) values in packets vary by OS
- TCP window sizes also differ between operating systems
- By analyzing these characteristics, we can guess the remote OS

Security Implications:
- Detailed banners help attackers identify vulnerable versions
- Best practice: Minimize banner information (banner hardening)
- In enterprise environments, knowing exact service versions helps the security
  team prioritize patching and identify unauthorized services
- OS fingerprinting helps identify potential attack vectors specific to certain OSes
"""

import socket
import ssl
import re
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


class ServiceDetector:
    """
    Detects services running on open ports using banner grabbing
    and protocol-specific probes.
    """

    # Protocol-specific probes to trigger responses from services
    PROBES = {
        "http": b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: SecurityScanner/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        "https": b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: SecurityScanner/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        "ftp": b"",  # FTP sends banner on connect
        "ssh": b"",  # SSH sends banner on connect
        "smtp": b"EHLO scanner.local\r\n",
        "pop3": b"",  # POP3 sends banner on connect
        "imap": b"",  # IMAP sends banner on connect
        "mysql": b"",  # MySQL sends greeting on connect
        "redis": b"PING\r\n",
        "mongodb": b"",
        "telnet": b"",
        "generic": b"\r\n",  # Generic probe
    }

    # Port to protocol mapping for probe selection
    PORT_PROTOCOL = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        465: "smtp",
        587: "smtp",
        993: "imap",
        995: "pop3",
        3306: "mysql",
        6379: "redis",
        8080: "http",
        8443: "https",
        27017: "mongodb",
    }

    def __init__(self, timeout: float = 3.0, max_threads: int = 50):
        self.timeout = timeout
        self.max_threads = max_threads

        # OS fingerprinting signatures based on TTL and window size
        self.OS_FINGERPRINTS = {
            "Linux": {"ttl": 64, "window": [5840, 29200, 65535]},
            "Windows": {"ttl": 128, "window": [65535, 8192, 16384, 17520, 32768]},
            "FreeBSD": {"ttl": 64, "window": [65535, 16384, 32768, 65535]},
            "OpenBSD": {"ttl": 64, "window": [65535, 16384, 32760, 65535]},
            "NetBSD": {"ttl": 64, "window": [65535, 16384, 32768, 65535]},
            "Cisco Router": {"ttl": 255, "window": [4128, 8192, 16384, 32768, 65535]},
            "Printer": {"ttl": 255, "window": [65535]},
        }

    def grab_banner(self, ip: str, port: int, service_info: dict = None) -> dict:
        """
        Attempt to grab the service banner from an open port.

        Process:
        1. Connect to the target port
        2. Some services send a banner immediately (SSH, FTP, SMTP)
        3. For others, send a protocol-specific probe (HTTP GET, etc.)
        4. Read and parse the response
        5. Extract software name, version, and other details

        Args:
            ip: Target IP address
            port: Target port number
            service_info: Optional service information from port scanner
        """
        # Use service info from port scanner if available, otherwise use defaults
        if service_info:
            # The service_info from port scanner contains 'service' and 'description' fields
            protocol = service_info.get("service", "").lower()
            # Fallback to port-based detection if service is empty or unrecognized
            if not protocol or protocol == "unknown":
                protocol = self.PORT_PROTOCOL.get(port, "unknown")
            service = service_info.get("service", "")
            description = service_info.get("description", "")
        else:
            protocol = self.PORT_PROTOCOL.get(port, "unknown")
            service = ""
            description = ""

        result = {
            "ip": ip,
            "port": port,
            "protocol": protocol,
            "banner": "",
            "service": service,
            "version": "",
            "os_hint": "",
            "ssl": False,
            "ssl_info": {},
            "security_notes": [],
            "timestamp": datetime.now().isoformat(),
        }

        # Store description for potential use in OS fingerprinting
        result["_description"] = description

        # Try SSL first for known HTTPS ports
        if port in (443, 8443, 465, 993, 995, 636):
            ssl_result = self._ssl_grab(ip, port)
            if ssl_result:
                result.update(ssl_result)
                result["ssl"] = True
                return result

        # Regular banner grab
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # Some services send banner immediately
            # Determine protocol - use service_info if available, otherwise fallback to PORT_PROTOCOL
            if service_info:
                protocol = service_info.get("service", "").lower()
                if not protocol:  # If service is empty, fallback to port-based detection
                    protocol = self.PORT_PROTOCOL.get(port, "generic")
            else:
                protocol = self.PORT_PROTOCOL.get(port, "generic")

            probe = self.PROBES.get(protocol, self.PROBES["generic"])

            if protocol == "http":
                probe = probe.replace(b"target", ip.encode())

            # Try to receive immediate banner
            banner = ""
            try:
                sock.settimeout(2.0)
                data = sock.recv(4096)
                banner = data.decode("utf-8", errors="replace").strip()
            except socket.timeout:
                pass

            # If no immediate banner, send probe
            if not banner and probe:
                try:
                    sock.send(probe)
                    sock.settimeout(3.0)
                    data = sock.recv(4096)
                    banner = data.decode("utf-8", errors="replace").strip()
                except (socket.timeout, BrokenPipeError):
                    pass

            sock.close()

            if banner:
                result["banner"] = banner[:500]  # Limit banner length
                parsed = self._parse_banner(banner, port, protocol)
                result.update(parsed)

        except Exception as e:
            result["banner"] = f"Error: {str(e)}"

        return result

    def _ssl_grab(self, ip: str, port: int) -> dict:
        """
        Grab banner over SSL/TLS and extract certificate information.
        
        SSL/TLS Security Analysis:
        - Check TLS version (TLS 1.2+ is recommended)
        - Verify certificate validity and chain
        - Check cipher suite strength
        - Look for known SSL vulnerabilities
        """
        result = {}
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            ssl_sock = context.wrap_socket(sock, server_hostname=ip)
            ssl_sock.connect((ip, port))

            # Get certificate info
            cert = ssl_sock.getpeercert(binary_form=False)
            cipher = ssl_sock.cipher()
            tls_version = ssl_sock.version()

            result["ssl_info"] = {
                "tls_version": tls_version,
                "cipher_suite": cipher[0] if cipher else "Unknown",
                "cipher_bits": cipher[2] if cipher else 0,
            }

            # Certificate parsing
            if cert:
                result["ssl_info"]["subject"] = dict(x[0] for x in cert.get("subject", []))
                result["ssl_info"]["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                result["ssl_info"]["not_before"] = cert.get("notBefore", "")
                result["ssl_info"]["not_after"] = cert.get("notAfter", "")
                result["ssl_info"]["serial_number"] = cert.get("serialNumber", "")

            # Security checks
            security_notes = []
            if tls_version and "TLSv1.0" in tls_version:
                security_notes.append("CRITICAL: TLS 1.0 is deprecated and insecure!")
            elif tls_version and "TLSv1.1" in tls_version:
                security_notes.append("WARNING: TLS 1.1 is deprecated!")
            if cipher and cipher[2] < 128:
                security_notes.append(f"WARNING: Weak cipher ({cipher[2]} bits)")
            
            result["security_notes"] = security_notes

            # Try HTTP request over SSL
            protocol = "https"
            probe = self.PROBES[protocol].replace(b"target", ip.encode())
            ssl_sock.send(probe)
            data = ssl_sock.recv(4096)
            banner = data.decode("utf-8", errors="replace").strip()
            result["banner"] = banner[:500]

            parsed = self._parse_banner(banner, port, protocol)
            result.update(parsed)

            ssl_sock.close()

        except Exception as e:
            result["banner"] = f"SSL Error: {str(e)}"

        # Perform OS fingerprinting based on TTL and window size (if available)
        # Note: In a real implementation, we'd need to capture TTL from packets
        # For this simulation, we'll use heuristic-based hints from banners
        os_hint = self._os_fingerprint_heuristic(result)
        if os_hint:
            result["os_hint"] = os_hint

        return result

    def _parse_banner(self, banner: str, port: int, protocol: str) -> dict:
        """
        Parse banner text to extract service name, version, and OS hints.
        
        Banner parsing is pattern matching against known server signatures.
        This is a simplified version of what tools like Nmap do with their
        extensive service probe database.
        """
        result = {"service": "", "version": "", "os_hint": ""}

        # SSH banners: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
        ssh_match = re.search(r"SSH-[\d.]+-([\w.]+?)(?:_| )?([\d.p]+)?(?:\s*(.+))?", banner)
        if ssh_match:
            result["service"] = ssh_match.group(1)
            result["version"] = ssh_match.group(2) or ""
            os_info = ssh_match.group(3) or ""
            if "Ubuntu" in os_info:
                result["os_hint"] = "Linux (Ubuntu)"
            elif "Debian" in os_info:
                result["os_hint"] = "Linux (Debian)"
            return result

        # HTTP Server headers
        server_match = re.search(r"Server:\s*(.+?)(?:\r?\n|$)", banner, re.IGNORECASE)
        if server_match:
            server = server_match.group(1).strip()
            result["service"] = server
            if "Apache" in server:
                ver = re.search(r"Apache/([\d.]+)", server)
                result["version"] = ver.group(1) if ver else ""
                result["os_hint"] = "Linux" if "Unix" in server or "Ubuntu" in server else ""
            elif "nginx" in server:
                ver = re.search(r"nginx/([\d.]+)", server)
                result["version"] = ver.group(1) if ver else ""
            elif "IIS" in server:
                ver = re.search(r"IIS/([\d.]+)", server)
                result["version"] = ver.group(1) if ver else ""
                result["os_hint"] = "Windows Server"
            return result

        # FTP banners: "220 ProFTPD 1.3.5 Server ready."
        ftp_match = re.search(r"220[- ](.+)", banner)
        if ftp_match and port == 21:
            result["service"] = "FTP"
            result["version"] = ftp_match.group(1).strip()
            return result

        # SMTP banners: "220 mail.example.com ESMTP Postfix"
        smtp_match = re.search(r"220[- ](.+)", banner)
        if smtp_match and port in (25, 465, 587):
            result["service"] = "SMTP"
            result["version"] = smtp_match.group(1).strip()
            return result

        # MySQL: Version in greeting
        if port == 3306 and banner:
            ver_match = re.search(r"([\d.]+)", banner)
            if ver_match:
                result["service"] = "MySQL"
                result["version"] = ver_match.group(1)
            return result

        # Generic: use first line as service info
        first_line = banner.split("\n")[0].strip()
        if first_line:
            result["service"] = first_line[:100]

        return result

    def _os_fingerprint_heuristic(self, result: dict) -> str:
        """
        Perform OS fingerprinting using heuristic analysis of banner and service information.

        This method analyzes service banners, service names, descriptions, and other characteristics
        to make educated guesses about the underlying operating system.

        Args:
            result: Service detection result dictionary

        Returns:
            String hint about the detected OS, or empty string if undetermined
        """
        banner = result.get("banner", "").lower()
        service = result.get("service", "").lower()
        description = result.get("_description", "").lower()
        version = result.get("version", "").lower()
        port = result.get("port", 0)

        # Debug print to see what we're working with
        # print(f"DEBUG OS Fingerprinting: port={port}, service='{service}', description='{description}', banner='{banner[:50]}...'")

        # Service-specific OS detection (check these first)
        if "apache" in service:
            if "ubuntu" in banner or "debian" in banner:
                return "Linux (Ubuntu/Debian) with Apache"
            elif "centos" in banner or "red hat" in banner:
                return "Linux (RHEL/CentOS) with Apache"
            elif "windows" in banner:
                return "Windows with Apache"
            else:
                return "Linux/Unix with Apache"
        elif "nginx" in service:
            if "ubuntu" in banner or "debian" in banner:
                return "Linux (Ubuntu/Debian) with nginx"
            elif "centos" in banner:
                return "Linux (CentOS) with nginx"
            elif "windows" in banner:
                return "Windows with nginx"
            else:
                return "Linux/Unix with nginx"
        elif "mysql" in service:
            if "ubuntu" in banner or "debian" in banner:
                return "Linux (Ubuntu/Debian) with MySQL"
            elif "centos" in banner or "red hat" in banner:
                return "Linux (RHEL/CentOS) with MySQL"
            elif "windows" in banner:
                return "Windows with MySQL"
            else:
                return "Linux/Unix with MySQL"
        elif "ssh" in service:
            if "openbsd" in banner:
                return "OpenBSD with OpenSSH"
            elif "freebsd" in banner:
                return "FreeBSD with OpenSSH"
            elif "ubuntu" in banner:
                return "Linux (Ubuntu) with OpenSSH"
            elif "debian" in banner:
                return "Linux (Debian) with OpenSSH"
            else:
                return "Unix-like with SSH"
        elif "iis" in service or "http" in service:
            # IIS detection
            if "windows" in banner or "iis" in banner:
                return "Windows with IIS"
            elif "10.0" in version:
                return "Windows Server 2016/Windows 10 with IIS"
            else:
                return "Windows with IIS"

        # Heuristic-based OS detection from banners/descriptions
        combined_text = f"{banner} {description}"

        if "windows" in combined_text or "microsoft" in combined_text or "iis" in service:
            # Check for specific Windows versions
            if "2000" in version or "5.0" in version:
                return "Windows 2000"
            elif "2003" in version or "5.2" in version:
                return "Windows Server 2003"
            elif "vista" in version or "6.0" in version:
                return "Windows Vista"
            elif "2008" in version or "6.1" in version:
                return "Windows Server 2008"
            elif "7" in version or "6.1" in version:
                return "Windows 7"
            elif "2012" in version or "6.2" in version:
                return "Windows Server 2012"
            elif "8" in version or "6.3" in version:
                return "Windows 8"
            elif "2016" in version or "10.0" in version:
                return "Windows Server 2016/Windows 10"
            elif "2019" in version or "10.0" in version:
                return "Windows Server 2019"
            elif "2022" in version:
                return "Windows Server 2022"
            else:
                return "Windows"

        elif "linux" in combined_text or "ubuntu" in combined_text or "debian" in combined_text or "centos" in combined_text:
            if "ubuntu" in combined_text:
                return "Linux (Ubuntu)"
            elif "debian" in combined_text:
                return "Linux (Debian)"
            elif "centos" in combined_text:
                return "Linux (CentOS)"
            else:
                return "Linux"

        elif "freebsd" in combined_text:
            return "FreeBSD"
        elif "openbsd" in combined_text:
            return "OpenBSD"
        elif "netbsd" in combined_text:
            return "NetBSD"
        elif "cisco" in combined_text or "ios" in combined_text:
            return "Cisco IOS"

        # Port-based and service-based OS fingerprinting for common Windows services
        # These are strong indicators of Windows when specific port/service combinations are found
        if port in [135, 139, 445, 3389, 5985, 5986, 9389, 47001] or \
           service in ["ms-rpc", "smb", "rdp", "netbios-ss"] or \
           "microsoft" in combined_text or "microsoft" in description:
            # These are very characteristic Windows ports/services
            if port == 445 or "smb" in service or "smb" in description:
                return "Windows (SMB service)"
            elif port == 3389 or "rdp" in service or "rdp" in description:
                return "Windows (RDP service)"
            elif port == 135 or "ms-rpc" in service or "ms-rpc" in description:
                return "Windows (MS-RPC service)"
            elif port in [139] or "netbios" in service or "netbios" in description:
                return "Windows (NetBIOS service)"
            else:
                return "Windows"

        # If we have Windows-typical services but no banner/description, still suggest Windows
        if service in ["ms-rpc", "smb", "rdp"] or "microsoft" in service:
            return "Windows"

        # If we have Linux/Unix typical services but no specific banner/description info
        if service in ["ssh", "http"] and not banner and not description:
            # Could be either, but Linux is more common for these in default configs
            return "Linux/Unix (likely)"

        return ""

    def detect_services(self, ip: str, open_ports: list) -> list:
        """
        Detect services on all open ports of a host.

        Args:
            ip: Target IP address
            open_ports: List of open port dictionaries from port scanner

        Returns:
            list: List of service detection results
        """
        results = []
        port_numbers = [p["port"] if isinstance(p, dict) else p for p in open_ports]

        print(f"\n[*] Service detection on {ip} ({len(port_numbers)} ports)...")

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self.grab_banner, ip, port, port_info): port
                for port, port_info in zip(port_numbers, open_ports)
            }

            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                    if result["banner"] and not result["banner"].startswith("Error"):
                        svc = result.get("service", "Unknown")
                        ver = result.get("version", "")
                        ssl_flag = " [SSL]" if result.get("ssl") else ""
                        print(f"  [+] {result['port']:>5}/tcp  {svc} {ver}{ssl_flag}")
                        for note in result.get("security_notes", []):
                            print(f"       {note}")
                except Exception:
                    pass

        results.sort(key=lambda x: x["port"])
        print(f"[*] Service detection complete: {len(results)} services analyzed")
        return results
