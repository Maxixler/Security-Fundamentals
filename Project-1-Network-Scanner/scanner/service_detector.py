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

Security Implications:
- Detailed banners help attackers identify vulnerable versions
- Best practice: Minimize banner information (banner hardening)
- In Tüpraş, knowing exact service versions helps the security
  team prioritize patching and identify unauthorized services
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

    def grab_banner(self, ip: str, port: int) -> dict:
        """
        Attempt to grab the service banner from an open port.
        
        Process:
        1. Connect to the target port
        2. Some services send a banner immediately (SSH, FTP, SMTP)
        3. For others, send a protocol-specific probe (HTTP GET, etc.)
        4. Read and parse the response
        5. Extract software name, version, and other details
        """
        result = {
            "ip": ip,
            "port": port,
            "protocol": self.PORT_PROTOCOL.get(port, "unknown"),
            "banner": "",
            "service": "",
            "version": "",
            "os_hint": "",
            "ssl": False,
            "ssl_info": {},
            "security_notes": [],
            "timestamp": datetime.now().isoformat(),
        }

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
                executor.submit(self.grab_banner, ip, port): port
                for port in port_numbers
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
