"""
Credential Scanner — Authenticated Service Checking
====================================================

Performs credential-based vulnerability checks on discovered services.
Uses default/common credentials to identify vulnerabilities requiring authentication.
"""

import asyncio
import logging
from typing import Dict, List, Any
from .service_detector import ServiceDetector
from .credential_manager import credential_manager, Credential

logger = logging.getLogger(__name__)

class CredentialScanner:
    """
    Scans services using credentials to detect vulnerabilities that require authentication.

    Note: This is a simulation for educational purposes. In a real implementation,
    this would attempt actual authentication to the services.
    """

    def __init__(self) -> None:
        self.service_detector = ServiceDetector()
        logger.debug("CredentialScanner initialized")

    async def scan_services(self, ip: str, services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Perform credential-based scanning on a list of discovered services.

        Args:
            ip: Target IP address
            services: List of service detection results from ServiceDetector

        Returns:
            List of credential scan results
        """
        credential_results = []

        for service in services:
            service_type = service.get("service", "").upper()
            port = service.get("port")

            # Skip if no credentials configured for this service type
            if not credential_manager.has_credentials(service_type):
                logger.debug(f"No credentials found for {service_type} on {ip}:{port}")
                continue

            # Retrieve credentials for this service type
            creds = credential_manager.get_credentials(service_type)
            logger.debug(f"Found {len(creds)} credentials for {service_type} on {ip}:{port}")

            # For each credential, attempt a simulated authenticated check
            for cred in creds:
                cred_result = await self._attempt_authenticated_check(ip, port, service_type, cred)
                if cred_result:
                    credential_results.append(cred_result)

        return credential_results

    async def _attempt_authenticated_check(self, ip: str, port: int, service_type: str, credential: Credential) -> Dict[str, Any]:
        """
        Simulate an authenticated check for a specific service and credential.

        Args:
            ip: Target IP address
            port: Target port
            service_type: Service protocol (SSH, FTP, HTTP, etc.)
            credential: Credential object to use

        Returns:
            Dictionary with scan result or None if check failed
        """
        # Simulate network delay
        await asyncio.sleep(0.1)

        result = {
            "ip": ip,
            "port": port,
            "service": service_type,
            "credential_used": f"{credential.username}:{'*' * len(credential.password)}",
            "authenticated": False,
            "vulnerabilities_found": [],
            "notes": "Credential checking simulation - would attempt auth in production"
        }

        # Simulate successful authentication for demonstration
        # In reality, this would depend on the actual credentials and service configuration
        if service_type == "SSH":
            # Simulate SSH authentication success for weak/default credentials
            if credential.username in ["root", "admin", "pi"] and credential.password in ["root", "admin", "password", "raspberry", ""]:
                result["authenticated"] = True
                result["vulnerabilities_found"] = [
                    {
                        "cve_id": "CVE-2023-SSH-DEFAULT-CRED",
                        "description": "SSH service accessible with default or weak credentials",
                        "severity": "Critical",
                        "details": f"Login successful with username: {credential.username}"
                    }
                ]
                result["notes"] = "Authenticated SSH scan completed - default/weak credentials accepted"

        elif service_type == "FTP":
            # Simulate FTP anonymous or weak credential success
            if credential.username in ["anonymous", "ftp"] or credential.username == credential.password:
                result["authenticated"] = True
                result["vulnerabilities_found"] = [
                    {
                        "cve_id": "CVE-2023-FTP-WEAK-CRED",
                        "description": "FTP service accessible with weak or default credentials",
                        "severity": "Medium",
                        "details": f"Login successful with username: {credential.username}"
                    }
                ]
                result["notes"] = "Authenticated FTP scan completed - weak/default credentials accepted"

        elif service_type in ["HTTP", "HTTPS"]:
            # Simulate web app login with weak credentials
            if credential.username in ["admin", "administrator", "user"] and len(credential.password) <= 8:
                result["authenticated"] = True
                result["vulnerabilities_found"] = [
                    {
                        "cve_id": "CVE-2023-WEB-WEAK-CRED",
                        "description": "Web application accessible with weak/default credentials",
                        "severity": "High",
                        "details": f"Login successful with username: {credential.username}"
                    }
                ]
                result["notes"] = "Authenticated HTTP scan completed - weak/default credentials accepted"

        elif service_type == "MySQL":
            # Simulate MySQL root access with weak/no password
            if credential.username == "root" and credential.password in ["", "root", "mysql"]:
                result["authenticated"] = True
                result["vulnerabilities_found"] = [
                    {
                        "cve_id": "CVE-2023-MYSQL-WEAK-ROOT",
                        "description": "MySQL root account accessible with weak or empty password",
                        "severity": "Critical",
                        "details": f"Login successful as root with password: '{credential.password}'"
                    }
                ]
                result["notes"] = "Authenticated MySQL scan completed - weak/empty root password accepted"

        elif service_type == "PostgreSQL":
            # Simulate PostgreSQL access with weak credentials
            if credential.username in ["postgres", "admin"] and credential.password in ["", "postgres", "admin", "password"]:
                result["authenticated"] = True
                result["vulnerabilities_found"] = [
                    {
                        "cve_id": "CVE-2023-PGSQL-WEAK-CRED",
                        "description": "PostgreSQL accessible with weak/default credentials",
                        "severity": "Critical",
                        "details": f"Login successful with username: {credential.username}"
                    }
                ]
                result["notes"] = "Authenticated PostgreSQL scan completed - weak/default credentials accepted"

        # Add more service types as needed...

        return result if result["authenticated"] else None


# Example usage and test
if __name__ == "__main__":
    import asyncio

    # Add some test credentials to the manager
    credential_manager.add_credential(Credential("root", "root", "SSH", "Default root credential"))
    credential_manager.add_credential(Credential("admin", "password", "HTTP", "Default web admin"))
    credential_manager.add_credential(Credential("anonymous", "", "FTP", "Anonymous FTP"))

    scanner = CredentialScanner()

    # Example service detection results (would normally come from ServiceDetector)
    test_services = [
        {"ip": "192.168.1.10", "port": 22, "service": "SSH", "banner": "SSH-2.0-OpenSSH_7.4"},
        {"ip": "192.168.1.10", "port": 80, "service": "HTTP", "banner": "Apache/2.4.41 (Ubuntu)"},
        {"ip": "192.168.1.10", "port": 21, "service": "FTP", "banner": "220 (vsFTPd 3.0.3)"},
    ]

    async def run_test():
        results = await scanner.scan_services("192.168.1.10", test_services)
        print("\nCredential Scan Results:")
        for result in results:
            print(f"  {result['ip']}:{result['port']} {result['service']} - Authenticated: {result['authenticated']}")
            if result["vulnerabilities_found"]:
                for vuln in result["vulnerabilities_found"]:
                    print(f"    VULN: {vuln['cve_id']} - {vuln['description']} ({vuln['severity']})")

    asyncio.run(run_test())