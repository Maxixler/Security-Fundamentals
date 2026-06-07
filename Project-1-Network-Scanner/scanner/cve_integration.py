"""
CVE Integration Module — Vulnerability Intelligence for Network Scanner
=======================================================================

Integrates CVE detection capabilities from Project 4 into Project 1's
service detection workflow to provide vulnerability intelligence.
"""

import sys
import os
# Add the Project-4-Vulnerability-Scanner directory to the path
project4_path = os.path.join(os.path.dirname(__file__), '..', '..', 'Project-4-Vulnerability-Scanner')
sys.path.insert(0, project4_path)

# Also add the scanner subdirectory
scanner_path = os.path.join(project4_path, 'scanner')
sys.path.insert(0, scanner_path)

from cve_engine import CVEEngine
from typing import List, Dict, Any


class CVEIntegrator:
    """
    Integrates CVE scanning with service detection results.

    This module bridges Project 1's network scanning with Project 4's CVE engine
    to provide vulnerability intelligence on discovered services.
    """

    def __init__(self) -> None:
        self.cve_engine = CVEEngine()
        # Cache for CVE lookups to avoid redundant queries
        self._cve_cache: Dict[str, List[Dict[str, Any]]] = {}

    def enrich_services_with_cve(self, services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enrich service detection results with CVE vulnerability information.

        Args:
            services: List of service detection results from ServiceDetector

        Returns:
            List of services enriched with CVE information
        """
        enriched_services = []

        for service in services:
            # Create a copy to avoid modifying the original
            enriched_service = service.copy()

            # Extract service name and version for CVE lookup
            service_name = service.get("service", "").strip()
            version = service.get("version", "").strip()

            # Skip if we don't have meaningful service information
            if not service_name or service_name in ["Unknown", ""]:
                enriched_service["cves"] = []
                enriched_service["cve_summary"] = {
                    "total": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0
                }
                enriched_services.append(enriched_service)
                continue

            # Create lookup key for caching
            lookup_key = f"{service_name.lower()}:{version.lower()}"

            # Check cache first
            if lookup_key in self._cve_cache:
                cves = self._cve_cache[lookup_key]
            else:
                # Query the CVE engine
                cves = self.cve_engine.check_version(f"{service_name} {version}".strip())
                self._cve_cache[lookup_key] = cves

            # Add CVE information to the service
            enriched_service["cves"] = cves

            # Calculate CVE summary statistics
            cve_summary = self._calculate_cve_summary(cves)
            enriched_service["cve_summary"] = cve_summary

            enriched_services.append(enriched_service)

        return enriched_services

    def _calculate_cve_summary(self, cves: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Calculate summary statistics for a list of CVEs.

        Args:
            cves: List of CVE dictionaries

        Returns:
            Dictionary with CVE counts by severity
        """
        summary = {
            "total": len(cves),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }

        for cve in cves:
            cvss = cve.get("cvss", 0.0)
            if cvss >= 9.0:
                summary["critical"] += 1
            elif cvss >= 7.0:
                summary["high"] += 1
            elif cvss >= 4.0:
                summary["medium"] += 1
            else:
                summary["low"] += 1

        return summary

    def get_vulnerability_highlights(self, services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Extract the most critical vulnerability information for reporting.

        Args:
            services: List of enriched service dictionaries

        Returns:
            List of vulnerability highlights sorted by severity
        """
        highlights = []

        for service in services:
            service_name = service.get("service", "Unknown")
            port = service.get("port", 0)
            cves = service.get("cves", [])

            for cve in cves:
                highlights.append({
                    "ip": service.get("ip", ""),
                    "port": port,
                    "service": service_name,
                    "cve_id": cve.get("cve_id", ""),
                    "cvss": cve.get("cvss", 0.0),
                    "severity": cve.get("severity", "Unknown"),
                    "description": cve.get("description", "")[:100] + "..." if len(cve.get("description", "")) > 100 else cve.get("description", ""),
                    "exploit_available": cve.get("exploit_available", False)
                })

        # Sort by CVSS score descending (most critical first)
        highlights.sort(key=lambda x: x["cvss"], reverse=True)
        return highlights


# Example usage and testing
if __name__ == "__main__":
    # Test with sample service data
    test_services = [
        {
            "ip": "192.168.1.10",
            "port": 22,
            "service": "OpenSSH",
            "version": "7.2",
            "banner": "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10"
        },
        {
            "ip": "192.168.1.10",
            "port": 80,
            "service": "Apache",
            "version": "2.4.49",
            "banner": "Apache/2.4.49 (Unix)"
        },
        {
            "ip": "192.168.1.10",
            "port": 3306,
            "service": "MySQL",
            "version": "5.7.38",
            "banner": "5.7.38-0ubuntu0.18.04.1"
        }
    ]

    integrator = CVEIntegrator()
    enriched = integrator.enrich_services_with_cve(test_services)

    print("CVE-Enhanced Service Detection Results:")
    print("=" * 50)

    for service in enriched:
        print(f"\n{service['service']} {service['version']} (Port {service['port']}):")
        print(f"  CVEs Found: {service['cve_summary']['total']} "
              f"(Critical: {service['cve_summary']['critical']}, "
              f"High: {service['cve_summary']['high']}, "
              f"Medium: {service['cve_summary']['medium']}, "
              f"Low: {service['cve_summary']['low']})")

        if service["cves"]:
            for cve in service["cves"][:3]:  # Show first 3 CVEs
                exploit_tag = " [EXPLOIT]" if cve.get("exploit_available") else ""
                print(f"  - {cve['cve_id']} (CVSS: {cve['cvss']}) {exploit_tag}")
                print(f"    {cve['description'][:80]}...")

    print("\n" + "=" * 50)
    print("Vulnerability Highlights (Sorted by Severity):")
    highlights = integrator.get_vulnerability_highlights(enriched)
    for highlight in highlights[:5]:  # Show top 5
        print(f"{highlight['ip']}:{highlight['port']} {highlight['service']} - "
              f"{highlight['cve_id']} (CVSS: {highlight['cvss']}) [{highlight['severity']}]")