"""
IDS/IPS Threat Intelligence Enrichment Engine
=============================================

Provides threat intelligence enrichment by checking IP addresses
against known malicious IP lists, domains, and other threat feeds.
"""

import ipaddress
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta


class ThreatIntel:
    """
    Threat intelligence enrichment engine.

    Maintains lists of known malicious IPs, domains, and provides
    reputation scoring for network entities.
    """

    def __init__(self) -> None:
        """Initialize threat intelligence with known threat feeds."""
        # Known malicious IP ranges (in CIDR notation) - examples
        self.malicious_ips: List[str] = [
            "103.11.22.44/32",   # Known C2 server
            "45.2.3.11/32",      # Known malware distributor
            "198.51.100.23/32",  # Known phishing site
            "203.0.113.42/32",   # Known botnet C2
        ]

        # Known malicious domains
        self.malicious_domains: List[str] = [
            "evil-c2.tk",
            "malware.xyz",
            "data-exfil.top",
            "phishing-bank.ml",
            "update.malware.xyz",
        ]

        # Compile IP networks for efficient lookup
        self._malicious_networks: List[ipaddress.IPv4Network] = []
        for ip_range in self.malicious_ips:
            try:
                network = ipaddress.IPv4Network(ip_range)
                self._malicious_networks.append(network)
            except ValueError:
                # Skip invalid CIDR notation
                pass

        # Statistics
        self.stats: Dict[str, int] = {
            "ips_checked": 0,
            "threats_detected": 0,
            "domain_threats": 0,
        }

        # Cache for recent lookups (to avoid repeated lookups)
        self._cache: Dict[str, Tuple[bool, datetime]] = {}
        self._cache_timeout = timedelta(minutes=5)

    def check_ip(self, ip_address: str) -> Tuple[bool, Optional[str]]:
        """
        Check if an IP address is known to be malicious.

        Args:
            ip_address: IP address string to check

        Returns:
            Tuple of (is_malicious, threat_type)
            is_malicious: True if IP is found in threat intelligence
            threat_type: Description of threat type or None if not malicious
        """
        self.stats["ips_checked"] += 1

        # Check cache first
        now = datetime.now()
        if ip_address in self._cache:
            is_malicious, timestamp = self._cache[ip_address]
            if now - timestamp < self._cache_timeout:
                return is_malicious, "Cached threat intelligence result"

        try:
            ip_obj = ipaddress.IPv4Address(ip_address)
        except ValueError:
            # Not a valid IPv4 address
            return False, None

        # Check against known malicious networks
        is_malicious = any(ip_obj in network for network in self._malicious_networks)

        if is_malicious:
            self.stats["threats_detected"] += 1
            threat_type = "Known malicious IP address"
            self._cache[ip_address] = (True, now)
            return True, threat_type

        # If not found in IP lists, check if it's in any suspicious ranges
        # For simplicity, we'll also check if it's from certain high-risk countries
        # (This would require a GeoIP database in a real implementation)

        # Cache negative result too
        self._cache[ip_address] = (False, now)
        return False, None

    def check_domain(self, domain: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a domain is known to be malicious.

        Args:
            domain: Domain name to check

        Returns:
            Tuple of (is_malicious, threat_type)
        """
        # Normalize domain
        domain_lower = domain.lower().strip()

        # Remove common prefixes
        if domain_lower.startswith("www."):
            domain_lower = domain_lower[4:]

        # Check against known malicious domains
        is_malicious = any(mal_domain in domain_lower for mal_domain in self.malicious_domains)

        if is_malicious:
            self.stats["domain_threats"] += 1
            threat_type = "Known malicious domain"
            return True, threat_type

        return False, None

    def get_stats(self) -> Dict[str, int]:
        """Get threat intelligence statistics."""
        return self.stats.copy()

    def reset_stats(self) -> None:
        """Reset statistics counters."""
        self.stats = {
            "ips_checked": 0,
            "threats_detected": 0,
            "domain_threats": 0,
        }


# Global threat intelligence instance
threat_intel = ThreatIntel()