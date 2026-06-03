"""
Threat Intelligence Feed
=========================
Simulates integration with enterprise threat intelligence platforms
(AbuseIPDB, AlienVault OTX, VirusTotal, MISP) to provide real-time
IP reputation scoring, GeoIP enrichment, and IOC matching.

Features:
    - Multi-feed IP reputation scoring (0-100 threat score)
    - GeoIP country/region mapping
    - Known threat actor attribution
    - IOC (Indicators of Compromise) matching
    - Threat category classification (botnet, C2, tor_exit, scanner, brute_force)
    - Historical threat data caching

Architecture:
    IP Address → Feed Lookup → Score Aggregation → Enrichment Response
"""

from typing import Dict, Any, Optional, List
from datetime import datetime


# ─── Simulated Threat Intelligence Database ─────────────────────────────
# In production, this would query APIs like AbuseIPDB, OTX, VirusTotal
_MALICIOUS_IPS: Dict[str, Dict[str, Any]] = {
    "185.15.2.14": {
        "threat_score": 95,
        "threat_type": "botnet_c2",
        "country": "RU",
        "region": "Moscow",
        "isp": "Bulletproof Hosting Ltd.",
        "actor": "APT28/Fancy Bear",
        "first_seen": "2024-01-15",
        "last_seen": "2026-04-01",
        "tags": ["botnet", "c2", "malware_distribution"],
        "references": ["US-CERT TA18-106A", "MITRE G0007"],
    },
    "45.2.3.11": {
        "threat_score": 88,
        "threat_type": "brute_force",
        "country": "CN",
        "region": "Beijing",
        "isp": "China Telecom",
        "actor": "Unknown Threat Actor",
        "first_seen": "2025-06-20",
        "last_seen": "2026-03-28",
        "tags": ["brute_force", "credential_stuffing", "ssh_scanner"],
        "references": ["AbuseIPDB Report #442211"],
    },
    "103.11.22.44": {
        "threat_score": 75,
        "threat_type": "tor_exit_node",
        "country": "NL",
        "region": "Amsterdam",
        "isp": "Leaseweb B.V.",
        "actor": "Anonymized Traffic",
        "first_seen": "2025-09-01",
        "last_seen": "2026-04-05",
        "tags": ["tor_exit", "anonymizer", "potential_exfiltration"],
        "references": ["TorProject Exit List"],
    },
    "192.168.1.99": {
        "threat_score": 60,
        "threat_type": "internal_compromised",
        "country": "LOCAL",
        "region": "Internal Network",
        "isp": "Corporate LAN",
        "actor": "Compromised Endpoint",
        "first_seen": "2026-04-01",
        "last_seen": "2026-04-05",
        "tags": ["internal_threat", "lateral_movement", "beaconing"],
        "references": ["Internal SOC Alert #2026-0401"],
    },
    "91.205.174.26": {
        "threat_score": 92,
        "threat_type": "ransomware_c2",
        "country": "UA",
        "region": "Kyiv",
        "isp": "Hosting Solutions Int.",
        "actor": "LockBit 3.0",
        "first_seen": "2025-11-10",
        "last_seen": "2026-03-30",
        "tags": ["ransomware", "c2", "data_encryption"],
        "references": ["CISA AA23-165A"],
    },
    "198.51.100.23": {
        "threat_score": 70,
        "threat_type": "scanner",
        "country": "US",
        "region": "Virginia",
        "isp": "Cloud Provider Inc.",
        "actor": "Automated Scanner",
        "first_seen": "2026-01-01",
        "last_seen": "2026-04-05",
        "tags": ["port_scanner", "vuln_scanner", "mass_scanning"],
        "references": ["Shodan/Censys Mass Scanner"],
    },
    "172.16.0.50": {
        "threat_score": 45,
        "threat_type": "policy_violation",
        "country": "LOCAL",
        "region": "Internal DMZ",
        "isp": "Corporate DMZ",
        "actor": "Policy Violator",
        "first_seen": "2026-04-03",
        "last_seen": "2026-04-05",
        "tags": ["unauthorized_access", "shadow_it", "policy_violation"],
        "references": ["Internal Policy Engine"],
    },
}

# ─── GeoIP Simulation Database ──────────────────────────────────────────
_GEOIP_DB: Dict[str, Dict[str, str]] = {
    "8.8.8.8":       {"country": "US", "region": "California", "isp": "Google LLC"},
    "1.1.1.1":       {"country": "US", "region": "California", "isp": "Cloudflare Inc."},
    "10.0.0.5":      {"country": "LOCAL", "region": "Internal", "isp": "Corporate LAN"},
    "10.0.0.50":     {"country": "LOCAL", "region": "Internal", "isp": "Corporate LAN"},
    "192.168.1.100": {"country": "LOCAL", "region": "Internal", "isp": "Corporate LAN"},
    "192.168.1.150": {"country": "LOCAL", "region": "Internal", "isp": "Corporate OT"},
}


class ThreatIntelFeed:
    """
    Central threat intelligence service for the SIEM engine.

    Provides real-time IP reputation scoring, GeoIP enrichment, and
    IOC matching against multiple simulated threat feeds.

    Attributes:
        lookup_count: Total number of IP lookups performed
        cache_hits: Number of lookups resolved from cache
    """

    def __init__(self) -> None:
        self.lookup_count: int = 0
        self.cache_hits: int = 0
        self._cache: Dict[str, Dict[str, Any]] = {}

    def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Query IP address against all threat intelligence feeds.

        Returns an enrichment result containing:
            - safe: Boolean indicating if the IP is clean
            - threat_score: 0-100 risk score
            - threat_type: Classification of the threat
            - country: GeoIP country code
            - region: GeoIP region
            - isp: Internet Service Provider
            - actor: Known threat actor attribution
            - tags: List of threat tags
            - references: External reference IDs

        Args:
            ip_address: IPv4 address string to look up

        Returns:
            Dict with threat intelligence enrichment data
        """
        self.lookup_count += 1

        # Check cache first
        if ip_address in self._cache:
            self.cache_hits += 1
            return self._cache[ip_address]

        # Check malicious IP database
        if ip_address in _MALICIOUS_IPS:
            data: Dict[str, Any] = _MALICIOUS_IPS[ip_address]
            result: Dict[str, Any] = {
                "safe": False,
                "threat_score": data["threat_score"],
                "threat_type": data["threat_type"],
                "country": data["country"],
                "region": data.get("region", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "actor": data.get("actor", "Unknown"),
                "tags": data.get("tags", []),
                "references": data.get("references", []),
                "first_seen": data.get("first_seen", ""),
                "last_seen": data.get("last_seen", ""),
            }
        else:
            # Clean IP — still enrich with GeoIP
            geo: Dict[str, str] = _GEOIP_DB.get(ip_address, {"country": "UNKNOWN", "region": "Unknown", "isp": "Unknown"})
            result: Dict[str, Any] = {
                "safe": True,
                "threat_score": 0,
                "threat_type": "clean",
                "country": geo["country"],
                "region": geo["region"],
                "isp": geo["isp"],
                "actor": "",
                "tags": [],
                "references": [],
                "first_seen": "",
                "last_seen": "",
            }

        # Cache the result
        self._cache[ip_address] = result
        return result

    def check_domain(self, domain: str) -> Dict[str, Any]:
        """
        Check a domain against known malicious domain lists.

        Args:
            domain: FQDN to check

        Returns:
            Dict with domain reputation data
        """
        # Simulated malicious domains
        malicious_domains: Dict[str, Dict[str, Any]] = {
            "evil-c2.tk": {"threat_score": 95, "type": "c2_domain", "actor": "APT28"},
            "phishing-bank.ml": {"threat_score": 90, "type": "phishing", "actor": "Unknown"},
            "crypto-miner.xyz": {"threat_score": 80, "type": "cryptojacking", "actor": "Unknown"},
            "data-exfil.top": {"threat_score": 85, "type": "exfiltration", "actor": "Unknown"},
        }

        for mal_domain, data in malicious_domains.items():
            if mal_domain in domain:
                return {"safe": False, **data}

        # Check for suspicious TLDs
        suspicious_tlds: List[str] = [".tk", ".ml", ".cf", ".xyz", ".top", ".buzz", ".pw"]
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                return {
                    "safe": False,
                    "threat_score": 40,
                    "type": "suspicious_tld",
                    "actor": "Unknown",
                }

        return {"safe": True, "threat_score": 0, "type": "clean", "actor": ""}

    def get_stats(self) -> Dict[str, int]:
        """Return threat intelligence lookup statistics."""
        return {
            "total_lookups": self.lookup_count,
            "cache_hits": self.cache_hits,
            "cache_size": len(self._cache),
            "known_malicious_ips": len(_MALICIOUS_IPS),
        }


# ─── Standalone Test ────────────────────────────────────────────────────
if __name__ == "__main__":
    ti = ThreatIntelFeed()

    test_ips = ["8.8.8.8", "185.15.2.14", "45.2.3.11", "91.205.174.26", "10.0.0.5"]
    for ip in test_ips:
        result = ti.check_ip(ip)
        status = "🔴 MALICIOUS" if not result["safe"] else "🟢 CLEAN"
        print(f"  {ip:20s} → {status} | Score: {result['threat_score']:3d} | "
              f"Country: {result['country']:5s} | Type: {result['threat_type']}")

    print(f"\n  Stats: {ti.get_stats()}")
