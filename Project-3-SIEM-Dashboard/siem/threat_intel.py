"""
Threat Intelligence Simulator
Looks up IP addresses against known malicious databases or feeds.
Returns threat scores and threat types.
"""

class ThreatIntelFeed:
    def __init__(self):
        # Simulated blacklist (e.g., from an API like AbuseIPDB, AlienVault OTX)
        self.malicious_ips = {
            "185.15.2.14": {"threat_score": 95, "type": "botnet", "country": "RU"},
            "45.2.3.11": {"threat_score": 88, "type": "brute_force", "country": "CN"},
            "103.11.22.44": {"threat_score": 75, "type": "tor_exit", "country": "NL"},
            "192.168.1.99": {"threat_score": 60, "type": "internal_compromised", "country": "LOCAL"}
        }

    def check_ip(self, ip_address):
        """
        Query the IP against the threat intelligence database.
        """
        # Exclude loopback and standard private segments in a real app,
        # but here we might have a compromised internal IP.
        if ip_address in self.malicious_ips:
            data = self.malicious_ips[ip_address]
            return {
                "safe": False,
                "score": data["threat_score"],
                "tags": data["type"],
                "country": data["country"]
            }
        
        return {
            "safe": True,
            "score": 0,
            "tags": "clean",
            "country": "UNKNOWN"
        }

if __name__ == "__main__":
    ti = ThreatIntelFeed()
    print("Checking 8.8.8.8:", ti.check_ip("8.8.8.8"))
    print("Checking 185.15.2.14:", ti.check_ip("185.15.2.14"))
