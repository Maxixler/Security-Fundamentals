import json
import os
import re

class SignatureMatcher:
    """Gelen paketleri (özellikle payload kısmını) bilinen saldırı imzaları ile (Snort mantığıyla) tarar."""
    
    def __init__(self, rules_path=None):
        if not rules_path:
            rules_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "signatures", "snort_rules.json")
        
        self.rules = []
        self._load_rules(rules_path)
        
    def _load_rules(self, path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw_rules = json.load(f)
                for rule in raw_rules:
                    content = rule.get("content", "")
                    rule["_regex"] = re.compile(re.escape(content), re.IGNORECASE)
                    self.rules.append(rule)
        except Exception as e:
            print(f"Error loading rules: {e}")
            
    def analyze_packet(self, packet: dict) -> list:
        """Paketi re.compile (önceden derlenmiş RegExp objeleri) ile yüksek performanslı arar."""
        matches = []
        payload = packet.get("payload", "")
        proto = packet.get("protocol", "TCP")
        
        for rule in self.rules:
            if rule.get("protocol") == proto and rule["_regex"].search(payload):
                matches.append(rule)
                
        return matches
