from datetime import datetime
from collections import deque
from typing import List, Dict
import json

class Correlator:
    """
    Standardize edilmiş olayları zaman penceresi ve kurallara göre izler, 
    belirli pattern'ler oluştuğunda Alerter tetikler.
    """
    def __init__(self, alerter):
        self.alerter = alerter
        self.events = deque()
        self.rules = []

    def load_rules(self, filepath: str):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                self.rules = json.load(f)
        except Exception:
            self.rules = []

    def process_event(self, normalized_event: dict):
        self.events.append(normalized_event)
        self._trim_events()
        self._evaluate_rules()

    def _trim_events(self):
        """Deque sayesinde eski olaylar O(1) maliyetle sol uçtan çıkarılır."""
        now = datetime.now()
        while self.events:
            try:
                evt_time = datetime.fromisoformat(self.events[0]["timestamp"])
                if (now - evt_time).total_seconds() > 300:
                    self.events.popleft()
                else:
                    break
            except Exception:
                self.events.popleft()

    def _evaluate_rules(self):
        """Yüklü kuralları mevcut event listesi üzerinde değerlendirir."""
        if not self.rules:
            # Fallback hardcoded rules for demo
            self._check_brute_force()
            self._check_port_scan()
            return
            
        for rule in self.rules:
            if rule["type"] == "threshold":
                self._check_threshold_rule(rule)

    def _check_brute_force(self):
        # Fallback brute-force check: Same IP, 5 LOGIN_FAILED
        fails = [e for e in self.events if e.get("action") == "LOGIN_FAILED" and e.get("src_ip")]
        
        # Group by IP
        ip_counts = {}
        for f in fails:
            ip = f["src_ip"]
            ip_counts.setdefault(ip, []).append(f)
            
        for ip, evt_list in ip_counts.items():
            if len(evt_list) >= 5:
                # Check if already alerted recently
                recent_alerts = [a for a in self.alerter.alerts if a["rule_name"] == "Brute Force Attack" and ip in a["description"]]
                if not recent_alerts:
                    self.alerter.generate_alert(
                        rule_name="Brute Force Attack",
                        description=f"Multiple failed logins detected from {ip}",
                        severity="CRITICAL",
                        source_events=evt_list[-5:]
                    )

    def _check_port_scan(self):
        # Same source IP, multiple DENY actions in firewall
        denies = [e for e in self.events if e.get("action") == "DENY" and e.get("src_ip")]
        ip_counts = {}
        for d in denies:
            ip = d["src_ip"]
            ip_counts.setdefault(ip, []).append(d)
            
        for ip, evt_list in ip_counts.items():
            if len(evt_list) >= 10:
                recent_alerts = [a for a in self.alerter.alerts if a["rule_name"] == "Port Scan Detected" and ip in a["description"]]
                if not recent_alerts:
                    self.alerter.generate_alert(
                        rule_name="Port Scan Detected",
                        description=f"High frequency of blocked connections from {ip}",
                        severity="HIGH",
                        source_events=evt_list[-10:]
                    )

    def _check_threshold_rule(self, rule: dict):
        pass # To be implemented if dynamic JSON rules are robustly needed
