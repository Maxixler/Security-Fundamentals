"""
SIEM Correlation Engine
Analyzes streams of normalized logs, applies rules to detect complex attacks.
For example: Brute-Force detection.
"""
from collections import defaultdict
import time
from .threat_intel import ThreatIntelFeed

class CorrelationEngine:
    def __init__(self):
        self.ti_feed = ThreatIntelFeed()
        # Track failed logins: {ip: {timestamp: count}}
        self.failed_logins = defaultdict(list)
        self.incidents = []

    def analyze(self, log_event):
        """
        Process a single normalized log and generate alerts if rules match.
        """
        src_ip = log_event.get("src_ip", "")
        if not src_ip: return None
        
        # 1. Enrichment: Add Threat Intelligence
        ti_data = self.ti_feed.check_ip(src_ip)
        log_event["ti_enrichment"] = ti_data
        
        # Immediate High-Severity Alert for known bad IPs
        if not ti_data["safe"]:
            self.create_incident("High", f"Traffic from Malicious IP ({ti_data['tags']})", log_event)

        # 2. Rule: Brute Force Detection (More than 3 failed logins in a short window)
        if log_event.get("event_type") == "failed_logon":
            now = time.time()
            self.failed_logins[src_ip].append(now)
            
            # Clean up old tracking (older than 60 seconds)
            self.failed_logins[src_ip] = [t for t in self.failed_logins[src_ip] if now - t < 60]
            
            if len(self.failed_logins[src_ip]) >= 3:
                self.create_incident("Critical", f"Brute Force Attack Detected against AD from {src_ip}", log_event)
                # clear tracker to avoid alert spamming
                self.failed_logins[src_ip] = []

        # 3. Rule: Port Scan / Mass Drop Check
        if log_event.get("source") == "firewall" and log_event.get("action") == "DENY":
            # Real SIEM would group by time window. We just pass it as Medium for dashboard vis.
            # Only trigger medium if it's hitting specific critical ports (RDP, SSH)
            if log_event.get("dst_port") in ["22", "3389", "502"]:
                self.create_incident("Medium", f"Connection blocked to critical port {log_event.get('dst_port')}", log_event)

    def create_incident(self, severity, description, trigger_log):
        incident = {
            "severity": severity,
            "description": description,
            "src_ip": trigger_log.get("src_ip"),
            "target": trigger_log.get("dst_ip") or trigger_log.get("username", "Enterprise DB"),
            "log_source": trigger_log.get("source"),
            "country": trigger_log.get("ti_enrichment", {}).get("country", "UNKNOWN")
        }
        self.incidents.append(incident)
        print(f"[{severity}] INCIDENT: {description}")

    def get_new_incidents(self):
        new_incs = self.incidents.copy()
        self.incidents.clear()
        return new_incs
