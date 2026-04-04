"""
Log Aggregator & Normalization Module
Collects logs from different sources (Firewall, AD, Web Server)
and normalizes them into a common JSON structure.
"""
import json
import time
from datetime import datetime

class LogAggregator:
    def __init__(self):
        self.logs = []
    
    def parse_firewall_log(self, raw_log):
        """Parse raw syslog-like firewall formats."""
        # Example format: "2026-04-05 10:00:01 [FIREWALL] DENY SRC=192.168.1.5 DST=10.0.0.5 DPORT=22"
        try:
            parts = raw_log.split(" ")
            timestamp = " ".join(parts[0:2])
            action = parts[3]
            src = [p.split('=')[1] for p in parts if p.startswith('SRC=')][0]
            dst = [p.split('=')[1] for p in parts if p.startswith('DST=')][0]
            port = [p.split('=')[1] for p in parts if p.startswith('DPORT=')][0]

            return {
                "timestamp": timestamp,
                "source": "firewall",
                "event_type": "network_traffic",
                "action": action,
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": port,
                "raw_log": raw_log
            }
        except Exception as e:
            return None

    def parse_ad_log(self, raw_json):
        """Parse Windows Event Log (AD) JSON output."""
        try:
            data = json.loads(raw_json)
            # EventID 4625 is Failed Logon
            event_type = "failed_logon" if data.get("EventID") == 4625 else "successful_logon"
            return {
                "timestamp": data.get("TimeCreated"),
                "source": "active_directory",
                "event_type": event_type,
                "username": data.get("TargetUserName"),
                "src_ip": data.get("IpAddress"),
                "action": "FAILURE" if event_type == "failed_logon" else "SUCCESS",
                "raw_log": raw_json
            }
        except Exception:
            return None

    def ingest_log(self, log_type, raw_data):
        """Entry point for incoming logs."""
        normalized = None
        if log_type == "firewall":
            normalized = self.parse_firewall_log(raw_data)
        elif log_type == "active_directory":
            normalized = self.parse_ad_log(raw_data)
            
        if normalized:
            self.logs.append(normalized)
            return normalized
        return None

if __name__ == "__main__":
    agg = LogAggregator()
    # Test firewall log
    fw_log = "2026-05-01 12:00:00 [FIREWALL] DENY SRC=8.8.8.8 DST=10.0.0.10 DPORT=3389"
    print(agg.ingest_log("firewall", fw_log))
    
    # Test AD log
    ad_log = '{"EventID": 4625, "TimeCreated": "2026-05-01 12:01:00", "TargetUserName": "admin", "IpAddress": "8.8.8.8"}'
    print(agg.ingest_log("active_directory", ad_log))
