import time
import random
from datetime import datetime
from .base_collector import BaseCollector

class SyslogCollector(BaseCollector):
    """Network cihazlarından (Router/Switch/Web Server vb.) gelen genel syslogları simüle eder."""
    
    def __init__(self):
        super().__init__(name="syslog")
        self.endpoints = ["192.168.1.10", "192.168.1.25", "10.0.0.5", "172.16.0.40"]
        self.messages = [
            "Connection accepted from client",
            "Configuration changed by admin",
            "Service restarted successfully",
            "Disk space usage above 80%",
            "NTP sync completed"
        ]
        self.severities = ["INFO", "WARNING", "ERR"]

    def _run_loop(self):
        while self.running:
            time.sleep(random.uniform(1.0, 3.0))  # 1-3 saniyede bir log gönder
            
            src_ip = random.choice(self.endpoints)
            severity = random.choice(self.severities)
            message = random.choice(self.messages)
            
            raw_log = {
                "source": "syslog",
                "timestamp": datetime.now().isoformat(),
                "host": src_ip,
                "app": "Linux-Kernel",
                "severity": severity,
                "msg": message
            }
            
            if self.on_log_received:
                self.on_log_received(raw_log)

    def inject_custom_log(self, src_ip, msg, severity="WARNING"):
        """Dışarıdan belirli bir log enjekte etmek (Test amaçlı, port scan vb.)"""
        raw_log = {
            "source": "syslog",
            "timestamp": datetime.now().isoformat(),
            "host": src_ip,
            "app": "Custom-Injector",
            "severity": severity,
            "msg": msg
        }
        if self.on_log_received:
            self.on_log_received(raw_log)
