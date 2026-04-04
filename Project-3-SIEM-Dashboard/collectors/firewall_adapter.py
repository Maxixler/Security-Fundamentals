import time
import random
from datetime import datetime
from .base_collector import BaseCollector

class FirewallLogCollector(BaseCollector):
    """Sanal Firewall loglarını (ALLOW/DENY olayları) simüle eder."""
    
    def __init__(self):
        super().__init__(name="firewall_log")
        self.internal_ips = ["192.168.1.10", "192.168.1.20"]
        self.external_ips = ["8.8.8.8", "1.1.1.1", "104.28.14.3", "45.33.12.5"]
        self.ports = [80, 443, 22, 3389, 53]

    def _run_loop(self):
        while self.running:
            time.sleep(random.uniform(1.0, 4.0))
            
            src = random.choice(self.external_ips)
            dst = random.choice(self.internal_ips)
            port = random.choice(self.ports)
            
            action = "ALLOW" if port in [80, 443, 53] else "DENY"
            
            raw_log = {
                "source": "firewall",
                "timestamp": datetime.now().isoformat(),
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": port,
                "protocol": "TCP" if port != 53 else "UDP",
                "action": action,
                "msg": f"Traffic {action}"
            }
            
            if self.on_log_received:
                self.on_log_received(raw_log)
