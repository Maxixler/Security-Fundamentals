import time
import random
from datetime import datetime
from .base_collector import BaseCollector

class AuthLogCollector(BaseCollector):
    """Windows AD veya Linux Auth loglarını simüle eder."""
    
    def __init__(self):
        super().__init__(name="auth_log")
        self.users = ["admin", "root", "dev1", "jsmith", "guest"]
        self.ips = ["192.168.1.55", "10.0.0.99", "8.8.8.8", "172.16.1.1"]

    def _run_loop(self):
        while self.running:
            time.sleep(random.uniform(2.0, 5.0)) 
            
            user = random.choice(self.users)
            ip = random.choice(self.ips)
            is_success = random.random() > 0.3  # %70 ihtimalle başarılı
            
            action = "LOGIN_SUCCESS" if is_success else "LOGIN_FAILED"
            
            raw_log = {
                "source": "auth_event",
                "timestamp": datetime.now().isoformat(),
                "user": user,
                "src_ip": ip,
                "action": action,
                "description": f"Authentication {'succeeded' if is_success else 'failed'} for user {user} from {ip}"
            }
            
            if self.on_log_received:
                self.on_log_received(raw_log)

    def inject_brute_force(self, ip, user, attempts=5):
        """Test amaçlı üst üste log basan injection fonksiyonu."""
        for _ in range(attempts):
            raw_log = {
                "source": "auth_event",
                "timestamp": datetime.now().isoformat(),
                "user": user,
                "src_ip": ip,
                "action": "LOGIN_FAILED",
                "description": f"Authentication failed for user {user} from {ip}"
            }
            if self.on_log_received:
                self.on_log_received(raw_log)
            time.sleep(0.1)
