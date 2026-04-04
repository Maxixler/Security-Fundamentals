import threading
import time
import random
from typing import Callable

class MockPacketSniffer:
    """Ağ arayüzünü izlemek yerine IDS sistemine sahte/simüle TCP/UDP paketleri basar."""
    
    def __init__(self):
        self.running = False
        self._thread = None
        
        self.benign_payloads = [
            "GET /index.html HTTP/1.1",
            "POST /login HTTP/1.1 (Valid Data)",
            "GET /images/logo.png HTTP/1.1"
        ]
        self.malicious_payloads = [
            "GET /search?q=1' OR 1=1-- HTTP/1.1",
            "GET /review?data=<script>alert(document.cookie)</script> HTTP/1.1",
            "UDP payload: NMAP scan probe string",
            "GET /../../../../etc/passwd HTTP/1.1"
        ]
        
    def start(self, callback: Callable[[dict], None]):
        self.running = True
        self._thread = threading.Thread(target=self._sniff_loop, args=(callback,), daemon=True)
        self._thread.start()
        
    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=1.0)
            
    def _sniff_loop(self, callback):
        while self.running:
            time.sleep(random.uniform(0.5, 2.0))
            
            is_malicious = random.random() > 0.85 # %15 ihtimalle zararlı trafik
            payload = random.choice(self.malicious_payloads) if is_malicious else random.choice(self.benign_payloads)
            
            # Simple heuristic matching
            proto = "UDP" if "UDP payload" in payload or "NMAP" in payload else "TCP"
            src_ip = f"{random.randint(10, 200)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            
            packet = {
                "timestamp": time.time(),
                "src_ip": src_ip,
                "dst_ip": "10.0.0.5",
                "dst_port": 80,
                "protocol": proto,
                "payload": payload
            }
            
            callback(packet)
            
    def inject_packet(self, callback: Callable[[dict], None], src_ip: str, payload: str, proto: str = "TCP"):
        """Test veya müdahale amaçlı özel paket basmak için kullanılır."""
        packet = {
            "timestamp": time.time(),
            "src_ip": src_ip,
            "dst_ip": "10.0.0.5",
            "dst_port": 80,
            "protocol": proto,
            "payload": payload
        }
        callback(packet)
