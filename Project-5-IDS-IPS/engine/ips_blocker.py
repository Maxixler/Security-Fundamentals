import time
from typing import List, Dict, Any

class IPSBlocker:
    """Zararlı aktivite tespiti sonrası ilgili kaynağı kara listeye alır.
    Bu modül TTL (Time-To-Live) destekleyerek performans optimizasyonu ve ban-kaldırma sağlar."""

    def __init__(self, ban_duration_sec: int = 15) -> None:
        self.banned_ips: Dict[str, float] = {}
        self.ban_duration: int = ban_duration_sec

    def block_ip(self, ip: str) -> None:
        """IP adresini geçici süreyle yasaklar."""
        self.banned_ips[ip] = time.time() + self.ban_duration

    def is_blocked(self, ip: str) -> bool:
        """IP'nin süresi devam eden bir ban listesinde olup olmadığını O(1) maliyetle denetler."""
        if ip in self.banned_ips:
            if time.time() < self.banned_ips[ip]:
                return True
            else:
                del self.banned_ips[ip]
        return False

    def get_active_bans(self) -> List[str]:
        """Günü geçmiş banları temizleyip aktif listeyi döner."""
        now = time.time()
        active: List[str] = []
        for ip, exp in list(self.banned_ips.items()):
            if now < exp:
                active.append(ip)
            else:
                del self.banned_ips[ip]
        return active
