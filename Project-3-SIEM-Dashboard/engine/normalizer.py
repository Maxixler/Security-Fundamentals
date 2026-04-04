import uuid
from datetime import datetime

class Normalizer:
    """
    Farklı tiplerdeki raw log verilerini (syslog, auth, firewall)
    Common Event Format (CEF) benzeri standardize edilmiş bir sözlüğe dönüştürür.
    """
    
    @staticmethod
    def normalize(raw_log: dict) -> dict:
        source = raw_log.get("source", "unknown")
        
        normalized = {
            "event_id": str(uuid.uuid4()),
            "timestamp": raw_log.get("timestamp", datetime.now().isoformat()),
            "source_type": source,
            "src_ip": None,
            "dst_ip": None,
            "action": None,
            "severity": "INFO",
            "user": None,
            "msg": raw_log.get("msg", raw_log.get("description", ""))
        }

        if source == "syslog":
            normalized["src_ip"] = raw_log.get("host")
            normalized["severity"] = raw_log.get("severity", "INFO")
            
        elif source == "auth_event":
            normalized["src_ip"] = raw_log.get("src_ip")
            normalized["action"] = raw_log.get("action")
            normalized["user"] = raw_log.get("user")
            if normalized["action"] == "LOGIN_FAILED":
                normalized["severity"] = "WARNING"
                
        elif source == "firewall":
            normalized["src_ip"] = raw_log.get("src_ip")
            normalized["dst_ip"] = raw_log.get("dst_ip")
            normalized["action"] = raw_log.get("action")
            if normalized["action"] == "DENY":
                normalized["severity"] = "WARNING"

        return normalized
