import uuid
from datetime import datetime
from typing import List, Dict

class Alerter:
    """
    Korelasyon motorundan gelen tespitlere göre Alarm (Alert) üretir 
    ve bunları hafızada veya veritabanında saklamak üzere iletir.
    """
    def __init__(self):
        self.alerts = []
        self.on_alert_generated = None

    def generate_alert(self, rule_name: str, description: str, severity: str, source_events: List[Dict]) -> dict:
        alert = {
            "alert_id": str(uuid.uuid4()),
            "timestamp": datetime.now().isoformat(),
            "rule_name": rule_name,
            "description": description,
            "severity": severity,
            "event_count": len(source_events),
            "source_event_ids": [evt["event_id"] for evt in source_events]
        }
        self.alerts.append(alert)
        
        if self.on_alert_generated:
            self.on_alert_generated(alert)
            
        return alert
