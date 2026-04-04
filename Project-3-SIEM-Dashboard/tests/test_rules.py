import sys, os
import json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.sqlite_manager import DatabaseManager
from engine.correlator import Correlator
from engine.alerter import Alerter

def test_database_manager():
    db = DatabaseManager(db_path=":memory:")
    
    # Test events
    db.insert_event({
        "event_id": "evt-123", "timestamp": "2024-01-01T00:00:00", 
        "source_type": "syslog", "src_ip": "1.1.1.1", "dst_ip": None, 
        "action": None, "severity": "INFO", "user": None, "msg": "Test"
    })
    events = db.get_recent_events()
    assert len(events) == 1
    assert events[0]["event_id"] == "evt-123"

def test_rules_loading():
    alerter = Alerter()
    correlator = Correlator(alerter)
    rules_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules", "detection_rules.json")
    correlator.load_rules(rules_path)
    assert len(correlator.rules) == 2
    assert correlator.rules[0]["name"] == "Brute Force Attack"
