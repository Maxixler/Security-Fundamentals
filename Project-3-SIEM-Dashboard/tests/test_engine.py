import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.normalizer import Normalizer
from engine.alerter import Alerter
from engine.correlator import Correlator

def test_normalizer_syslog():
    raw_log = {"source": "syslog", "host": "192.168.1.1", "severity": "WARNING", "msg": "Disk Full"}
    norm = Normalizer.normalize(raw_log)
    assert norm["src_ip"] == "192.168.1.1"
    assert norm["severity"] == "WARNING"
    assert norm["source_type"] == "syslog"

def test_normalizer_auth():
    raw_log = {"source": "auth_event", "src_ip": "10.0.0.5", "action": "LOGIN_FAILED", "user": "admin"}
    norm = Normalizer.normalize(raw_log)
    assert norm["severity"] == "WARNING" # Normalizer overrides severity for failed login
    assert norm["action"] == "LOGIN_FAILED"

def test_alerter_generation():
    alerter = Alerter()
    alert = alerter.generate_alert("Test Rule", "Description", "HIGH", [{"event_id": "123"}])
    assert len(alerter.alerts) == 1
    assert alert["rule_name"] == "Test Rule"

def test_correlator_brute_force():
    alerter = Alerter()
    correlator = Correlator(alerter)
    
    # 5 attempts from same IP
    for _ in range(5):
        raw = {"source": "auth_event", "src_ip": "8.8.8.8", "action": "LOGIN_FAILED", "user": "root"}
        norm = Normalizer.normalize(raw)
        correlator.process_event(norm)
        
    assert len(alerter.alerts) == 1
    assert alerter.alerts[0]["rule_name"] == "Brute Force Attack"
    assert "8.8.8.8" in alerter.alerts[0]["description"]

def test_correlator_port_scan():
    alerter = Alerter()
    correlator = Correlator(alerter)
    
    # 10 DENY actions from same IP
    for _ in range(10):
        raw = {"source": "firewall", "src_ip": "1.2.3.4", "action": "DENY"}
        norm = Normalizer.normalize(raw)
        correlator.process_event(norm)
        
    assert len(alerter.alerts) == 1
    assert alerter.alerts[0]["rule_name"] == "Port Scan Detected"
