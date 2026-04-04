import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collectors.syslog_receiver import SyslogCollector
from collectors.auth_logger import AuthLogCollector
from collectors.firewall_adapter import FirewallLogCollector

def test_syslog_collector_inject():
    col = SyslogCollector()
    received = []
    col.on_log_received = lambda x: received.append(x)
    col.inject_custom_log("10.0.0.1", "Unit test message")
    assert len(received) == 1
    assert received[0]["host"] == "10.0.0.1"
    assert received[0]["msg"] == "Unit test message"

def test_auth_collector_brute_force():
    col = AuthLogCollector()
    received = []
    col.on_log_received = lambda x: received.append(x)
    col.inject_brute_force("192.168.1.55", "admin", attempts=3)
    assert len(received) == 3
    assert all(x["action"] == "LOGIN_FAILED" for x in received)

def test_run_stop():
    col = FirewallLogCollector()
    received = []
    col.start(lambda x: received.append(x))
    assert col.running is True
    col.stop()
    assert col.running is False
