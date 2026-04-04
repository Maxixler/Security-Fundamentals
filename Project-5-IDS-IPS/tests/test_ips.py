import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.ips_blocker import IPSBlocker

def test_ips_blocker():
    ips = IPSBlocker()
    assert ips.is_blocked("10.0.0.99") == False
    
    ips.block_ip("10.0.0.99")
    assert ips.is_blocked("10.0.0.99") == True
    assert ips.is_blocked("8.8.8.8") == False
