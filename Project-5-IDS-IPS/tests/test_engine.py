import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.signature_matcher import SignatureMatcher

def test_signature_matcher():
    matcher = SignatureMatcher()
    
    # Zararsız paket
    benign = {"payload": "GET / HTTP/1.1", "protocol": "TCP"}
    assert len(matcher.analyze_packet(benign)) == 0
    
    # SQLi Paketi
    sqli = {"payload": "id=1' OR 1=1--", "protocol": "TCP"}
    matches = matcher.analyze_packet(sqli)
    assert len(matches) == 1
    assert matches[0]["msg"] == "Possible SQL Injection Detected"
    
    # XSS Paketi
    xss = {"payload": "<script>alert(1)</script>", "protocol": "TCP"}
    matches2 = matcher.analyze_packet(xss)
    assert len(matches2) == 1
    assert matches2[0]["action"] == "ALERT"
    
    # UDP Nmap Paketi
    nmap = {"payload": "nmap scan probe string", "protocol": "UDP"}
    matches3 = matcher.analyze_packet(nmap)
    assert len(matches3) == 1
    assert matches3[0]["action"] == "DROP"
