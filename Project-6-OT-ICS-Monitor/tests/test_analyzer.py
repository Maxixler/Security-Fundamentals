import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.scada_analyzer import SCADAAnalyzer

def test_scada_analyzer():
    analyzer = SCADAAnalyzer()
    
    # 1. Okuma işlemi (Normal, alert olmamalı)
    read_pkt = {"function_code": 3, "address": 100}
    res = analyzer.analyze_modbus_command(read_pkt)
    assert res["is_alert"] == False

    # 2. Yetkisiz yazma (Adres 100 - Read Only Segment)
    write_protected = {"function_code": 6, "address": 100, "value": 1}
    res2 = analyzer.analyze_modbus_command(write_protected)
    assert res2["is_alert"] == True
    assert res2["severity"] == "CRITICAL"
    
    # 3. Yüksek limit asimi (Adres 200, RPM 5000 > 3000)
    overload = {"function_code": 6, "address": 200, "value": 5000}
    res3 = analyzer.analyze_modbus_command(overload)
    assert res3["is_alert"] == True
    assert "OVERLOAD" in res3["message"]
    
    # 4. Doğru limitte yazma (Alert olmamali, sadece uyari)
    valid_write = {"function_code": 6, "address": 200, "value": 2000}
    res4 = analyzer.analyze_modbus_command(valid_write)
    assert res4["is_alert"] == False
