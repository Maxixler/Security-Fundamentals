import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.modbus_parser import ModbusParser

def test_parse_packet():
    parser = ModbusParser()
    pkt = {"transaction_id": 1, "function_code": 3, "address": 100}
    res = parser.parse_packet(pkt)
    assert res["action_type"] == "READ ANALOG VALUE"

    pkt2 = {"transaction_id": 2, "function_code": 6, "address": 200, "value": 1500}
    res2 = parser.parse_packet(pkt2)
    assert res2["action_type"] == "SET ANALOG SETPOINT"
