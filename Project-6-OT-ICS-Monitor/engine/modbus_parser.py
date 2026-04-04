class ModbusParser:
    """Modbus TCP paketlerini parse eden yapı (Simülasyon).
    Gerçekte Wireshark'ın okuduğu Hex frame'leri yerine dict formatında alınıp endüstriyel aksiyonlara çevrilir."""
    
    # Standard Modbus Function Codes (FC)
    FC_READ_COILS = 1
    FC_READ_HOLDING_REGISTERS = 3
    FC_WRITE_SINGLE_COIL = 5
    FC_WRITE_SINGLE_REGISTER = 6
    FC_WRITE_MULTIPLE_REGISTERS = 16

    def parse_packet(self, packet: dict) -> dict:
        parsed = packet.copy()
        fc = packet.get("function_code")
        
        if fc == self.FC_READ_COILS:
            parsed["action_type"] = "READ SENSOR/COIL STATE"
        elif fc == self.FC_READ_HOLDING_REGISTERS:
            parsed["action_type"] = "READ ANALOG VALUE"
        elif fc == self.FC_WRITE_SINGLE_COIL:
            parsed["action_type"] = "ACTIVATE/DEACTIVATE (ON/OFF)"
        elif fc == self.FC_WRITE_SINGLE_REGISTER:
            parsed["action_type"] = "SET ANALOG SETPOINT"
        elif fc == self.FC_WRITE_MULTIPLE_REGISTERS:
            parsed["action_type"] = "BULK PLC OVERWRITE"
        else:
            parsed["action_type"] = "UNKNOWN COMMAND"
            
        return parsed
