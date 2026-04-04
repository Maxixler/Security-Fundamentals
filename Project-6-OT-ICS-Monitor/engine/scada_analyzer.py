class SCADAAnalyzer:
    """Modbus komutlarının tehlikeli veya fabrikasyon süreçlerine (OT) aykırı olup olmadığını denetler."""
    
    def __init__(self):
        # Endüstriyel OT Güvenlik Kuralları (Baseline)
        self.rules = {
            100: {"max_write_val": 0, "allow_write": False, "desc": "Ana Reaktor Basınç Valfi (Read Only Segment)"},
            200: {"max_write_val": 3000, "allow_write": True, "desc": "Soğutucu Ana Pompa (Maksimum Devir: 3000 RPM)"}
        }
    
    def analyze_modbus_command(self, parsed_pkt: dict) -> dict:
        fc = parsed_pkt.get("function_code")
        address = parsed_pkt.get("address")
        value = parsed_pkt.get("value", 0)
        
        alert = False
        msg = "Routine Polling Data"
        severity = "INFO"
        
        # Sadece WRITE (Sistem durumunu değiştiren manipülatif fonskiyonlar) kontrol edilir
        if fc in [5, 6, 16]:
            if address in self.rules:
                rule = self.rules[address]
                if not rule["allow_write"]:
                    alert = True
                    msg = f"MODBUS SECURITY BREACH: {rule['desc']} is strictly WRITE-PROTECTED. Actuator manipulation blocked!"
                    severity = "CRITICAL"
                elif value > rule["max_write_val"]:
                    alert = True
                    msg = f"OVERLOAD ALERT: Actuator value limit exceeded. Attempted: {value}, Max safe bound: {rule['max_write_val']} RPM."
                    severity = "CRITICAL"
                else:
                    msg = f"Authorized Configuration Command Accepted for {rule['desc']}."
                    severity = "WARN" # Write işlemleri hep dikkat çeker
            else:
                alert = True
                msg = f"UNAUTHORIZED MEMORY ADDRESS FAULT: SCADA tried to write to unmapped memory address: {address}."
                severity = "HIGH"
                
        return {
            "original_packet": parsed_pkt,
            "is_alert": alert,
            "message": msg,
            "severity": severity
        }
