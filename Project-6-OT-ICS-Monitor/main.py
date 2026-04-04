import time
import random
import threading
from flask import Flask, jsonify, send_from_directory
from engine.modbus_parser import ModbusParser
from engine.scada_analyzer import SCADAAnalyzer

app = Flask(__name__, static_folder="dashboard")

parser = ModbusParser()
analyzer = SCADAAnalyzer()

# PLC Simulation State (Endüstriyel Durum)
plc_state = {
    100: 50, # Basınç valfi durumu (0-100)
    200: 1500 # Motor rpm (0-5000)
}

event_logs = []
MAX_LOGS = 30

def generate_modbus_traffic():
    """Arka planda rastgele OT (Modbus TCP) trafiği oluşturur."""
    transaction_id = 1
    while True:
        time.sleep(random.uniform(0.5, 2.5))
        
        # %15 ihtimalle anomalili / sabotaj paketi
        is_attack = random.random() > 0.85
        
        if is_attack:
            # Saldırı senaryosu: ya Read-only 100 nolu valfe yazar, ya da 200'ü tehlikeli limit (3000+) üstüne çeker.
            attack_type = random.choice(["write_100", "overload_200"])
            if attack_type == "write_100":
                fc, addr, val = 6, 100, random.randint(1, 100)
            else:
                fc, addr, val = 6, 200, random.randint(3100, 5000)
            pkt = {"transaction_id": transaction_id, "function_code": fc, "address": addr, "value": val}
        else:
            # Normal endüstriyel operasyon (Read veya güvenli Write)
            addr = random.choice([100, 200])
            fc = random.choice([3, 6])
            if fc == 3:
                pkt = {"transaction_id": transaction_id, "function_code": 3, "address": addr}
            else:
                # Güvenli write
                if addr == 200:
                    val = random.randint(500, 2500)
                else:
                    fc = 3 # 100 is read only, fallback to read
                    val = 0
                pkt = {"transaction_id": transaction_id, "function_code": fc, "address": addr, "value": val}
                
        # Parse & SCADA Security Analyze
        parsed = parser.parse_packet(pkt)
        analysis = analyzer.analyze_modbus_command(parsed)
        
        # IPS engel koymadıysa gerçek PLC durumunu güncelle (Basit Simülasyon)
        if fc == 6 and not analysis["is_alert"]:
            plc_state[addr] = pkt["value"]
            
        event_logs.append({
            "time": time.strftime("%H:%M:%S"),
            "tid": transaction_id,
            "action": parsed["action_type"],
            "addr": pkt["address"],
            "val": pkt.get("value", "-"),
            "alert": analysis["is_alert"],
            "msg": analysis["message"],
            "sev": analysis["severity"]
        })
        
        if len(event_logs) > MAX_LOGS:
            event_logs.pop(0)
            
        transaction_id += 1

@app.route("/")
def index():
    return send_from_directory("dashboard", "index.html")

@app.route("/<path:path>")
def serve_static(path):
    return send_from_directory("dashboard", path)

@app.route("/api/scada_data")
def get_data():
    return jsonify({
        "plc_state": plc_state,
        "logs": event_logs
    })

if __name__ == "__main__":
    t = threading.Thread(target=generate_modbus_traffic, daemon=True)
    t.start()
    print("[*] OT/ICS Monitor started at http://localhost:5005")
    app.run(host="0.0.0.0", port=5005, use_reloader=False)
