"""
Modbus TCP Client - HMI / SCADA Link
This script connects to the simulated boiler PLC, reads current sensor values,
and can send legitimate operator commands (like changing thresholds in safe limits).
"""

from pymodbus.client import ModbusTcpClient

class SCADAClient:
    def __init__(self, host="127.0.0.1", port=5020):
        self.host = host
        self.port = port
        self.client = ModbusTcpClient(host, port=port)

    def connect(self):
        return self.client.connect()

    def disconnect(self):
        self.client.close()

    def read_metrics(self):
        """
        Reads the holding registers representing our OT equipment.
        Mapping:
        0 = Temp, 1 = Pressure, 2 = Max Temp, 3 = Max Pressure, 4 = Valve Status
        """
        if not self.client.is_socket_open():
            if not self.connect():
                return None

        try:
            # Read 5 holding registers starting at address 0
            # Unit=0 is typical for direct TCP connections (sometimes 1)
            response = self.client.read_holding_registers(address=0, count=5, slave=0)
            if response.isError():
                print("Error reading from PLC")
                return None

            data = response.registers
            return {
                "temperature": data[0],
                "pressure": data[1],
                "threshold_temp": data[2],
                "threshold_pressure": data[3],
                "valve_status": data[4]
            }
        except Exception as e:
            print(f"Exception during Modbus read: {e}")
            return None

    def write_threshold(self, threshold_type, value):
        """
        Operators can change alarm thresholds. 
        type: 'temp' or 'pressure'
        """
        if not self.client.is_socket_open():
            self.connect()

        try:
            addr = 2 if threshold_type == 'temp' else 3
            res = self.client.write_register(address=addr, value=value, slave=0)
            return not res.isError()
        except:
            return False

if __name__ == "__main__":
    import time
    scada = SCADAClient()
    if scada.connect():
        print("Connected to PLC successfully. Reading metrics...")
        for _ in range(5):
            print(scada.read_metrics())
            time.sleep(1)
        scada.disconnect()
    else:
        print("Could not connect to PLC.")
