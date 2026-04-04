"""
Modbus TCP Server - PLC Simulator for Refinery Boiler
This script simulates a PLC controlling a critical boiler unit in the refinery.
It holds values like temperature and pressure in its registers, and allows
Modbus TCP clients (HMIs or attackers) to read and write to these registers.
"""

import asyncio
import logging
import threading
import time
import random

from pymodbus.server import StartAsyncTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext

# Setup logging
logging.basicConfig()
log = logging.getLogger()
log.setLevel(logging.INFO)

# Register Map (Holding Registers)
# Address 0: Current Boiler Temperature (0-500 C)
# Address 1: Current Boiler Pressure (0-100 psi)
# Address 2: Max Temperature Alarm Threshold (Default: 450 C)
# Address 3: Max Pressure Alarm Threshold (Default: 80 psi)
# Address 4: Emergency Valve Status (0: Closed, 1: Open)

class RefineryPLCSimulator:
    def __init__(self, host="0.0.0.0", port=5020): # Using 5020 to avoid root requirement on linux/mac, works fine on windows too
        self.host = host
        self.port = port
        self.store = None
        self.context = None
        self.simulation_running = False

    def setup_datastore(self):
        # Initialize Modbus datastore with 100 registers.
        # Pymodbus ModbusSequentialDataBlock often uses 1-based internal indexing for its array.
        # So values[1] maps to address 0, values[2] to address 1, etc.
        values = [0] * 100
        values[1] = 250  # Temp (Address 0)
        values[2] = 40   # Pressure (Address 1)
        values[3] = 450  # Max Temp (Address 2)
        values[4] = 80   # Max Pressure (Address 3)
        values[5] = 0    # Valve (Address 4)
        
        holding_registers = ModbusSequentialDataBlock(0, values)
        slave_context = ModbusSlaveContext(
            di=ModbusSequentialDataBlock(0, [0]*100),
            co=ModbusSequentialDataBlock(0, [0]*100),
            hr=holding_registers,
            ir=ModbusSequentialDataBlock(0, [0]*100)
        )
        self.context = ModbusServerContext(slaves=slave_context, single=True)

    def setup_identity(self):
        identity = ModbusDeviceIdentification()
        identity.VendorName = 'IndustrialSim'
        identity.ProductCode = 'IND-PLC-100'
        identity.VendorUrl = 'http://security.industrial.local'
        identity.ProductName = 'Boiler Controller PLC'
        identity.ModelName = 'IND-Sim-Model'
        identity.MajorMinorRevision = '1.0'
        return identity

    def simulate_process(self):
        """
        Background thread that simulates the physical process.
        It slightly varies the temperature and pressure randomly to look realistic.
        It also checks if thresholds are exceeded to trigger emergency responses.
        """
        log.info("Starting refinery process simulation loop...")
        self.simulation_running = True
        while self.simulation_running:
            if not self.context:
                time.sleep(1)
                continue
            
            # Get current values
            slave_id = 0x00
            current_temp = self.context[slave_id].getValues(3, 0, count=1)[0]
            current_press = self.context[slave_id].getValues(3, 1, count=1)[0]
            max_temp = self.context[slave_id].getValues(3, 2, count=1)[0]
            max_press = self.context[slave_id].getValues(3, 3, count=1)[0]
            valve_status = self.context[slave_id].getValues(3, 4, count=1)[0]

            # Simulate physical changes (random walk)
            # If valve is open (1), pressure and temp decrease rapidly
            if valve_status == 1:
                new_temp = max(50, current_temp - random.randint(5, 15))
                new_press = max(10, current_press - random.randint(2, 5))
            else:
                # Normal fluctuation
                temp_delta = random.choice([-1, 0, 1, 2])
                press_delta = random.choice([-1, 0, 1])
                
                # Slowly trend back towards normal operating state if we are slightly off, 
                # but allow it to drift if attacked.
                new_temp = current_temp + temp_delta
                new_press = current_press + press_delta

                # Emergency Trigger Condition
                if new_temp >= max_temp or new_press >= max_press:
                    log.warning(f"⚠️ CRITICAL ALARM: Limits exceeded! Temp: {new_temp}/{max_temp}, Press: {new_press}/{max_press}")
                    # Automatic safety interlock: Open the valve!
                    self.context[slave_id].setValues(3, 4, [1])

            # Update datastore with new simulated values
            self.context[slave_id].setValues(3, 0, [new_temp])
            self.context[slave_id].setValues(3, 1, [new_press])

            # Print status periodically conceptually handled by dashboard, but good for CLI
            time.sleep(2)

    async def run_server(self):
        self.setup_datastore()
        identity = self.setup_identity()
        
        # Start the physical simulation loop in a background thread
        sim_thread = threading.Thread(target=self.simulate_process, daemon=True)
        sim_thread.start()

        log.info(f"Starting Modbus TCP Simulator on {self.host}:{self.port}")
        await StartAsyncTcpServer(
            context=self.context,
            identity=identity,
            address=(self.host, self.port)
        )

if __name__ == "__main__":
    simulator = RefineryPLCSimulator()
    try:
        asyncio.run(simulator.run_server())
    except KeyboardInterrupt:
        print("Simulator stopped.")
