"""
OT/ICS Modbus PLC Simulator
==============================
Simulates a realistic industrial control system with multiple PLCs
controlling a Crude Distillation Unit (CDU) refinery process.

Simulated Units:
    - Boiler System (temperature, pressure, valve position)
    - Pump Station (flow rate, RPM, discharge pressure)
    - Cooling Tower (coolant temp, fan speed)
    - Safety Instrumented System (SIS) (emergency shutdown logic)

Register Map:
    100-109: Boiler (temperature, pressure, valve, fuel_rate)
    200-209: Pump (flow_rate, rpm, discharge_pressure, vibration)
    300-309: Cooling (coolant_temp, fan_speed, inlet_temp, outlet_temp)
    400-409: SIS (emergency_active, trip_count, override_enabled)

Architecture:
    Register Store → Physics Engine → Alarm Manager → Modbus Interface
"""

import time
import random
import math
from typing import Dict, List, Any, Optional
from datetime import datetime


class ProcessPhysics:
    """
    Simulates simplified physical process dynamics for the CDU.
    Models cross-register dependencies (e.g., temperature → pressure).
    """

    @staticmethod
    def update_boiler(registers: Dict[int, int], dt: float) -> None:
        """Update boiler physics: temperature drives pressure."""
        temp = registers.get(100, 350)
        pressure = registers.get(101, 45)
        valve = registers.get(102, 50)
        fuel = registers.get(103, 40)

        # Temperature changes based on fuel rate and valve cooling
        temp_delta = (fuel * 0.3 - valve * 0.15) * dt
        temp = max(200, min(600, temp + int(temp_delta)))

        # Pressure is a function of temperature (P ∝ T by ideal gas law approximation)
        target_pressure = int(temp * 0.15)
        pressure = pressure + int((target_pressure - pressure) * 0.1)
        pressure = max(10, min(100, pressure))

        # Add small random noise for realism
        temp += random.randint(-2, 2)
        pressure += random.randint(-1, 1)

        registers[100] = max(200, min(600, temp))
        registers[101] = max(10, min(100, pressure))

    @staticmethod
    def update_pump(registers: Dict[int, int], dt: float) -> None:
        """Update pump physics: RPM drives flow rate."""
        rpm = registers.get(201, 1500)
        flow = registers.get(200, 120)
        discharge = registers.get(202, 35)
        vibration = registers.get(203, 5)

        # Flow rate proportional to RPM
        target_flow = int(rpm * 0.08)
        flow = flow + int((target_flow - flow) * 0.15)
        flow = max(0, min(500, flow))

        # Discharge pressure from flow
        target_discharge = int(flow * 0.3)
        discharge = discharge + int((target_discharge - discharge) * 0.1)

        # Vibration increases with RPM and age
        vibration = int(rpm * 0.003 + random.randint(0, 3))

        flow += random.randint(-3, 3)
        registers[200] = max(0, min(500, flow))
        registers[202] = max(0, min(80, discharge))
        registers[203] = max(0, min(50, vibration))

    @staticmethod
    def update_cooling(registers: Dict[int, int], boiler_temp: int, dt: float) -> None:
        """Update cooling tower: manages coolant temperatures."""
        coolant = registers.get(300, 85)
        fan_speed = registers.get(301, 50)
        inlet = registers.get(302, 90)
        outlet = registers.get(303, 35)

        # Inlet temperature influenced by boiler
        inlet = max(50, min(120, int(boiler_temp * 0.2 + random.randint(-3, 3))))

        # Coolant temperature: balance of inlet heat and fan cooling
        cooling_effect = fan_speed * 0.5
        target_coolant = max(20, int(inlet - cooling_effect * 0.3))
        coolant = coolant + int((target_coolant - coolant) * 0.1)

        # Outlet temperature is cooled water
        outlet = max(15, int(coolant * 0.5 + random.randint(-2, 2)))

        registers[300] = max(20, min(120, coolant))
        registers[302] = inlet
        registers[303] = outlet


class AlarmManager:
    """
    Manages real-time process alarms based on register values and thresholds.
    """

    ALARM_THRESHOLDS = {
        "boiler_temp_high": {"register": 100, "max": 500, "severity": "Critical", "unit": "°C"},
        "boiler_temp_warning": {"register": 100, "max": 450, "severity": "Warning", "unit": "°C"},
        "boiler_pressure_high": {"register": 101, "max": 80, "severity": "Critical", "unit": "bar"},
        "pump_rpm_high": {"register": 201, "max": 3000, "severity": "High", "unit": "RPM"},
        "pump_vibration_high": {"register": 203, "max": 30, "severity": "Warning", "unit": "mm/s"},
        "cooling_temp_high": {"register": 300, "max": 100, "severity": "High", "unit": "°C"},
    }

    def __init__(self):
        self.active_alarms: List[Dict[str, Any]] = []

    def check_alarms(self, registers: Dict[int, int]) -> List[Dict[str, Any]]:
        """Evaluate all alarm conditions against current register values."""
        new_alarms = []
        for alarm_name, config in self.ALARM_THRESHOLDS.items():
            reg_addr = config["register"]
            current_value = registers.get(reg_addr, 0)

            if current_value > config["max"]:
                alarm = {
                    "name": alarm_name,
                    "register": reg_addr,
                    "current_value": current_value,
                    "threshold": config["max"],
                    "severity": config["severity"],
                    "unit": config["unit"],
                    "timestamp": datetime.now().isoformat(),
                    "message": f"{alarm_name}: {current_value}{config['unit']} exceeds limit {config['max']}{config['unit']}",
                }
                new_alarms.append(alarm)

        self.active_alarms = new_alarms
        return new_alarms


class PLCSimulator:
    """
    Modbus PLC simulator with multi-unit industrial process.

    Simulates holding registers for boiler, pump, cooling, and SIS systems
    with realistic physics-based value propagation.

    Attributes:
        registers: Dictionary mapping register addresses to values
        alarm_manager: Process alarm evaluator
        physics: Physics engine for cross-register dependencies
        alarm_log: Historical alarm entries
    """

    # Default register configuration
    REGISTER_MAP = {
        # Boiler System (100-109)
        100: {"name": "Boiler Temperature", "unit": "°C", "default": 350, "min": 200, "max": 600, "readonly": False},
        101: {"name": "Boiler Pressure", "unit": "bar", "default": 45, "min": 10, "max": 100, "readonly": True},
        102: {"name": "Outlet Valve Position", "unit": "%", "default": 50, "min": 0, "max": 100, "readonly": False},
        103: {"name": "Fuel Feed Rate", "unit": "L/min", "default": 40, "min": 0, "max": 100, "readonly": False},
        # Pump Station (200-209)
        200: {"name": "Flow Rate", "unit": "m³/h", "default": 120, "min": 0, "max": 500, "readonly": True},
        201: {"name": "Motor RPM", "unit": "RPM", "default": 1500, "min": 0, "max": 5000, "readonly": False},
        202: {"name": "Discharge Pressure", "unit": "bar", "default": 35, "min": 0, "max": 80, "readonly": True},
        203: {"name": "Vibration Level", "unit": "mm/s", "default": 5, "min": 0, "max": 50, "readonly": True},
        # Cooling Tower (300-309)
        300: {"name": "Coolant Temperature", "unit": "°C", "default": 85, "min": 20, "max": 120, "readonly": True},
        301: {"name": "Fan Speed", "unit": "%", "default": 50, "min": 0, "max": 100, "readonly": False},
        302: {"name": "Hot Inlet Temp", "unit": "°C", "default": 90, "min": 50, "max": 120, "readonly": True},
        303: {"name": "Cold Outlet Temp", "unit": "°C", "default": 35, "min": 15, "max": 80, "readonly": True},
        # Safety Instrumented System (400-409)
        400: {"name": "Emergency Shutdown", "unit": "bool", "default": 0, "min": 0, "max": 1, "readonly": False},
        401: {"name": "Trip Count", "unit": "count", "default": 0, "min": 0, "max": 999, "readonly": True},
        402: {"name": "Maintenance Override", "unit": "bool", "default": 0, "min": 0, "max": 1, "readonly": False},
    }

    def __init__(self):
        # Initialize registers with defaults
        self.registers: Dict[int, int] = {
            addr: cfg["default"] for addr, cfg in self.REGISTER_MAP.items()
        }
        self.alarm_manager = AlarmManager()
        self.physics = ProcessPhysics()
        self.alarm_log: List[Dict] = []
        self._event_log: List[Dict] = []
        self.max_log_size = 50

    def tick(self, dt: float = 1.0) -> Dict[str, Any]:
        """
        Advance the simulation by one time step.

        Updates physics, checks alarms, and returns the current state.

        Args:
            dt: Time step in seconds

        Returns:
            Dictionary containing current state and any new alarms
        """
        # Skip physics if emergency shutdown is active
        if self.registers.get(400, 0) == 1:
            return {"state": "EMERGENCY_SHUTDOWN", "registers": dict(self.registers), "alarms": []}

        # Update physics
        self.physics.update_boiler(self.registers, dt)
        self.physics.update_pump(self.registers, dt)
        self.physics.update_cooling(self.registers, self.registers.get(100, 350), dt)

        # Check alarms
        alarms = self.alarm_manager.check_alarms(self.registers)
        for a in alarms:
            self.alarm_log.insert(0, a)
            if len(self.alarm_log) > self.max_log_size:
                self.alarm_log.pop()

        # SIS auto-trip if critical conditions
        if self.registers.get(100, 0) > 550 or self.registers.get(101, 0) > 90:
            self.registers[400] = 1
            self.registers[401] = self.registers.get(401, 0) + 1

        return {
            "state": "RUNNING",
            "registers": dict(self.registers),
            "alarms": alarms,
        }

    def read_register(self, address: int) -> Optional[int]:
        """Read a single register value (Modbus function code 3)."""
        return self.registers.get(address)

    def write_register(self, address: int, value: int) -> Dict[str, Any]:
        """
        Write a value to a register (Modbus function code 6).
        Checks for read-only protection and value range.
        """
        reg_config = self.REGISTER_MAP.get(address)
        if reg_config is None:
            return {"success": False, "error": "Unknown register address"}

        if reg_config["readonly"]:
            return {"success": False, "error": f"Register {address} is read-only"}

        if not (reg_config["min"] <= value <= reg_config["max"]):
            return {
                "success": False,
                "error": f"Value {value} out of range [{reg_config['min']}-{reg_config['max']}]",
            }

        old_value = self.registers.get(address, 0)
        self.registers[address] = value

        event = {
            "timestamp": datetime.now().isoformat(),
            "action": "WRITE",
            "register": address,
            "register_name": reg_config["name"],
            "old_value": old_value,
            "new_value": value,
        }
        self._event_log.insert(0, event)
        if len(self._event_log) > self.max_log_size:
            self._event_log.pop()

        return {"success": True, "event": event}

    def get_state(self) -> Dict[str, Any]:
        """Return full simulator state for dashboard consumption."""
        register_data = {}
        for addr, value in self.registers.items():
            config = self.REGISTER_MAP.get(addr, {})
            register_data[str(addr)] = {
                "value": value,
                "name": config.get("name", "Unknown"),
                "unit": config.get("unit", ""),
                "readonly": config.get("readonly", True),
                "min": config.get("min", 0),
                "max": config.get("max", 100),
            }

        return {
            "registers": register_data,
            "alarms": self.alarm_log[:10],
            "events": self._event_log[:10],
            "emergency": self.registers.get(400, 0) == 1,
        }
