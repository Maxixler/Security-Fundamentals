"""
OT Anomaly Detection & Traffic Monitor
=========================================
Monitors Modbus register operations for anomalous patterns that may
indicate cyber attacks against industrial control systems.

Detection Methods:
    1. Unauthorized Function Code — Detects write to read-only registers
    2. Value Range Violation — Values outside safe operating parameters
    3. Rate of Change — Sudden jumps in process values
    4. Access Pattern — Abnormal register access frequency
    5. Unauthorized Write Source — Writes from non-SCADA IPs

Architecture:
    Modbus Command → Whitelist Check → Range Validation →
    Rate-of-Change → Access Pattern → Alert/Allow
"""

import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Any
from datetime import datetime


class OTAnomalyDetector:
    """
    Industrial anomaly detection engine for Modbus TCP traffic.

    Monitors register read/write operations and flags suspicious
    patterns that may indicate unauthorized access or sabotage.

    Attributes:
        alerts: Queue of generated OT security alerts
        register_history: Per-register value history for rate-of-change analysis
        access_counters: Per-register access frequency tracking
        stats: Detection statistics
    """

    # Authorized SCADA/HMI addresses (whitelist)
    AUTHORIZED_WRITERS = {"10.0.0.5", "10.0.0.10", "192.168.1.100"}

    # Maximum rate of change per tick (% of register range)
    MAX_RATE_OF_CHANGE = 25  # percent

    # Write frequency threshold (writes per minute per register)
    MAX_WRITE_FREQUENCY = 10

    def __init__(self):
        self.alerts: List[Dict[str, Any]] = []
        self.register_history: Dict[int, deque] = defaultdict(lambda: deque(maxlen=20))
        self.access_counters: Dict[int, deque] = defaultdict(deque)
        self.stats = {
            "commands_analyzed": 0,
            "alerts_generated": 0,
            "writes_blocked": 0,
            "unauthorized_access": 0,
        }
        self.max_alerts = 50

    def analyze_command(self, command: Dict[str, Any], register_map: Dict[int, Dict] = None) -> Dict[str, Any]:
        """
        Analyze a Modbus command for anomalous patterns.

        Args:
            command: Dict with keys: function_code, address, value, source_ip
            register_map: PLC register configuration for validation

        Returns:
            Analysis result with is_alert flag and severity
        """
        self.stats["commands_analyzed"] += 1

        fc = command.get("function_code", 3)
        address = command.get("address", 0)
        value = command.get("value", 0)
        source_ip = command.get("source_ip", "unknown")
        now = time.time()

        result = {
            "is_alert": False,
            "severity": "info",
            "message": "Normal operation",
            "action": "ALLOW",
            "checks": [],
        }

        # Only analyze write operations (FC 6 = Write Single Register, FC 16 = Write Multiple)
        if fc not in (6, 16):
            result["message"] = f"Read operation (FC {fc}) — Allowed"
            return result

        # ─── Check 1: Unauthorized Source IP ────────────────────────────
        if source_ip not in self.AUTHORIZED_WRITERS and source_ip != "HMI":
            result["is_alert"] = True
            result["severity"] = "Critical"
            result["action"] = "BLOCK"
            result["message"] = f"UNAUTHORIZED WRITE: Source {source_ip} not in authorized list"
            result["checks"].append("unauthorized_source")
            self.stats["unauthorized_access"] += 1
            self._create_alert(result, command)
            return result

        # ─── Check 2: Read-Only Register Protection ────────────────────
        if register_map:
            reg_config = register_map.get(address, {})
            if reg_config.get("readonly", False):
                result["is_alert"] = True
                result["severity"] = "Critical"
                result["action"] = "BLOCK"
                result["message"] = f"WRITE TO READ-ONLY REGISTER: {reg_config.get('name', address)} (addr {address})"
                result["checks"].append("readonly_violation")
                self.stats["writes_blocked"] += 1
                self._create_alert(result, command)
                return result

        # ─── Check 3: Value Range Validation ────────────────────────────
        if register_map:
            reg_config = register_map.get(address, {})
            reg_min = reg_config.get("min", 0)
            reg_max = reg_config.get("max", 65535)

            if value < reg_min or value > reg_max:
                result["is_alert"] = True
                result["severity"] = "High"
                result["action"] = "BLOCK"
                result["message"] = (
                    f"VALUE OUT OF RANGE: Register {address} ({reg_config.get('name', '?')}) "
                    f"value {value} outside [{reg_min}-{reg_max}]"
                )
                result["checks"].append("range_violation")
                self.stats["writes_blocked"] += 1
                self._create_alert(result, command)
                return result

        # ─── Check 4: Rate of Change Analysis ──────────────────────────
        history = self.register_history[address]
        if len(history) >= 2:
            prev_value = history[-1]
            if register_map and address in register_map:
                reg_range = register_map[address].get("max", 100) - register_map[address].get("min", 0)
                if reg_range > 0:
                    change_pct = abs(value - prev_value) / reg_range * 100
                    if change_pct > self.MAX_RATE_OF_CHANGE:
                        result["is_alert"] = True
                        result["severity"] = "High"
                        result["message"] = (
                            f"RAPID VALUE CHANGE: Register {address} changed by {change_pct:.0f}% "
                            f"({prev_value} → {value})"
                        )
                        result["checks"].append("rate_of_change")
                        self._create_alert(result, command)

        # Record value in history
        history.append(value)

        # ─── Check 5: Write Frequency Analysis ─────────────────────────
        access_log = self.access_counters[address]
        access_log.append(now)

        # Clean old entries (> 60 seconds)
        while access_log and (now - access_log[0]) > 60:
            access_log.popleft()

        if len(access_log) > self.MAX_WRITE_FREQUENCY:
            if not result["is_alert"]:  # Don't overwrite a more severe alert
                result["is_alert"] = True
                result["severity"] = "Medium"
                result["message"] = (
                    f"HIGH WRITE FREQUENCY: Register {address} written "
                    f"{len(access_log)} times in 60s (limit: {self.MAX_WRITE_FREQUENCY})"
                )
                result["checks"].append("write_frequency")
                self._create_alert(result, command)

        if not result["is_alert"]:
            result["message"] = f"Write to register {address} = {value} — Normal operation"

        return result

    def _create_alert(self, result: Dict, command: Dict) -> None:
        """Record an alert for the dashboard."""
        self.stats["alerts_generated"] += 1
        alert = {
            "timestamp": datetime.now().isoformat(),
            "severity": result["severity"],
            "message": result["message"],
            "action": result.get("action", "ALERT"),
            "register": command.get("address", 0),
            "value": command.get("value", 0),
            "source_ip": command.get("source_ip", "unknown"),
            "function_code": command.get("function_code", 0),
            "checks_triggered": result.get("checks", []),
        }
        self.alerts.insert(0, alert)
        if len(self.alerts) > self.max_alerts:
            self.alerts.pop()

    def get_alerts(self) -> List[Dict]:
        """Return recent alerts."""
        return self.alerts

    def get_stats(self) -> Dict:
        """Return detection statistics."""
        return dict(self.stats)
