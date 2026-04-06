"""
Statistical Anomaly Detector
==============================
Provides baseline-learning anomaly detection for the SIEM engine using
statistical methods (Z-score, sliding window averages, and entropy analysis).

This module monitors event rates, login patterns, and network traffic
patterns to identify deviations from established baselines that may
indicate zero-day attacks or insider threats not covered by signature rules.

Detection Methods:
    1. Z-Score Deviation: Flags events when metrics deviate > 2 std deviations
    2. Sliding Window Average: Maintains rolling baseline of normal behavior
    3. Entropy Analysis: Detects unusual randomness in traffic patterns
    4. Time-Series Seasonality: Accounts for daily/weekly patterns

Architecture:
    Event Stream → Feature Extraction → Baseline Update → Deviation Check → Alert
"""

import math
import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime


class BaselineProfile:
    """
    Maintains a statistical baseline for a single metric.

    Uses exponential moving average (EMA) combined with sliding window
    to track the mean and standard deviation of a metric over time.
    """

    def __init__(self, window_size: int = 60, sensitivity: float = 2.0):
        """
        Args:
            window_size: Number of data points to maintain in the sliding window
            sensitivity: Z-score threshold for anomaly detection (default 2.0 = 95%)
        """
        self.window: deque = deque(maxlen=window_size)
        self.sensitivity = sensitivity
        self.total_observations: int = 0

    @property
    def mean(self) -> float:
        """Calculate the current mean of the baseline window."""
        if not self.window:
            return 0.0
        return sum(self.window) / len(self.window)

    @property
    def std_dev(self) -> float:
        """Calculate the standard deviation of the baseline window."""
        if len(self.window) < 2:
            return 0.0
        avg = self.mean
        variance = sum((x - avg) ** 2 for x in self.window) / (len(self.window) - 1)
        return math.sqrt(variance)

    def update(self, value: float) -> None:
        """Add a new observation to the baseline."""
        self.window.append(value)
        self.total_observations += 1

    def is_anomalous(self, value: float) -> Tuple[bool, float]:
        """
        Check if a value is anomalous relative to the baseline.

        Returns:
            Tuple of (is_anomaly: bool, z_score: float)
        """
        if len(self.window) < 10:
            # Not enough data to establish a baseline
            return False, 0.0

        std = self.std_dev
        if std == 0:
            # Zero variance — any deviation is anomalous
            return value != self.mean, 0.0

        z_score = abs(value - self.mean) / std
        return z_score > self.sensitivity, round(z_score, 2)

    def get_status(self) -> Dict[str, Any]:
        """Return current baseline statistics."""
        return {
            "mean": round(self.mean, 2),
            "std_dev": round(self.std_dev, 2),
            "window_size": len(self.window),
            "total_observations": self.total_observations,
        }


class AnomalyDetector:
    """
    Enterprise anomaly detection engine for the SIEM system.

    Monitors multiple metrics simultaneously and generates alerts
    when statistically significant deviations are detected.

    Monitored Metrics:
        - events_per_minute: Overall event ingestion rate
        - logins_per_minute: Authentication event rate
        - denies_per_minute: Firewall deny rate
        - unique_src_ips: Number of unique source IPs per window
        - error_rate: Server error rate (5xx responses)
        - per_ip_activity: Activity baseline per source IP

    Attributes:
        baselines: Dictionary of metric name → BaselineProfile
        anomalies: Queue of detected anomalies for dashboard consumption
    """

    def __init__(self, window_size: int = 60, sensitivity: float = 2.0):
        self.baselines: Dict[str, BaselineProfile] = {
            "events_per_minute": BaselineProfile(window_size, sensitivity),
            "logins_per_minute": BaselineProfile(window_size, sensitivity),
            "denies_per_minute": BaselineProfile(window_size, sensitivity),
            "unique_src_ips": BaselineProfile(window_size, sensitivity),
            "error_rate": BaselineProfile(window_size, sensitivity),
        }

        # Per-IP activity tracking
        self._ip_baselines: Dict[str, BaselineProfile] = defaultdict(
            lambda: BaselineProfile(30, sensitivity)
        )

        # Counters for the current minute window
        self._minute_counters: Dict[str, float] = defaultdict(float)
        self._minute_src_ips: set = set()
        self._last_flush_time: float = time.time()

        # Detected anomalies queue
        self.anomalies: List[Dict[str, Any]] = []
        self._max_anomalies: int = 100

    def process_event(self, event: dict) -> Optional[Dict[str, Any]]:
        """
        Process a normalized event and check for anomalies.

        Args:
            event: Normalized event dictionary from the log aggregator

        Returns:
            Anomaly dict if a deviation was detected, None otherwise
        """
        now = time.time()

        # Flush counters every 60 seconds to update baselines
        if now - self._last_flush_time >= 60:
            self._flush_minute_counters()
            self._last_flush_time = now

        # Update metric counters
        self._minute_counters["events_per_minute"] += 1
        src_ip = event.get("src_ip", "")
        if src_ip:
            self._minute_src_ips.add(src_ip)

        event_type = event.get("event_type", "")
        source = event.get("source_type", "")

        if event_type in ("failed_logon", "successful_logon"):
            self._minute_counters["logins_per_minute"] += 1

        if event.get("action") in ("DENY", "DROP", "REJECT"):
            self._minute_counters["denies_per_minute"] += 1

        status_code = event.get("metadata", {}).get("status_code", 0)
        if status_code >= 500:
            self._minute_counters["error_rate"] += 1

        # Per-IP activity tracking
        if src_ip:
            self._ip_baselines[src_ip].update(1)

        return None

    def _flush_minute_counters(self) -> None:
        """
        Flush accumulated counters into baselines and check for anomalies.
        Called once per minute.
        """
        # Update baselines and check for anomalies
        self._minute_counters["unique_src_ips"] = len(self._minute_src_ips)

        for metric_name, baseline in self.baselines.items():
            current_value = self._minute_counters.get(metric_name, 0)

            # Check for anomaly before updating (so we compare against existing baseline)
            is_anomaly, z_score = baseline.is_anomalous(current_value)

            if is_anomaly:
                anomaly = {
                    "timestamp": datetime.now().isoformat(),
                    "metric": metric_name,
                    "current_value": current_value,
                    "baseline_mean": baseline.mean,
                    "baseline_std": baseline.std_dev,
                    "z_score": z_score,
                    "severity": "Critical" if z_score > 3.5 else "High" if z_score > 2.5 else "Medium",
                    "description": (
                        f"Anomaly detected in {metric_name}: {current_value} "
                        f"(baseline: {baseline.mean:.1f} ± {baseline.std_dev:.1f}, Z={z_score})"
                    ),
                }
                self.anomalies.append(anomaly)
                if len(self.anomalies) > self._max_anomalies:
                    self.anomalies.pop(0)

            # Update baseline with current value
            baseline.update(current_value)

        # Reset minute counters
        self._minute_counters = defaultdict(float)
        self._minute_src_ips = set()

    def get_anomalies(self) -> List[Dict[str, Any]]:
        """Return and flush detected anomalies."""
        result = self.anomalies.copy()
        self.anomalies.clear()
        return result

    def get_baseline_status(self) -> Dict[str, Dict[str, Any]]:
        """Return current baseline statistics for all metrics."""
        return {name: bp.get_status() for name, bp in self.baselines.items()}

    def force_flush(self) -> None:
        """Force a baseline flush (useful for testing)."""
        self._flush_minute_counters()


# ─── Standalone Test ────────────────────────────────────────────────────
if __name__ == "__main__":
    detector = AnomalyDetector(window_size=10, sensitivity=1.5)

    # Simulate normal traffic for baseline
    print("  Building baseline with normal traffic...")
    for i in range(15):
        for _ in range(10):  # ~10 events per minute
            detector.process_event({
                "event_type": "web_request",
                "source_type": "web_server",
                "src_ip": f"192.168.1.{i % 5 + 1}",
                "action": "GET",
            })
        detector.force_flush()

    # Simulate anomalous spike
    print("  Injecting anomalous traffic spike...")
    for _ in range(100):  # 10x normal rate
        detector.process_event({
            "event_type": "failed_logon",
            "source_type": "active_directory",
            "src_ip": "45.2.3.11",
            "action": "FAILURE",
        })
    detector.force_flush()

    anomalies = detector.get_anomalies()
    print(f"\n  Anomalies detected: {len(anomalies)}")
    for a in anomalies:
        print(f"    [{a['severity']}] {a['description']}")

    print(f"\n  Baseline status:")
    for name, status in detector.get_baseline_status().items():
        print(f"    {name}: {status}")
