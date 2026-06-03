"""
SIEM Application State Management
=================================

Centralized application state management to replace global variables
and provide better structure for the SIEM system.
"""

import threading
import time
from typing import List, Dict, Any, Optional
from collections import deque

from .log_aggregator import LogAggregator, NormalizedEvent
from .correlation_engine import CorrelationEngine, Incident
from .anomaly_detector import AnomalyDetector
from .ml_anomaly_detector import get_ml_anomaly_detector
from .threat_intel import ThreatIntelFeed


class ApplicationState:
    """
    Centralized application state for the SIEM system.

    Replaces global variables with a thread-safe, manageable state object.
    """

    def __init__(self, max_alerts: int = 50, max_logs: int = 100):
        # Core SIEM components
        self.aggregator = LogAggregator(max_buffer=500)
        self.correlator = CorrelationEngine()
        self.anomaly_detector = AnomalyDetector(window_size=30, sensitivity=2.0)
        self.ml_anomaly_detector = get_ml_anomaly_detector()

        # ML training buffer
        self._ml_training_buffer: deque = deque(maxlen=1000)
        self._ml_last_train_time = 0
        self._ml_retrain_interval = 300  # 5 minutes
        self._ml_min_samples = 50

        # Thread-safe buffers for UI consumption
        self._system_alerts: deque = deque(maxlen=max_alerts)
        self._historical_logs: deque = deque(maxlen=max_logs)
        self._alerts_lock = threading.RLock()
        self._logs_lock = threading.RLock()

        # Simulation state
        self.simulation_running = False
        self._simulation_lock = threading.Lock()

        # Statistics
        self.start_time = time.time()
        self.events_processed = 0

    # ─── Alert Management ────────────────────────────────────────────────

    def add_alert(self, alert_data: Dict[str, Any]) -> None:
        """Add a new alert to the system (thread-safe)."""
        with self._alerts_lock:
            self._system_alerts.appendleft(alert_data)

    def get_alerts(self, limit: int = 20, severity_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get alerts from the system (thread-safe)."""
        with self._alerts_lock:
            alerts = list(self._system_alerts)
            if severity_filter:
                alerts = [alert for alert in alerts
                         if alert.get("severity", "").lower() == severity_filter.lower()]
            return alerts[:limit]

    def get_alert_count(self) -> int:
        """Get total number of alerts."""
        with self._alerts_lock:
            return len(self._system_alerts)

    # ─── Log Management ─────────────────────────────────────────────────

    def add_log(self, log_data: Dict[str, Any]) -> None:
        """Add a new log entry to the system (thread-safe)."""
        with self._logs_lock:
            self._historical_logs.appendleft(log_data)

    def get_logs(self, limit: int = 15, source_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get logs from the system (thread-safe)."""
        with self._logs_lock:
            logs = list(self._historical_logs)
            if source_filter:
                logs = [log for log in logs
                       if log.get("source_type") == source_filter]
            return logs[:limit]

    def get_log_count(self) -> int:
        """Get total number of logs."""
        with self._logs_lock:
            return len(self._historical_logs)

    # ─── Simulation Control ─────────────────────────────────────────────

    def start_simulation(self) -> None:
        """Start the log simulation."""
        with self._simulation_lock:
            self.simulation_running = True

    def stop_simulation(self) -> None:
        """Stop the log simulation."""
        with self._simulation_lock:
            self.simulation_running = False

    def is_simulation_running(self) -> bool:
        """Check if simulation is currently running."""
        with self._simulation_lock:
            return self.simulation_running

    # ─── Statistics ─────────────────────────────────────────────────────

    def increment_events_processed(self) -> None:
        """Increment the events processed counter."""
        self.events_processed += 1

    # ─── ML Training ────────────────────────────────────────────────

    async def add_event_for_ml_training(self, event_dict: Dict[str, Any]) -> None:
        """Add event to ML training buffer and potentially retrain."""
        self._ml_training_buffer.append(event_dict)

        # Check if we should retrain
        current_time = time.time()
        if (len(self._ml_training_buffer) >= self._ml_min_samples and
                (current_time - self._ml_last_train_time) > self._ml_retrain_interval):
            await self._retrain_ml_models()

    async def _retrain_ml_models(self) -> None:
        """Retrain ML models with buffered events."""
        if len(self._ml_training_buffer) < self._ml_min_samples:
            return

        print(f"  [ML] Retraining models with {len(self._ml_training_buffer)} samples...")
        success = self.ml_anomaly_detector.train_models(list(self._ml_training_buffer))
        if success:
            self.ml_anomaly_detector.save_models("siem_ml")
            self._ml_last_train_time = time.time()
            print(f"  [ML] Retraining successful and models saved.")
        else:
            print(f"  [ML] Retraining failed - not enough valid samples.")

    def get_uptime(self) -> float:
        """Get application uptime in seconds."""
        return time.time() - self.start_time

    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive application statistics."""
        stats = {
            "uptime_seconds": round(self.get_uptime(), 2),
            "events_processed": self.events_processed,
            "alert_count": self.get_alert_count(),
            "log_count": self.get_log_count(),
            "simulation_running": self.is_simulation_running(),
            "ingestion_stats": self.aggregator.get_stats(),
            "anomaly_baselines": self.anomaly_detector.get_baseline_status(),
            "threat_intel_stats": self.correlator.ti_feed.get_stats(),
        }

        # Add ML anomaly detector stats if available
        if hasattr(self, 'ml_anomaly_detector'):
            stats["ml_anomaly_detector"] = {
                "is_trained": self.ml_anomaly_detector.is_trained,
                "contamination": self.ml_anomaly_detector.contamination,
                "feature_count": len(self.ml_anomaly_detector.feature_names) if self.ml_anomaly_detector.feature_names else 0,
                "last_train_time": self.ml_anomaly_detector.last_train_time,
                "buffer_size": len(self.ml_anomaly_detector.feature_buffer)
            }

        return stats


# Global application state instance (singleton pattern)
app_state = ApplicationState()


def get_application_state() -> ApplicationState:
    """Get the global application state instance."""
    return app_state