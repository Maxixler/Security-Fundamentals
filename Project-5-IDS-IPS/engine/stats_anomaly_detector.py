"""
Statistical Anomaly Detection Engine for IDS/IPS
=================================================

Implements Z-score based anomaly detection with sliding windows
for detecting deviations in network traffic patterns.
"""

import numpy as np
from typing import Dict, List, Any, Optional, Tuple, Deque
from collections import deque
import time
from datetime import datetime


class StatisticalAnomalyDetector:
    """
    Statistical anomaly detection using Z-score with sliding windows.

    Monitors various network metrics and detects anomalies based on
    deviation from established baselines using Z-score analysis.

    Attributes:
        window_size: Size of sliding window for baseline calculation
        threshold: Z-score threshold for anomaly detection
        metrics: Dictionary of metrics being monitored
        baselines: Calculated mean and std for each metric
        history: Historical data for each metric
    """

    def __init__(self,
                 window_size: int = 100,
                 threshold: float = 3.0,
                 update_interval: int = 10):
        """
        Initialize the statistical anomaly detector.

        Args:
            window_size: Number of samples to maintain in sliding window
            threshold: Z-score threshold above which is considered anomalous
            update_interval: How often to recalculate baselines (in samples)
        """
        self.window_size: int = window_size
        self.threshold: float = threshold
        self.update_interval: int = update_interval

        # Metrics to monitor
        self.metrics: Dict[str, Deque[float]] = {
            'packet_rate': deque(maxlen=window_size),      # Packets per second
            'avg_packet_size': deque(maxlen=window_size),  # Average packet size
            'syn_ratio': deque(maxlen=window_size),       # Ratio of SYN packets
            'unique_dst_ports': deque(maxlen=window_size), # Unique destination ports
            'icmp_ratio': deque(maxlen=window_size),      # Ratio of ICMP packets
            'port_scan_score': deque(maxlen=window_size), # Port scan likelihood
        }

        # Baselines (mean, std) for each metric
        self.baselines: Dict[str, Dict[str, float]] = {
            metric: {'mean': 0.0, 'std': 1.0} for metric in self.metrics.keys()
        }

        # History for calculating baselines
        self.history: Dict[str, Deque[float]] = {
            metric: deque(maxlen=window_size*2) for metric in self.metrics.keys()
        }

        # Packet counters for rate calculation
        self.packet_timestamps: Deque[float] = deque(maxlen=window_size)
        self.last_update: float = time.time()
        self.samples_since_update: int = 0

        # Detected anomalies
        self.anomalies: List[Dict[str, Any]] = []

        # Statistics
        self.stats: Dict[str, Any] = {
            'samples_processed': 0,
            'anomalies_detected': 0,
            'baseline_updates': 0,
        }

    def _calculate_baseline(self, metric_name: str) -> Tuple[float, float]:
        """
        Calculate mean and standard deviation for a metric.

        Args:
            metric_name: Name of the metric to calculate baseline for

        Returns:
            Tuple of (mean, std)
        """
        data: List[float] = list(self.history[metric_name])
        if len(data) < 2:
            return 0.0, 1.0

        mean: float = np.mean(data)
        std: float = np.std(data)
        # Avoid division by zero
        if std == 0:
            std = 1.0
        return mean, std

    def _update_baselines(self) -> None:
        """Update baselines for all metrics."""
        for metric_name in self.metrics.keys():
            mean, std = self._calculate_baseline(metric_name)
            self.baselines[metric_name] = {'mean': mean, 'std': std}
        self.stats['baseline_updates'] += 1

    def _detect_anomaly(self, metric_name: str, value: float) -> Tuple[bool, float]:
        """
        Detect if a value is anomalous for a given metric.

        Args:
            metric_name: Name of the metric
            value: Current value to check

        Returns:
            Tuple of (is_anomaly: bool, z_score: float)
        """
        baseline: Dict[str, float] = self.baselines[metric_name]
        if baseline['std'] == 0:
            z_score: float = 0.0
        else:
            z_score: float = abs((value - baseline['mean']) / baseline['std'])

        is_anomaly: bool = z_score > self.threshold
        return is_anomaly, z_score

    def update(self, packet_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Update the detector with a new packet and check for anomalies.

        Args:
            packet_dict: Dictionary representation of a packet

        Returns:
            List of anomaly alerts generated
        """
        current_time: float = time.time()
        self.packet_timestamps.append(current_time)
        self.samples_since_update += 1
        self.stats['samples_processed'] += 1

        # Calculate current metrics
        metrics: Dict[str, float] = self._calculate_current_metrics(packet_dict)

        # Update metric histories and check for anomalies
        anomalies: List[Dict[str, Any]] = []

        for metric_name, value in metrics.items():
            # Add to history
            self.history[metric_name].append(value)
            self.metrics[metric_name].append(value)

            # Check for anomaly
            is_anomaly, z_score = self._detect_anomaly(metric_name, value)
            if is_anomaly:
                anomaly_alert: Dict[str, Any] = {
                    'timestamp': datetime.fromtimestamp(current_time).isoformat(),
                    'metric': metric_name,
                    'value': value,
                    'z_score': z_score,
                    'threshold': self.threshold,
                    'packet_info': {
                        'src_ip': packet_dict.get('src_ip', ''),
                        'dst_ip': packet_dict.get('dst_ip', ''),
                        'protocol': packet_dict.get('protocol', ''),
                        'size': packet_dict.get('size', 0),
                    }
                }
                anomalies.append(anomaly_alert)
                self.anomalies.append(anomaly_alert)
                self.stats['anomalies_detected'] += 1

        # Update baselines if needed
        if self.samples_since_update >= self.update_interval:
            self._update_baselines()
            self.samples_since_update = 0

        return anomalies

    def _calculate_current_metrics(self, packet_dict: Dict[str, Any]) -> Dict[str, float]:
        """
        Calculate current metric values based on recent packets.

        Args:
            packet_dict: Dictionary representation of a packet

        Returns:
            Dictionary of metric names to current values
        """
        metrics: Dict[str, float] = {}
        now: float = time.time()

        # Calculate packet rate (packets per second over last window)
        if len(self.packet_timestamps) >= 2:
            time_span: float = self.packet_timestamps[-1] - self.packet_timestamps[0]
            if time_span > 0:
                metrics['packet_rate']: float = len(self.packet_timestamps) / time_span
            else:
                metrics['packet_rate']: float = len(self.packet_timestamps)
        else:
            metrics['packet_rate']: float = 0.0

        # Average packet size
        if len(self.metrics['avg_packet_size']) > 0:
            metrics['avg_packet_size']: float = np.mean(list(self.metrics['avg_packet_size']))
        else:
            metrics['avg_packet_size']: float = float(packet_dict.get('size', 0))

        # SYN ratio (percentage of SYN packets)
        syn_count: int = sum(1 for p in list(self.metrics.get('syn_ratio', deque())) if p == 1.0)
        total_packets: int = max(len(self.metrics.get('syn_ratio', deque())), 1)
        metrics['syn_ratio']: float = syn_count / total_packets if total_packets > 0 else 0.0

        # Unique destination ports (normalized to 0-1 range)
        # For simplicity, we'll use a heuristic based on port diversity
        dst_port: int = packet_dict.get('dst_port', 0)
        # In a real implementation, we'd track unique ports over time
        metrics['unique_dst_ports']: float = min(dst_port / 65535.0, 1.0) if dst_port > 0 else 0.0

        # ICMP ratio
        icmp_count: int = sum(1 for p in list(self.metrics.get('icmp_ratio', deque())) if p == 1.0)
        total_packets_icmp: int = max(len(self.metrics.get('icmp_ratio', deque())), 1)
        metrics['icmp_ratio']: float = icmp_count / total_packets_icmp if total_packets_icmp > 0 else 0.0

        # Port scan score (heuristic based on port patterns)
        flags: str = packet_dict.get('flags', '')
        dst_port: int = packet_dict.get('dst_port', 0)
        # Simple heuristic: SYN to high ports suggests scanning
        if flags == 'SYN' and dst_port > 1024:
            metrics['port_scan_score']: float = 0.8
        elif flags == 'SYN':
            metrics['port_scan_score']: float = 0.2
        else:
            metrics['port_scan_score']: float = 0.0

        return metrics

    def get_stats(self) -> Dict[str, Any]:
        """
        Get detector statistics.

        Returns:
            Dictionary of statistics and current baselines
        """
        stats: Dict[str, Any] = self.stats.copy()
        stats['baselines']: Dict[str, Dict[str, float]] = self.baselines.copy()
        stats['recent_anomalies']: List[Dict[str, Any]] = self.anomalies[-10:] if self.anomalies else []
        return stats

    def reset(self) -> None:
        """Reset the detector to initial state."""
        self.__init__(
            window_size=self.window_size,
            threshold=self.threshold,
            update_interval=self.update_interval
        )