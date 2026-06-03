"""
Test script for ML Anomaly Detector
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from siem.ml_anomaly_detector import get_ml_anomaly_detector

def test_ml_detector():
    """Test the ML anomaly detector with sample events."""
    print("Testing ML Anomaly Detector...")

    # Get detector instance
    detector = get_ml_anomaly_detector()

    # Create sample normal events
    normal_events = []
    for i in range(50):
        event = {
            'event_id': f'test_{i}',
            'timestamp': '2026-06-01T10:00:00',
            'source_type': 'firewall',
            'event_type': 'network_traffic',
            'severity': 4,
            'src_ip': f'10.0.0.{i % 10 + 1}',
            'dst_ip': f'10.0.1.{i % 10 + 1}',
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 'TCP',
            'action': 'ALLOW',
            'username': '',
            'hostname': '',
            'description': f'Normal traffic {i}',
            'raw_log': f'2026-06-01 10:00:00 [FIREWALL] ALLOW SRC=10.0.0.{i % 10 + 1} DST=10.0.1.{i % 10 + 1} DPORT=80',
            'metadata': {}
        }
        normal_events.append(event)

    # Create sample anomalous events
    anomalous_events = []
    for i in range(5):
        event = {
            'event_id': f'anom_{i}',
            'timestamp': '2026-06-01T10:00:00',
            'source_type': 'firewall',
            'event_type': 'network_traffic',
            'severity': 9,  # High severity
            'src_ip': f'45.2.3.{i + 10}',  # Known bad IP range
            'dst_ip': f'10.0.0.{i + 1}',
            'src_port': 12345,
            'dst_port': 3389,  # RDP port
            'protocol': 'TCP',
            'action': 'DENY',
            'username': '',
            'hostname': '',
            'description': f'Malicious traffic {i}',
            'raw_log': f'2026-06-01 10:00:00 [FIREWALL] DENY SRC=45.2.3.{i + 10} DST=10.0.0.{i + 1} DPORT=3389',
            'metadata': {}
        }
        anomalous_events.append(event)

    # Train on normal events
    print(f"Training on {len(normal_events)} normal events...")
    detector.train_models(normal_events)

    # Test predictions
    print("\nTesting predictions:")
    print("Normal events:")
    for i, event in enumerate(normal_events[:5]):
        is_anomaly, confidence, details = detector.predict_anomaly(event)
        print(f"  Event {i}: Anomaly={is_anomaly}, Confidence={confidence:.2f}")

    print("\nAnomalous events:")
    for i, event in enumerate(anomalous_events):
        is_anomaly, confidence, details = detector.predict_anomaly(event)
        print(f"  Event {i}: Anomaly={is_anomaly}, Confidence={confidence:.2f}")

    # Test model saving/loading
    print("\nTesting model persistence...")
    detector.save_models("test")

    # Create new detector and load models
    detector2 = get_ml_anomaly_detector()
    success = detector2.load_models("test")
    if success:
        print("Model loading successful!")
        # Test with loaded model
        is_anomaly, confidence, details = detector2.predict_anomaly(anomalous_events[0])
        print(f"Loaded model test: Anomaly={is_anomaly}, Confidence={confidence:.2f}")
    else:
        print("Model loading failed!")

if __name__ == "__main__":
    test_ml_detector()