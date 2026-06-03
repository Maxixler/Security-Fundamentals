"""
Test script to train ML detector with sufficient data
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from siem.ml_anomaly_detector import get_ml_anomaly_detector

def train_and_test_ml_detector():
    """Train and test the ML anomaly detector with sufficient data."""
    print("Testing ML Anomaly Detector with sufficient training data...")

    # Get detector instance with lower threshold for testing
    detector = get_ml_anomaly_detector()
    # Override to require fewer samples for testing
    detector.min_samples_for_training = 20

    # Create sample normal events (more diverse)
    normal_events = []
    for i in range(100):
        # Vary the event types to create a realistic baseline
        event_types = ['network_traffic', 'web_request', 'dns_query', 'failed_logon', 'successful_logon']
        sources = ['firewall', 'web_server', 'dns', 'active_directory']
        actions = ['ALLOW', 'DENY', 'GET', 'POST', 'QUERY', 'FAILURE', 'SUCCESS']

        event = {
            'event_id': f'train_{i}',
            'timestamp': f'2026-06-01T{(i % 24):02d}:{(i % 60):02d}:{(i % 60):02d}',
            'source_type': sources[i % len(sources)],
            'event_type': event_types[i % len(event_types)],
            'severity': (i % 5) + 1,  # 1-5 severity
            'src_ip': f'10.0.{(i // 10) % 3}.{(i % 10) + 1}',
            'dst_ip': f'10.0.{(i // 10) % 3 + 3}.{(i % 10) + 1}',
            'src_port': 1024 + (i % 60000),
            'dst_port': 80 if (i % 3 == 0) else 443 if (i % 3 == 1) else 53,
            'protocol': 'TCP' if (i % 2 == 0) else 'UDP',
            'action': actions[i % len(actions)],
            'username': 'admin' if i % 5 == 0 else '',
            'hostname': f'host{(i % 10) + 1}',
            'description': f'Normal training event {i}',
            'raw_log': f'2026-06-01T{(i % 24):02d}:{(i % 60):02d}:{(i % 60):02d} [{sources[i % len(sources)].upper()}] {actions[i % len(actions)]} SRC=10.0.{(i // 10) % 3}.{(i % 10) + 1} DST=10.0.{(i // 10) % 3 + 3}.{(i % 10) + 1}',
            'metadata': {
                'bytes': 1000 + (i % 9000),
                'status_code': 200 if (i % 5 == 0) else 404 if (i % 5 == 1) else 500 if (i % 5 == 2) else 301 if (i % 5 == 3) else 302
            }
        }
        normal_events.append(event)

    # Train on normal events
    print(f"Training on {len(normal_events)} normal events...")
    success = detector.train_models(normal_events)
    print(f"Training success: {success}")
    print(f"Is trained: {detector.is_trained}")
    if detector.is_trained:
        print(f"Feature names: {detector.feature_names}")
        print(f"Number of features: {len(detector.feature_names)}")

    # Create sample anomalous events
    anomalous_events = []
    for i in range(10):
        event = {
            'event_id': f'anom_test_{i}',
            'timestamp': '2026-06-01T12:00:00',
            'source_type': 'firewall',
            'event_type': 'network_traffic',
            'severity': 9,  # High severity
            'src_ip': f'45.2.3.{i + 10}',  # Known bad IP range (external)
            'dst_ip': f'10.0.0.{i + 1}',
            'src_port': 12345,
            'dst_port': 3389,  # RDP port (suspicious)
            'protocol': 'TCP',
            'action': 'DENY',
            'username': '',
            'hostname': 'external_host',
            'description': f'Malicious traffic {i}',
            'raw_log': f'2026-06-01 12:00:00 [FIREWALL] DENY SRC=45.2.3.{i + 10} DST=10.0.0.{i + 1} DPORT=3389',
            'metadata': {
                'bytes': 50000,  # Large transfer
                'status_code': 0
            }
        }
        anomalous_events.append(event)

    # Test predictions
    print("\nTesting predictions on normal events:")
    normal_anomaly_count = 0
    for i, event in enumerate(normal_events[:10]):
        is_anomaly, confidence, details = detector.predict_anomaly(event)
        if is_anomaly:
            normal_anomaly_count += 1
        print(f"  Normal Event {i}: Anomaly={is_anomaly}, Confidence={confidence:.2f}")

    print("\nTesting predictions on anomalous events:")
    anomaly_detected_count = 0
    for i, event in enumerate(anomalous_events):
        is_anomaly, confidence, details = detector.predict_anomaly(event)
        if is_anomaly:
            anomaly_detected_count += 1
        print(f"  Anomalous Event {i}: Anomaly={is_anomaly}, Confidence={confidence:.2f}")
        if is_anomaly and details:
            print(f"    Details: {details.get('ensemble_vote', 'N/A')}")

    print(f"\nResults:")
    print(f"  Normal events flagged as anomalous: {normal_anomaly_count}/10")
    print(f"  Anomalous events correctly detected: {anomaly_detected_count}/10")

    # Test model saving/loading
    print("\nTesting model persistence...")
    detector.save_models("test_training")

    # Create new detector and load models
    detector2 = get_ml_anomaly_detector()
    detector2.min_samples_for_training = 20  # Match the training threshold
    success = detector2.load_models("test_training")
    if success:
        print("Model loading successful!")
        # Test with loaded model
        is_anomaly, confidence, details = detector2.predict_anomaly(anomalous_events[0])
        print(f"Loaded model test: Anomaly={is_anomaly}, Confidence={confidence:.2f}")
    else:
        print("Model loading failed!")

if __name__ == "__main__":
    train_and_test_ml_detector()