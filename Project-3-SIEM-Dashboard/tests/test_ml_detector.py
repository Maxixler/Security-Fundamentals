import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from siem.ml_anomaly_detector import get_ml_anomaly_detector


def test_ml_detector_initialization():
    """Test ML detector initializes correctly"""
    detector = get_ml_anomaly_detector()
    assert detector is not None
    assert hasattr(detector, 'models')
    assert hasattr(detector, 'scalers')
    assert hasattr(detector, 'feature_names')
    assert detector.is_trained == False  # Should not be trained initially


def test_ml_detector_feature_extraction():
    """Test feature extraction from events"""
    detector = get_ml_anomaly_detector()

    # Test event
    event = {
        'severity': 5,
        'src_ip': '192.168.1.1',
        'dst_ip': '10.0.0.1',
        'src_port': 12345,
        'dst_port': 80,
        'protocol': 'TCP',
        'action': 'GET',
        'event_type': 'web_request',
        'source_type': 'web_server',
        'username': 'admin',
        'metadata': {
            'status_code': 200,
            'bytes': 1024
        },
        'timestamp': '2026-06-01T12:00:00'
    }

    # Extract features
    features = detector._extract_features(event)
    assert features is not None
    assert features.shape == (1, 17)  # Should have 17 features
    assert len(detector.feature_names) == 17


def test_ml_detector_training_with_insufficient_data():
    """Test training fails gracefully with insufficient data"""
    detector = get_ml_anomaly_detector()
    # Temporarily reduce minimum for testing
    original_min = detector.min_samples_for_training
    detector.min_samples_for_training = 10

    # Try to train with insufficient data
    events = [{'event_id': f'test_{i}'} for i in range(5)]  # Only 5 events
    success = detector.train_models(events)
    assert success == False  # Should fail with insufficient data

    # Restore original value
    detector.min_samples_for_training = original_min


def test_ml_detector_prediction_untrained():
    """Test prediction returns False when not trained"""
    detector = get_ml_anomaly_detector()
    # Ensure detector is not trained
    detector.is_trained = False

    event = {
        'severity': 5,
        'src_ip': '192.168.1.1',
        'dst_ip': '10.0.0.1',
        'src_port': 12345,
        'dst_port': 80,
        'protocol': 'TCP',
        'action': 'GET',
        'event_type': 'web_request',
        'source_type': 'web_server',
        'username': 'admin',
        'metadata': {
            'status_code': 200,
            'bytes': 1024
        },
        'timestamp': '2026-06-01T12:00:00'
    }

    is_anomaly, confidence, details = detector.predict_anomaly(event)
    assert is_anomaly == False
    assert confidence == 0.0
    assert details.get('reason') == 'models_not_trained'


def test_ml_detector_save_load_models():
    """Test saving and loading models works"""
    detector = get_ml_anomaly_detector()

    # Create minimal training data
    events = []
    for i in range(15):  # Just enough for testing
        event = {
            'event_id': f'train_{i}',
            'timestamp': f'2026-06-01T{(i % 24):02d}:{(i % 60):02d}:{(i % 60):02d}',
            'source_type': 'web_server',
            'event_type': 'web_request',
            'severity': (i % 5) + 1,
            'src_ip': f'10.0.{(i // 10) % 3}.{(i % 10) + 1}',
            'dst_ip': f'10.0.{(i // 10) % 3 + 3}.{(i % 10) + 1}',
            'src_port': 1024 + (i % 60000),
            'dst_port': 80 if (i % 3 == 0) else 443,
            'protocol': 'TCP' if (i % 2 == 0) else 'UDP',
            'action': 'GET',
            'username': 'admin' if i % 5 == 0 else '',
            'hostname': f'host{(i % 10) + 1}',
            'description': f'Training event {i}',
            'raw_log': f'2026-06-01T{(i % 24):02d}:{(i % 60):02d}:{(i % 60):02d} [WEB_SERVER] GET SRC=10.0.{(i // 10) % 3}.{(i % 10) + 1} DST=10.0.{(i // 10) % 3 + 3}.{(i % 10) + 1}',
            'metadata': {
                'bytes': 1000 + (i % 9000),
                'status_code': 200 if (i % 5 == 0) else 404
            }
        }
        events.append(event)

    # Temporarily reduce minimum for testing
    original_min = detector.min_samples_for_training
    detector.min_samples_for_training = 10

    # Train models
    success = detector.train_models(events)
    assert success == True
    assert detector.is_trained == True

    # Save models
    detector.save_models("test_save_load")

    # Create new detector and load models
    detector2 = get_ml_anomaly_detector()
    detector2.min_samples_for_training = 10  # Match training threshold
    load_success = detector2.load_models("test_save_load")
    assert load_success == True
    assert detector2.is_trained == True

    # Test that loaded model works
    test_event = events[0]
    is_anomaly, confidence, details = detector2.predict_anomaly(test_event)
    assert isinstance(is_anomaly, bool)
    assert isinstance(confidence, float)
    assert isinstance(details, dict)

    # Restore original value
    detector.min_samples_for_training = original_min