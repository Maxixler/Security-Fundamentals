import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.detection.stats_anomaly_detector import StatisticalAnomalyDetector

def test_stats_detector_initialization():
    """Test that the statistical detector initializes correctly."""
    detector = StatisticalAnomalyDetector()
    assert detector is not None
    assert hasattr(detector, 'metrics')
    assert hasattr(detector, 'baselines')
    assert hasattr(detector, 'stats')

def test_stats_detector_update():
    """Test updating the detector with packets."""
    detector = StatisticalAnomalyDetector()

    # Test with normal packet
    normal_packet = {
        'packet_id': 'test1',
        'timestamp': '2023-01-01T12:00:00',
        'protocol': 'TCP',
        'src_ip': '10.0.0.1',
        'dst_ip': '10.0.0.2',
        'src_port': 12345,
        'dst_port': 80,
        'flags': 'PSH-ACK',
        'payload': 'GET / HTTP/1.1',
        'size': 150,
        'ttl': 64,
        'metadata': {}
    }

    anomalies = detector.update(normal_packet)
    # Should not detect anomalies with just one packet
    assert isinstance(anomalies, list)
    assert detector.stats['samples_processed'] == 1

def test_stats_detector_multiple_packets():
    """Test detector with multiple packets."""
    detector = StatisticalAnomalyDetector()

    # Add several normal packets
    for i in range(5):
        packet = {
            'packet_id': f'test{i}',
            'timestamp': '2023-01-01T12:00:00',
            'protocol': 'TCP',
            'src_ip': '10.0.0.1',
            'dst_ip': '10.0.0.2',
            'src_port': 12345 + i,
            'dst_port': 80,
            'flags': 'PSH-ACK',
            'payload': 'GET / HTTP/1.1',
            'size': 100 + i*10,
            'ttl': 64,
            'metadata': {}
        }
        detector.update(packet)

    assert detector.stats['samples_processed'] == 5

def test_stats_detector_baseline_calculation():
    """Test that baselines are calculated correctly."""
    detector = StatisticalAnomalyDetector(window_size=5, update_interval=3)

    # Add packets to trigger baseline calculation
    for i in range(10):
        packet = {
            'packet_id': f'test{i}',
            'timestamp': '2023-01-01T12:00:00',
            'protocol': 'TCP',
            'src_ip': '10.0.0.1',
            'dst_ip': '10.0.0.2',
            'src_port': 12345,
            'dst_port': 80,
            'flags': 'PSH-ACK',
            'payload': 'GET / HTTP/1.1',
            'size': 100,
            'ttl': 64,
            'metadata': {}
        }
        detector.update(packet)

    # Check that baselines have been updated
    assert detector.stats['baseline_updates'] > 0
    # Check that we have some baseline values
    assert detector.baselines['packet_rate']['mean'] >= 0

def test_stats_detector_reset():
    """Test resetting the detector."""
    detector = StatisticalAnomalyDetector()

    # Add some data
    packet = {
        'packet_id': 'test1',
        'timestamp': '2023-01-01T12:00:00',
        'protocol': 'TCP',
        'src_ip': '10.0.0.1',
        'dst_ip': '10.0.0.2',
        'src_port': 12345,
        'dst_port': 80,
        'flags': 'PSH-ACK',
        'payload': 'GET / HTTP/1.1',
        'size': 150,
        'ttl': 64,
        'metadata': {}
    }
    detector.update(packet)
    initial_samples = detector.stats['samples_processed']

    # Reset
    detector.reset()

    # Should be reset to initial state
    assert detector.stats['samples_processed'] == 0
    assert len(detector.anomalies) == 0

if __name__ == "__main__":
    # Run tests manually if executed directly
    test_stats_detector_initialization()
    print("✓ Statistical detector initialization test passed")

    test_stats_detector_update()
    print("✓ Update test passed")

    test_stats_detector_multiple_packets()
    print("✓ Multiple packets test passed")

    test_stats_detector_baseline_calculation()
    print("✓ Baseline calculation test passed")

    test_stats_detector_reset()
    print("✓ Reset test passed")

    print("\nAll tests passed! 🎉")