import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from siem.application import ApplicationState
from siem.log_aggregator import NormalizedEvent


def test_application_state_initialization():
    """Test ApplicationState initializes correctly"""
    app_state = ApplicationState()
    assert app_state is not None
    assert hasattr(app_state, 'aggregator')
    assert hasattr(app_state, 'correlator')
    assert hasattr(app_state, 'anomaly_detector')
    assert hasattr(app_state, 'ml_anomaly_detector')
    assert app_state.simulation_running == False
    assert app_state.events_processed == 0


def test_application_state_alert_management():
    """Test alert management functions"""
    app_state = ApplicationState(max_alerts=10)

    # Test adding alerts
    alert_data = {
        "id": "INC-000001",
        "timestamp": "2026-06-01T12:00:00",
        "severity": "High",
        "description": "Test alert",
        "attack_type": "brute_force",
        "src_ip": "45.2.3.11",
        "target": "admin",
        "source": "active_directory",
        "country": "CN",
        "mitre": {"tactic": "Credential Access", "technique": "T1110"},
        "status": "new",
        "event_count": 1
    }

    app_state.add_alert(alert_data)
    assert app_state.get_alert_count() == 1

    alerts = app_state.get_alerts(limit=5)
    assert len(alerts) == 1
    assert alerts[0]["id"] == "INC-000001"
    assert alerts[0]["severity"] == "High"


def test_application_state_log_management():
    """Test log management functions"""
    app_state = ApplicationState(max_logs=10)

    # Test adding logs
    log_data = {
        "event_id": "test-event-001",
        "timestamp": "2026-06-01T12:00:00",
        "source_type": "firewall",
        "event_type": "network_traffic",
        "severity": 5,
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 12345,
        "dst_port": 80,
        "protocol": "TCP",
        "action": "ALLOW",
        "username": "",
        "hostname": "server1",
        "description": "Test firewall log",
        "raw_log": "2026-06-01 12:00:00 [FIREWALL] ALLOW SRC=192.168.1.100 DST=10.0.0.1 DPORT=80",
        "metadata": {}
    }

    app_state.add_log(log_data)
    assert app_state.get_log_count() == 1

    logs = app_state.get_logs(limit=5)
    assert len(logs) == 1
    assert logs[0]["event_id"] == "test-event-001"
    assert logs[0]["source_type"] == "firewall"


def test_application_state_simulation_control():
    """Test simulation control functions"""
    app_state = ApplicationState()

    # Initially not running
    assert app_state.is_simulation_running() == False

    # Start simulation
    app_state.start_simulation()
    assert app_state.is_simulation_running() == True

    # Stop simulation
    app_state.stop_simulation()
    assert app_state.is_simulation_running() == False


def test_application_state_events_processed():
    """Test events processed counter"""
    app_state = ApplicationState()
    initial_count = app_state.events_processed

    # Increment counter
    app_state.increment_events_processed()
    assert app_state.events_processed == initial_count + 1

    # Increment multiple times
    for _ in range(5):
        app_state.increment_events_processed()
    assert app_state.events_processed == initial_count + 6


def test_application_state_ml_training_buffer():
    """Test ML training buffer functionality"""
    app_state = ApplicationState()

    # Add event to ML training buffer
    event_dict = {
        "event_id": "test-event-001",
        "timestamp": "2026-06-01T12:00:00",
        "source_type": "firewall",
        "event_type": "network_traffic",
        "severity": 5,
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "description": "Test event",
        "raw_log": "test log",
        "metadata": {}
    }

    # This should not trigger retraining (not enough samples)
    initial_buffer_size = len(app_state._ml_training_buffer)
    app_state.add_event_for_ml_training(event_dict)
    assert len(app_state._ml_training_buffer) == initial_buffer_size + 1

    # Add many events to test retraining logic (would need to mock time)
    # We'll just verify the buffer works
    for i in range(10):
        event_dict["event_id"] = f"test-event-{i}"
        app_state.add_event_for_ml_training(event_dict)

    assert len(app_state._ml_training_buffer) > 10


def test_application_state_stats():
    """Test statistics gathering"""
    app_state = ApplicationState()

    stats = app_state.get_stats()
    assert isinstance(stats, dict)
    assert "uptime_seconds" in stats
    assert "events_processed" in stats
    assert "alert_count" in stats
    assert "log_count" in stats
    assert "simulation_running" in stats
    assert "ingestion_stats" in stats
    assert "anomaly_baselines" in stats
    assert "threat_intel_stats" in stats
    assert "ml_anomaly_detector" in stats