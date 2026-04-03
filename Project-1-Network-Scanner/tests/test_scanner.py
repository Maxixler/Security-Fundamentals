"""
Tests for Network Scanner modules.
Run with: python -m pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.ip_utils import (
    validate_ip, validate_cidr, parse_target, 
    get_subnet_info, get_service_name, get_local_ip,
    ip_to_int, int_to_ip
)
from scanner.host_discovery import HostDiscovery
from scanner.port_scanner import PortScanner


class TestIPUtils:
    """Tests for IP utility functions."""

    def test_validate_ip_valid(self):
        assert validate_ip("192.168.1.1") is True
        assert validate_ip("10.0.0.1") is True
        assert validate_ip("0.0.0.0") is True
        assert validate_ip("255.255.255.255") is True

    def test_validate_ip_invalid(self):
        assert validate_ip("256.1.1.1") is False
        assert validate_ip("abc") is False
        assert validate_ip("192.168.1") is False
        assert validate_ip("") is False

    def test_validate_cidr(self):
        assert validate_cidr("192.168.1.0/24") is True
        assert validate_cidr("10.0.0.0/8") is True
        assert validate_cidr("invalid") is False

    def test_parse_target_single_ip(self):
        result = parse_target("192.168.1.1")
        assert result == ["192.168.1.1"]

    def test_parse_target_cidr(self):
        result = parse_target("192.168.1.0/30")
        assert len(result) == 2  # /30 has 2 usable hosts
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result

    def test_parse_target_range(self):
        result = parse_target("192.168.1.1-5")
        assert len(result) == 5
        assert "192.168.1.1" in result
        assert "192.168.1.5" in result

    def test_parse_target_comma_separated(self):
        result = parse_target("192.168.1.1,192.168.1.2,192.168.1.3")
        assert len(result) == 3

    def test_parse_target_invalid(self):
        result = parse_target("invalid_target_xyz")
        assert result == []

    def test_subnet_info(self):
        info = get_subnet_info("192.168.1.0/24")
        assert info["network_address"] == "192.168.1.0"
        assert info["broadcast_address"] == "192.168.1.255"
        assert info["subnet_mask"] == "255.255.255.0"
        assert info["usable_hosts"] == 254
        assert info["prefix_length"] == 24
        assert info["is_private"] is True
        assert info["network_class"] == "C"

    def test_subnet_info_class_a(self):
        info = get_subnet_info("10.0.0.0/8")
        assert info["network_class"] == "A"
        assert info["usable_hosts"] == 16777214

    def test_service_name_known(self):
        name, desc = get_service_name(80)
        assert name == "HTTP"
        
        name, desc = get_service_name(22)
        assert name == "SSH"
        
        name, desc = get_service_name(502)
        assert name == "Modbus"

    def test_service_name_unknown(self):
        name, desc = get_service_name(59999)
        assert name == "Unknown"

    def test_ip_int_conversion(self):
        ip = "192.168.1.1"
        ip_int = ip_to_int(ip)
        assert int_to_ip(ip_int) == ip

    def test_get_local_ip(self):
        ip = get_local_ip()
        assert validate_ip(ip) is True


class TestHostDiscovery:
    """Tests for host discovery module."""

    def test_tcp_ping_localhost(self):
        hd = HostDiscovery(timeout=2.0)
        result = hd.tcp_ping("127.0.0.1")
        # Localhost should always be up
        assert result["ip"] == "127.0.0.1"
        assert result["alive"] is True

    def test_tcp_ping_invalid(self):
        hd = HostDiscovery(timeout=0.5)
        # RFC 5737 TEST-NET, should not respond
        result = hd.tcp_ping("192.0.2.1")
        assert result["alive"] is False

    def test_scan_network_single(self):
        hd = HostDiscovery(timeout=2.0)
        results = hd.scan_network(["127.0.0.1"])
        assert len(results) >= 1
        assert results[0]["ip"] == "127.0.0.1"


class TestPortScanner:
    """Tests for port scanner module."""

    def test_scan_profiles_exist(self):
        ps = PortScanner()
        assert "quick" in ps.SCAN_PROFILES
        assert "common" in ps.SCAN_PROFILES
        assert "top100" in ps.SCAN_PROFILES
        assert "full" in ps.SCAN_PROFILES

    def test_ot_ports_defined(self):
        ps = PortScanner()
        assert 502 in ps.OT_PORTS  # Modbus
        assert 47808 in ps.OT_PORTS  # BACnet

    def test_scan_closed_port(self):
        ps = PortScanner(timeout=1.0)
        # Port that's very likely closed
        result = ps.tcp_connect_scan("127.0.0.1", 19)
        assert result["port"] == 19
        assert result["state"] in ("closed", "filtered", "error")


if __name__ == "__main__":
    # Simple test runner without pytest
    print("Running tests...\n")
    
    test_classes = [TestIPUtils, TestHostDiscovery, TestPortScanner]
    passed = 0
    failed = 0
    
    for cls in test_classes:
        instance = cls()
        print(f"--- {cls.__name__} ---")
        for method_name in dir(instance):
            if method_name.startswith("test_"):
                try:
                    getattr(instance, method_name)()
                    print(f"  [PASS] {method_name}")
                    passed += 1
                except Exception as e:
                    print(f"  [FAIL] {method_name}: {e}")
                    failed += 1
        print()
    
    print(f"\nResults: {passed} passed, {failed} failed")
