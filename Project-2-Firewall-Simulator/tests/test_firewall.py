"""Tests for Firewall Simulator modules."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from firewall.packet_parser import Packet, PacketParser, Protocol
from firewall.rule_engine import RuleEngine, FirewallRule
from firewall.stateful_tracker import StatefulTracker, ConnectionState
from firewall.zone_manager import ZoneManager
from firewall.firewall_engine import FirewallEngine
from firewall.traffic_generator import TrafficGenerator


class TestPacketParser:
    def test_from_dict(self):
        pkt = PacketParser.from_dict({"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "protocol": "TCP", "src_port": 1234, "dst_port": 80})
        assert pkt.src_ip == "10.0.0.1"
        assert pkt.dst_port == 80
        assert pkt.protocol == Protocol.TCP

    def test_ip_in_network(self):
        assert PacketParser.ip_in_network("192.168.1.5", "192.168.1.0/24") is True
        assert PacketParser.ip_in_network("192.168.2.5", "192.168.1.0/24") is False
        assert PacketParser.ip_in_network("10.10.1.1", "10.10.0.0/16") is True
        assert PacketParser.ip_in_network("1.2.3.4", "any") is True

    def test_validate_ip(self):
        assert PacketParser.validate_ip("192.168.1.1") is True
        assert PacketParser.validate_ip("192.168.1.0/24") is True
        assert PacketParser.validate_ip("invalid") is False


class TestRuleEngine:
    def test_add_and_evaluate(self):
        engine = RuleEngine(default_policy="DENY")
        engine.add_rule(FirewallRule(priority=100, action="ALLOW", protocol="TCP", dst_port=80))
        pkt = Packet(src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol=Protocol.TCP, src_port=5000, dst_port=80)
        assert engine.evaluate(pkt) == "ALLOW"

    def test_default_deny(self):
        engine = RuleEngine(default_policy="DENY")
        pkt = Packet(src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol=Protocol.TCP, src_port=5000, dst_port=9999)
        assert engine.evaluate(pkt) == "DENY"

    def test_priority_order(self):
        engine = RuleEngine(default_policy="DENY")
        engine.add_rule(FirewallRule(priority=200, action="ALLOW", protocol="TCP", dst_port=22))
        engine.add_rule(FirewallRule(priority=100, action="DENY", protocol="TCP", dst_port=22))
        pkt = Packet(protocol=Protocol.TCP, dst_port=22)
        # Priority 100 (DENY) should match first
        assert engine.evaluate(pkt) == "DENY"

    def test_cidr_matching(self):
        engine = RuleEngine(default_policy="DENY")
        engine.add_rule(FirewallRule(priority=100, action="ALLOW", src_ip="192.168.1.0/24", dst_port=443))
        pkt = Packet(src_ip="192.168.1.50", dst_ip="8.8.8.8", protocol=Protocol.TCP, dst_port=443)
        assert engine.evaluate(pkt) == "ALLOW"
        pkt2 = Packet(src_ip="10.0.0.1", dst_ip="8.8.8.8", protocol=Protocol.TCP, dst_port=443)
        assert engine.evaluate(pkt2) == "DENY"

    def test_protocol_filter(self):
        engine = RuleEngine(default_policy="DENY")
        engine.add_rule(FirewallRule(priority=100, action="ALLOW", protocol="UDP", dst_port=53))
        tcp_pkt = Packet(protocol=Protocol.TCP, dst_port=53)
        udp_pkt = Packet(protocol=Protocol.UDP, dst_port=53)
        assert engine.evaluate(tcp_pkt) == "DENY"
        assert engine.evaluate(udp_pkt) == "ALLOW"

    def test_hit_count(self):
        engine = RuleEngine()
        rule = engine.add_rule(FirewallRule(priority=100, action="ALLOW", dst_port=80))
        pkt = Packet(protocol=Protocol.TCP, dst_port=80)
        engine.evaluate(pkt)
        engine.evaluate(pkt)
        assert rule.hit_count == 2

    def test_remove_rule(self):
        engine = RuleEngine()
        rule = engine.add_rule(FirewallRule(priority=100, action="ALLOW", name="test"))
        assert engine.remove_rule(rule.rule_id) is True
        assert len(engine.rules) == 0

    def test_save_and_load(self):
        engine = RuleEngine()
        engine.add_rule(FirewallRule(priority=100, action="ALLOW", name="saved_rule", dst_port=8080))
        path = os.path.join(os.path.dirname(__file__), "test_rules.json")
        engine.save_rules(path)
        engine2 = RuleEngine()
        engine2.load_rules(path)
        assert len(engine2.rules) == 1
        assert engine2.rules[0].name == "saved_rule"
        os.remove(path)


class TestStatefulTracker:
    def test_new_tcp_connection(self):
        tracker = StatefulTracker()
        pkt = Packet(src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol=Protocol.TCP,
                     src_port=5000, dst_port=80, tcp_flags=["SYN"])
        state = tracker.track_packet(pkt)
        assert state == ConnectionState.NEW

    def test_tcp_handshake(self):
        tracker = StatefulTracker()
        # SYN
        syn = Packet(src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol=Protocol.TCP,
                     src_port=5000, dst_port=80, tcp_flags=["SYN"])
        assert tracker.track_packet(syn) == ConnectionState.NEW
        # SYN-ACK
        syn_ack = Packet(src_ip="2.2.2.2", dst_ip="1.1.1.1", protocol=Protocol.TCP,
                         src_port=80, dst_port=5000, tcp_flags=["SYN", "ACK"])
        assert tracker.track_packet(syn_ack) == ConnectionState.SYN_RECV
        # ACK
        ack = Packet(src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol=Protocol.TCP,
                     src_port=5000, dst_port=80, tcp_flags=["ACK"])
        assert tracker.track_packet(ack) == ConnectionState.ESTABLISHED

    def test_invalid_non_syn_first(self):
        tracker = StatefulTracker()
        pkt = Packet(src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol=Protocol.TCP,
                     src_port=5000, dst_port=80, tcp_flags=["ACK"])
        state = tracker.track_packet(pkt)
        assert state == ConnectionState.INVALID

    def test_udp_tracking(self):
        tracker = StatefulTracker()
        pkt = Packet(src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol=Protocol.UDP,
                     src_port=5000, dst_port=53)
        state = tracker.track_packet(pkt)
        assert state == ConnectionState.NEW


class TestZoneManager:
    def test_zone_lookup(self):
        zm = ZoneManager()
        assert zm.get_zone_for_ip("192.168.1.10") == "trusted"
        assert zm.get_zone_for_ip("10.10.1.20") == "ot_network"
        assert zm.get_zone_for_ip("172.16.0.10") == "dmz"
        assert zm.get_zone_for_ip("10.0.0.5") == "management"
        assert zm.get_zone_for_ip("8.8.8.8") == "untrusted"

    def test_zone_policy(self):
        zm = ZoneManager()
        assert zm.get_policy("untrusted", "ot_network") == "DENY"
        assert zm.get_policy("trusted", "untrusted") == "ALLOW"
        assert zm.get_policy("trusted", "trusted") == "ALLOW"
        assert zm.get_policy("management", "ot_network") == "ALLOW"

    def test_zone_matrix(self):
        zm = ZoneManager()
        matrix = zm.get_zone_matrix()
        assert "trusted" in matrix
        assert matrix["trusted"]["trusted"] == "SELF"


class TestFirewallEngine:
    def test_full_pipeline(self):
        rules_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules", "default_rules.json")
        fw = FirewallEngine(rules_file=rules_path)
        # Allowed: internal HTTPS
        pkt = Packet(src_ip="192.168.1.10", dst_ip="8.8.8.8", protocol=Protocol.TCP,
                     src_port=5000, dst_port=443, tcp_flags=["SYN"], direction="OUTBOUND")
        result = fw.process_packet(pkt)
        assert result["action"] == "ALLOW"

    def test_block_telnet(self):
        rules_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules", "default_rules.json")
        fw = FirewallEngine(rules_file=rules_path)
        pkt = Packet(src_ip="8.8.8.8", dst_ip="192.168.1.10", protocol=Protocol.TCP,
                     src_port=5000, dst_port=23, tcp_flags=["SYN"], direction="INBOUND")
        result = fw.process_packet(pkt)
        assert result["action"] == "DENY"

    def test_block_it_to_ot_modbus(self):
        rules_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules", "default_rules.json")
        fw = FirewallEngine(rules_file=rules_path)
        pkt = Packet(src_ip="192.168.1.10", dst_ip="10.10.1.20", protocol=Protocol.TCP,
                     src_port=5000, dst_port=502, tcp_flags=["SYN"], direction="FORWARD")
        result = fw.process_packet(pkt)
        assert result["action"] == "DENY"

    def test_allow_ot_internal_modbus(self):
        rules_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules", "default_rules.json")
        fw = FirewallEngine(rules_file=rules_path)
        pkt = Packet(src_ip="10.10.1.10", dst_ip="10.10.2.200", protocol=Protocol.TCP,
                     src_port=5000, dst_port=502, tcp_flags=["SYN"], direction="ANY")
        result = fw.process_packet(pkt)
        assert result["action"] == "ALLOW"


class TestTrafficGenerator:
    def test_normal_traffic(self):
        gen = TrafficGenerator()
        packets = gen.generate_normal_traffic(50)
        assert len(packets) == 50
        assert all(isinstance(p, Packet) for p in packets)

    def test_attack_traffic(self):
        gen = TrafficGenerator()
        for attack in ["port_scan", "brute_force", "syn_flood", "ot_intrusion", "lateral_movement"]:
            packets = gen.generate_attack_traffic(attack, 10)
            assert len(packets) == 10

    def test_tcp_handshake(self):
        gen = TrafficGenerator()
        packets = gen.generate_tcp_handshake("1.1.1.1", "2.2.2.2", 5000, 80)
        assert len(packets) == 5
        assert "SYN" in packets[0].tcp_flags


if __name__ == "__main__":
    print("Running Firewall Simulator tests...\n")
    test_classes = [TestPacketParser, TestRuleEngine, TestStatefulTracker,
                    TestZoneManager, TestFirewallEngine, TestTrafficGenerator]
    passed = failed = 0
    for cls in test_classes:
        instance = cls()
        print(f"--- {cls.__name__} ---")
        for name in sorted(dir(instance)):
            if name.startswith("test_"):
                try:
                    getattr(instance, name)()
                    print(f"  [PASS] {name}")
                    passed += 1
                except Exception as e:
                    print(f"  [FAIL] {name}: {e}")
                    failed += 1
        print()
    print(f"Results: {passed} passed, {failed} failed")
