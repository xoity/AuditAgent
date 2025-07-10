"""
Tests for audit_agent.core.rules module.
"""

import pytest

from audit_agent.core.objects import IPAddress, IPRange, Zone
from audit_agent.core.rules import (
    Action,
    BaseRule,
    Direction,
    FirewallRule,
    NATRule,
    QoSRule,
    VPNRule,
)


class TestBaseRule:
    """Test cases for BaseRule class."""

    def test_base_rule_creation(self):
        """Test basic rule creation."""
        rule = BaseRule()
        assert rule.id is None
        assert rule.name is None
        assert rule.description is None
        assert rule.enabled is True
        assert rule.priority == 100
        assert rule.tags == []

    def test_base_rule_with_values(self):
        """Test rule creation with values."""
        rule = BaseRule(
            id="test-rule-1",
            name="Test Rule",
            description="A test rule",
            enabled=False,
            priority=50,
        )
        assert rule.id == "test-rule-1"
        assert rule.name == "Test Rule"
        assert rule.description == "A test rule"
        assert rule.enabled is False
        assert rule.priority == 50

    def test_add_tag(self):
        """Test adding tags to a rule."""
        rule = BaseRule()

        result = rule.add_tag("security")
        assert result == rule  # Should return self for chaining
        assert "security" in rule.tags

        # Adding the same tag again should not duplicate
        rule.add_tag("security")
        assert rule.tags.count("security") == 1

        # Adding different tags
        rule.add_tag("production")
        assert "production" in rule.tags
        assert len(rule.tags) == 2


class TestFirewallRule:
    """Test cases for FirewallRule class."""

    def test_firewall_rule_creation(self):
        """Test basic firewall rule creation."""
        rule = FirewallRule()
        assert rule.action == Action.ALLOW
        assert rule.direction == Direction.INBOUND
        assert rule.protocol is None
        assert rule.source_ips == []
        assert rule.destination_ips == []
        assert rule.source_ports == []
        assert rule.destination_ports == []
        assert rule.source_zones == []
        assert rule.destination_zones == []
        assert rule.services == []
        assert rule.log_traffic is False

    def test_firewall_rule_fluent_interface(self):
        """Test the fluent interface for building rules."""
        rule = (
            FirewallRule()
            .allow()
            .inbound()
            .tcp()
            .port(22)
            .from_ip("192.168.1.0/24")
            .to_ip("10.0.0.1")
            .log()
            .priority_high()
        )

        assert rule.action == Action.ALLOW
        assert rule.direction == Direction.INBOUND
        assert rule.protocol is not None
        assert rule.protocol.name == "tcp"
        assert len(rule.destination_ports) == 1
        assert rule.destination_ports[0].number == 22
        assert len(rule.source_ips) == 1
        assert isinstance(rule.source_ips[0], IPRange)
        assert len(rule.destination_ips) == 1
        assert isinstance(rule.destination_ips[0], IPAddress)
        assert rule.log_traffic is True
        assert rule.priority == 10

    def test_action_methods(self):
        """Test action setting methods."""
        rule = FirewallRule()

        # Test allow
        rule.allow()
        assert rule.action == Action.ALLOW

        # Test deny
        rule.deny()
        assert rule.action == Action.DENY

        # Test drop
        rule.drop()
        assert rule.action == Action.DROP

        # Test reject
        rule.reject()
        assert rule.action == Action.REJECT

    def test_direction_methods(self):
        """Test direction setting methods."""
        rule = FirewallRule()

        # Test inbound
        rule.inbound()
        assert rule.direction == Direction.INBOUND

        # Test outbound
        rule.outbound()
        assert rule.direction == Direction.OUTBOUND

        # Test bidirectional
        rule.bidirectional()
        assert rule.direction == Direction.BIDIRECTIONAL

    def test_convenience_methods(self):
        """Test convenience methods for action + direction."""
        rule = FirewallRule()

        # Test allow_inbound
        rule.allow_inbound()
        assert rule.action == Action.ALLOW
        assert rule.direction == Direction.INBOUND

        # Test allow_outbound
        rule.allow_outbound()
        assert rule.action == Action.ALLOW
        assert rule.direction == Direction.OUTBOUND

        # Test deny_inbound
        rule.deny_inbound()
        assert rule.action == Action.DENY
        assert rule.direction == Direction.INBOUND

        # Test deny_outbound
        rule.deny_outbound()
        assert rule.action == Action.DENY
        assert rule.direction == Direction.OUTBOUND

    def test_protocol_methods(self):
        """Test protocol setting methods."""
        rule = FirewallRule()

        # Test TCP
        rule.tcp()
        assert rule.protocol is not None
        assert rule.protocol.name == "tcp"

        # Test UDP
        rule.udp()
        assert rule.protocol is not None
        assert rule.protocol.name == "udp"

        # Test ICMP
        rule.icmp()
        assert rule.protocol is not None
        assert rule.protocol.name == "icmp"

        # Test any protocol
        rule.any_protocol()
        assert rule.protocol is not None
        assert rule.protocol.name == "any"

    def test_ip_methods(self):
        """Test IP address setting methods."""
        rule = FirewallRule()

        # Test from_ip with single IP
        rule.from_ip("192.168.1.1")
        assert len(rule.source_ips) == 1
        assert isinstance(rule.source_ips[0], IPAddress)
        assert rule.source_ips[0].address == "192.168.1.1"

        # Test from_ip with CIDR
        rule.from_ip("10.0.0.0/24")
        assert len(rule.source_ips) == 2
        assert isinstance(rule.source_ips[1], IPRange)
        assert rule.source_ips[1].cidr == "10.0.0.0/24"

        # Test to_ip
        rule.to_ip("192.168.2.1")
        assert len(rule.destination_ips) == 1
        assert isinstance(rule.destination_ips[0], IPAddress)

        # Test from_any and to_any
        rule = FirewallRule()
        rule.from_any()
        assert len(rule.source_ips) == 1
        assert isinstance(rule.source_ips[0], IPRange)
        assert rule.source_ips[0].cidr == "0.0.0.0/0"

        rule.to_any()
        assert len(rule.destination_ips) == 1
        assert isinstance(rule.destination_ips[0], IPRange)
        assert rule.destination_ips[0].cidr == "0.0.0.0/0"

    def test_zone_methods(self):
        """Test zone setting methods."""
        rule = FirewallRule()

        # Test from_zone with string
        rule.from_zone("dmz")
        assert len(rule.source_zones) == 1
        assert isinstance(rule.source_zones[0], Zone)
        assert rule.source_zones[0].name == "dmz"

        # Test from_zone with Zone object
        zone = Zone(name="internal")
        rule.from_zone(zone)
        assert len(rule.source_zones) == 2
        assert rule.source_zones[1] == zone

        # Test to_zone
        rule.to_zone("external")
        assert len(rule.destination_zones) == 1
        assert rule.destination_zones[0].name == "external"

    def test_port_methods(self):
        """Test port setting methods."""
        rule = FirewallRule()

        # Test single port
        rule.port(80)
        assert len(rule.destination_ports) == 1
        assert rule.destination_ports[0].number == 80

        # Test named port
        rule.port("ssh")
        assert len(rule.destination_ports) == 2
        assert rule.destination_ports[1].name == "ssh"

        # Test multiple ports
        rule = FirewallRule()
        rule.ports([80, 443, "ssh"])
        assert len(rule.destination_ports) == 3

        # Test port range
        rule = FirewallRule()
        rule.port_range(8000, 8099)
        assert len(rule.destination_ports) == 1
        assert rule.destination_ports[0].range_start == 8000
        assert rule.destination_ports[0].range_end == 8099

        # Test source port
        rule.source_port(1024)
        assert len(rule.source_ports) == 1
        assert rule.source_ports[0].number == 1024

    def test_service_methods(self):
        """Test service setting methods."""
        rule = FirewallRule()

        # Test predefined service
        rule.service("ssh")
        assert len(rule.services) == 1
        assert rule.services[0].name == "ssh"

        # Test custom service name
        rule.service("custom-service")
        assert len(rule.services) == 2
        assert rule.services[1].name == "custom-service"

    def test_priority_methods(self):
        """Test priority setting methods."""
        rule = FirewallRule()

        # Test high priority
        rule.priority_high()
        assert rule.priority == 10

        # Test low priority
        rule.priority_low()
        assert rule.priority == 1000

        # Test custom priority
        rule.set_priority(500)
        assert rule.priority == 500

    def test_log_method(self):
        """Test logging setting methods."""
        rule = FirewallRule()

        # Test enable logging
        rule.log()
        assert rule.log_traffic is True

        # Test disable logging
        rule.log(False)
        assert rule.log_traffic is False


class TestNATRule:
    """Test cases for NATRule class."""

    def test_nat_rule_creation(self):
        """Test basic NAT rule creation."""
        original_ip = IPAddress(address="192.168.1.1")
        translated_ip = IPAddress(address="10.0.0.1")

        rule = NATRule(
            type="source", original_ip=original_ip, translated_ip=translated_ip
        )

        assert rule.type == "source"
        assert rule.original_ip == original_ip
        assert rule.translated_ip == translated_ip
        assert rule.original_port is None
        assert rule.translated_port is None
        assert rule.protocol is None

    def test_nat_rule_fluent_interface(self):
        """Test NAT rule fluent interface."""
        original_ip = IPAddress(address="192.168.1.1")
        translated_ip = IPAddress(address="10.0.0.1")

        rule = NATRule(
            type="source", original_ip=original_ip, translated_ip=translated_ip
        )

        # Test source NAT
        rule.source_nat()
        assert rule.type == "source"

        # Test destination NAT
        rule.destination_nat()
        assert rule.type == "destination"

        # Test static NAT
        rule.static_nat()
        assert rule.type == "static"


class TestVPNRule:
    """Test cases for VPNRule class."""

    def test_vpn_rule_creation(self):
        """Test basic VPN rule creation."""
        rule = VPNRule(tunnel_type="ipsec")

        assert rule.tunnel_type == "ipsec"
        assert rule.local_networks == []
        assert rule.remote_networks == []
        assert rule.encryption is None
        assert rule.authentication is None

    def test_vpn_rule_fluent_interface(self):
        """Test VPN rule fluent interface."""
        rule = VPNRule(tunnel_type="test")

        # Test IPSec
        rule.ipsec()
        assert rule.tunnel_type == "ipsec"

        # Test SSL VPN
        rule.ssl_vpn()
        assert rule.tunnel_type == "ssl"


class TestQoSRule:
    """Test cases for QoSRule class."""

    def test_qos_rule_creation(self):
        """Test basic QoS rule creation."""
        rule = QoSRule(traffic_class="business-critical")

        assert rule.traffic_class == "business-critical"
        assert rule.bandwidth_limit is None
        assert rule.priority_level == 1
        assert rule.dscp_marking is None

    def test_qos_rule_fluent_interface(self):
        """Test QoS rule fluent interface."""
        rule = QoSRule(traffic_class="web-traffic")

        # Test set bandwidth
        rule.set_bandwidth("100Mbps")
        assert rule.bandwidth_limit == "100Mbps"

        # Test set DSCP
        rule.set_dscp(46)
        assert rule.dscp_marking == 46


class TestActionEnum:
    """Test cases for Action enum."""

    def test_action_values(self):
        """Test Action enum values."""
        assert Action.ALLOW == "allow"
        assert Action.DENY == "deny"
        assert Action.DROP == "drop"
        assert Action.REJECT == "reject"
        assert Action.LOG == "log"


class TestDirectionEnum:
    """Test cases for Direction enum."""

    def test_direction_values(self):
        """Test Direction enum values."""
        assert Direction.INBOUND == "inbound"
        assert Direction.OUTBOUND == "outbound"
        assert Direction.BIDIRECTIONAL == "bidirectional"


if __name__ == "__main__":
    pytest.main([__file__])
