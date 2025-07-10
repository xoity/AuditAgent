"""
Tests for audit_agent.core.objects module.
"""

import pytest
from pydantic import ValidationError

from audit_agent.core.objects import IPAddress, IPRange, Port, Protocol, Service, Zone


class TestIPAddress:
    """Test cases for IPAddress class."""

    def test_valid_ip_creation(self):
        """Test creating valid IP addresses."""
        ip = IPAddress(address="192.168.1.1")
        assert ip.address == "192.168.1.1"
        assert str(ip) == "192.168.1.1"

    def test_invalid_ip_creation(self):
        """Test creating invalid IP addresses."""
        with pytest.raises(ValueError, match="Invalid IP address"):
            IPAddress(address="256.256.256.256")

        with pytest.raises(ValueError, match="Invalid IP address"):
            IPAddress(address="not.an.ip.address")

        with pytest.raises(ValueError, match="Invalid IP address"):
            IPAddress(address="192.168.1")


class TestIPRange:
    """Test cases for IPRange class."""

    def test_valid_cidr_creation(self):
        """Test creating valid CIDR ranges."""
        ip_range = IPRange(cidr="192.168.1.0/24")
        assert ip_range.cidr == "192.168.1.0/24"
        assert str(ip_range) == "192.168.1.0/24"

    def test_invalid_cidr_creation(self):
        """Test creating invalid CIDR ranges."""
        with pytest.raises(ValidationError, match="not a valid netmask"):
            IPRange(cidr="192.168.1.0/33")  # Invalid prefix length

        with pytest.raises(ValueError, match="Invalid CIDR notation"):
            IPRange(cidr="256.256.256.0/24")  # Invalid IP

    def test_contains_ip(self):
        """Test checking if IP is within range."""
        ip_range = IPRange(cidr="192.168.1.0/24")

        # Test IP within range
        assert ip_range.contains("192.168.1.1")
        assert ip_range.contains("192.168.1.254")

        # Test IP outside range
        assert not ip_range.contains("192.168.2.1")
        assert not ip_range.contains("10.0.0.1")

        # Test with IPAddress object
        ip_addr = IPAddress(address="192.168.1.100")
        assert ip_range.contains(ip_addr)

    def test_contains_invalid_ip(self):
        """Test contains method with invalid IP."""
        ip_range = IPRange(cidr="192.168.1.0/24")
        assert not ip_range.contains("invalid.ip")


class TestPort:
    """Test cases for Port class."""

    def test_single_port_creation(self):
        """Test creating single ports."""
        port = Port(number=80)
        assert port.number == 80
        assert port.is_single()
        assert not port.is_range()
        assert not port.is_named()
        assert str(port) == "80"

    def test_port_range_creation(self):
        """Test creating port ranges."""
        port = Port(range_start=8000, range_end=8099)
        assert port.range_start == 8000
        assert port.range_end == 8099
        assert port.is_range()
        assert not port.is_single()
        assert not port.is_named()
        assert str(port) == "8000-8099"

    def test_named_port_creation(self):
        """Test creating named ports."""
        port = Port(name="ssh")
        assert port.name == "ssh"
        assert port.is_named()
        assert not port.is_single()
        assert not port.is_range()
        assert str(port) == "ssh"

    def test_class_methods(self):
        """Test Port class creation methods."""
        # Test single port
        port = Port.single(443)
        assert port.number == 443
        assert port.is_single()

        # Test port range
        port = Port.range(1024, 2048)
        assert port.range_start == 1024
        assert port.range_end == 2048
        assert port.is_range()

        # Test named port
        port = Port.named("http")
        assert port.name == "http"
        assert port.is_named()

    def test_invalid_port_numbers(self):
        """Test invalid port number validation."""
        with pytest.raises(ValueError, match="Port number must be between 1 and 65535"):
            Port(number=0)

        with pytest.raises(ValueError, match="Port number must be between 1 and 65535"):
            Port(number=65536)

        with pytest.raises(ValueError, match="Port range must be between 1 and 65535"):
            Port(range_start=0, range_end=100)

        with pytest.raises(ValueError, match="Port range must be between 1 and 65535"):
            Port(range_start=100, range_end=65536)


class TestZone:
    """Test cases for Zone class."""

    def test_zone_creation(self):
        """Test basic zone creation."""
        zone = Zone(name="dmz")
        assert zone.name == "dmz"
        assert zone.description is None
        assert zone.networks == []
        assert str(zone) == "dmz"

    def test_zone_with_description(self):
        """Test zone creation with description."""
        zone = Zone(name="internal", description="Internal network zone")
        assert zone.name == "internal"
        assert zone.description == "Internal network zone"

    def test_valid_zone_names(self):
        """Test valid zone names."""
        valid_names = ["dmz", "internal", "external", "web-tier", "db_tier", "zone123"]

        for name in valid_names:
            zone = Zone(name=name)
            assert zone.name == name

    def test_invalid_zone_names(self):
        """Test invalid zone names."""
        invalid_names = ["zone with spaces", "zone@special", "zone.with.dots"]

        for name in invalid_names:
            with pytest.raises(
                ValueError, match="Zone name must contain only alphanumeric"
            ):
                Zone(name=name)

    def test_add_network(self):
        """Test adding networks to zone."""
        zone = Zone(name="test")

        # Add network as string
        zone.add_network("192.168.1.0/24")
        assert len(zone.networks) == 1
        assert isinstance(zone.networks[0], IPRange)
        assert zone.networks[0].cidr == "192.168.1.0/24"

        # Add network as IPRange object
        ip_range = IPRange(cidr="10.0.0.0/8")
        zone.add_network(ip_range)
        assert len(zone.networks) == 2
        assert zone.networks[1] == ip_range

    def test_contains_ip(self):
        """Test checking if IP is within zone."""
        zone = Zone(name="test")
        zone.add_network("192.168.1.0/24")
        zone.add_network("10.0.0.0/8")

        # Test IP in first network
        assert zone.contains_ip("192.168.1.100")

        # Test IP in second network
        assert zone.contains_ip("10.1.2.3")

        # Test IP not in any network
        assert not zone.contains_ip("172.16.1.1")

        # Test with IPAddress object
        ip_addr = IPAddress(address="192.168.1.50")
        assert zone.contains_ip(ip_addr)


class TestProtocol:
    """Test cases for Protocol class."""

    def test_protocol_creation(self):
        """Test basic protocol creation."""
        protocol = Protocol(name="tcp")
        assert protocol.name == "tcp"
        assert protocol.number is None
        assert str(protocol) == "tcp"

    def test_protocol_with_number(self):
        """Test protocol creation with number."""
        protocol = Protocol(name="tcp", number=6)
        assert protocol.name == "tcp"
        assert protocol.number == 6

    def test_valid_protocol_names(self):
        """Test valid protocol names."""
        valid_protocols = ["tcp", "udp", "icmp", "esp", "ah", "gre", "any"]

        for proto in valid_protocols:
            protocol = Protocol(name=proto)
            assert protocol.name == proto

    def test_numeric_protocols(self):
        """Test numeric protocol values."""
        # Test valid numeric protocol
        protocol = Protocol(name="50")  # ESP protocol number
        assert protocol.name == "50"

        # Test edge cases
        protocol = Protocol(name="0")
        assert protocol.name == "0"

        protocol = Protocol(name="255")
        assert protocol.name == "255"

    def test_invalid_protocol_names(self):
        """Test invalid protocol names."""
        invalid_protocols = ["invalid", "256", "-1", "tcp/udp"]

        for proto in invalid_protocols:
            with pytest.raises(ValueError, match="Invalid protocol"):
                Protocol(name=proto)

    def test_class_methods(self):
        """Test Protocol class creation methods."""
        # Test TCP
        tcp = Protocol.tcp()
        assert tcp.name == "tcp"
        assert tcp.number == 6

        # Test UDP
        udp = Protocol.udp()
        assert udp.name == "udp"
        assert udp.number == 17

        # Test ICMP
        icmp = Protocol.icmp()
        assert icmp.name == "icmp"
        assert icmp.number == 1

        # Test any protocol
        any_proto = Protocol.any_protocol()
        assert any_proto.name == "any"


class TestService:
    """Test cases for Service class."""

    def test_service_creation(self):
        """Test basic service creation."""
        protocol = Protocol.tcp()
        port = Port.single(80)

        service = Service(
            name="web", protocol=protocol, ports=[port], description="Web service"
        )

        assert service.name == "web"
        assert service.protocol == protocol
        assert service.ports == [port]
        assert service.description == "Web service"
        assert str(service) == "web"

    def test_predefined_services(self):
        """Test predefined service creation methods."""
        # Test SSH
        ssh = Service.ssh()
        assert ssh.name == "ssh"
        assert ssh.protocol.name == "tcp"
        assert len(ssh.ports) == 1
        assert ssh.ports[0].number == 22
        assert ssh.description == "Secure Shell"

        # Test HTTP
        http = Service.http()
        assert http.name == "http"
        assert http.protocol.name == "tcp"
        assert ssh.ports[0].number == 22
        assert http.description == "HTTP Web Traffic"

        # Test HTTPS
        https = Service.https()
        assert https.name == "https"
        assert https.protocol.name == "tcp"
        assert len(https.ports) == 1
        assert https.ports[0].number == 443
        assert https.description == "HTTPS Web Traffic"

        # Test DNS
        dns = Service.dns()
        assert dns.name == "dns"
        assert dns.protocol.name == "udp"
        assert len(dns.ports) == 1
        assert dns.ports[0].number == 53
        assert dns.description == "Domain Name System"


if __name__ == "__main__":
    pytest.main([__file__])
