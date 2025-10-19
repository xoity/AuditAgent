"""
Core rule definitions for network security policies.
"""

from enum import Enum
from typing import List, Optional, Union

from pydantic import BaseModel

from .objects import IPAddress, IPRange, Port, Protocol, Service, Zone


class Action(str, Enum):
    """Possible actions for a rule."""

    ALLOW = "allow"
    DENY = "deny"
    DROP = "drop"
    REJECT = "reject"
    LOG = "log"


class Direction(str, Enum):
    """Traffic direction."""

    INBOUND = "inbound"
    OUTBOUND = "outbound"
    BIDIRECTIONAL = "bidirectional"


class BaseRule(BaseModel):
    """Base class for all network rules."""

    id: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: bool = True
    priority: int = 100
    tags: List[str] = []

    def add_tag(self, tag: str) -> "BaseRule":
        """Add a tag to this rule."""
        if tag not in self.tags:
            self.tags.append(tag)
        return self


class FirewallRule(BaseRule):
    """Represents a firewall rule."""

    action: Action = Action.ALLOW
    direction: Direction = Direction.INBOUND
    protocol: Optional[Protocol] = None
    source_ips: List[Union[IPAddress, IPRange]] = []
    destination_ips: List[Union[IPAddress, IPRange]] = []
    source_ports: List[Port] = []
    destination_ports: List[Port] = []
    source_zones: List[Zone] = []
    destination_zones: List[Zone] = []
    services: List[Service] = []
    log_traffic: bool = False

    def allow(self) -> "FirewallRule":
        """Set action to allow."""
        self.action = Action.ALLOW
        return self

    def deny(self) -> "FirewallRule":
        """Set action to deny."""
        self.action = Action.DENY
        return self

    def drop(self) -> "FirewallRule":
        """Set action to drop."""
        self.action = Action.DROP
        return self

    def reject(self) -> "FirewallRule":
        """Set action to reject."""
        self.action = Action.REJECT
        return self

    def inbound(self) -> "FirewallRule":
        """Set direction to inbound."""
        self.direction = Direction.INBOUND
        return self

    def outbound(self) -> "FirewallRule":
        """Set direction to outbound."""
        self.direction = Direction.OUTBOUND
        return self

    def bidirectional(self) -> "FirewallRule":
        """Set direction to bidirectional."""
        self.direction = Direction.BIDIRECTIONAL
        return self

    def allow_inbound(self) -> "FirewallRule":
        """Convenience method for allow + inbound."""
        return self.allow().inbound()

    def allow_outbound(self) -> "FirewallRule":
        """Convenience method for allow + outbound."""
        return self.allow().outbound()

    def deny_inbound(self) -> "FirewallRule":
        """Convenience method for deny + inbound."""
        return self.deny().inbound()

    def deny_outbound(self) -> "FirewallRule":
        """Convenience method for deny + outbound."""
        return self.deny().outbound()

    def tcp(self) -> "FirewallRule":
        """Set protocol to TCP."""
        self.protocol = Protocol.tcp()
        return self

    def udp(self) -> "FirewallRule":
        """Set protocol to UDP."""
        self.protocol = Protocol.udp()
        return self

    def icmp(self) -> "FirewallRule":
        """Set protocol to ICMP."""
        self.protocol = Protocol.icmp()
        return self

    def any_protocol(self) -> "FirewallRule":
        """Set protocol to any."""
        self.protocol = Protocol.any_protocol()
        return self

    def from_ip(self, ip: Union[str, IPAddress, IPRange]) -> "FirewallRule":
        """Add source IP."""
        if isinstance(ip, str):
            # Try to determine if it's a single IP or CIDR
            if "/" in ip:
                ip = IPRange(cidr=ip)
            else:
                ip = IPAddress(address=ip)
        self.source_ips.append(ip)
        return self

    def to_ip(self, ip: Union[str, IPAddress, IPRange]) -> "FirewallRule":
        """Add destination IP."""
        if isinstance(ip, str):
            if "/" in ip:
                ip = IPRange(cidr=ip)
            else:
                ip = IPAddress(address=ip)
        self.destination_ips.append(ip)
        return self

    def from_any(self) -> "FirewallRule":
        """Allow from any source IP."""
        self.source_ips.append(IPRange(cidr="0.0.0.0/0"))
        return self

    def to_any(self) -> "FirewallRule":
        """Allow to any destination IP."""
        self.destination_ips.append(IPRange(cidr="0.0.0.0/0"))
        return self

    def from_zone(self, zone: Union[str, Zone]) -> "FirewallRule":
        """Add source zone."""
        if isinstance(zone, str):
            zone = Zone(name=zone)
        self.source_zones.append(zone)
        return self

    def to_zone(self, zone: Union[str, Zone]) -> "FirewallRule":
        """Add destination zone."""
        if isinstance(zone, str):
            zone = Zone(name=zone)
        self.destination_zones.append(zone)
        return self

    def port(self, port: Union[int, str, Port]) -> "FirewallRule":
        """Add destination port."""
        if isinstance(port, (int, str)):
            if isinstance(port, int):
                port = Port.single(port)
            else:
                port = Port.named(port)
        self.destination_ports.append(port)
        return self

    def ports(self, ports: List[Union[int, str, Port]]) -> "FirewallRule":
        """Add multiple destination ports."""
        for port in ports:
            self.port(port)
        return self

    def source_port(self, port: Union[int, str, Port]) -> "FirewallRule":
        """Add source port."""
        if isinstance(port, (int, str)):
            if isinstance(port, int):
                port = Port.single(port)
            else:
                port = Port.named(port)
        self.source_ports.append(port)
        return self

    def port_range(self, start: int, end: int) -> "FirewallRule":
        """Add destination port range."""
        self.destination_ports.append(Port.range(start, end))
        return self

    def service(self, service: Union[str, Service]) -> "FirewallRule":
        """Add a service."""
        if isinstance(service, str):
            # Map common service names
            service_map = {
                "ssh": Service.ssh(),
                "http": Service.http(),
                "https": Service.https(),
                "dns": Service.dns(),
            }
            if service.lower() in service_map:
                service = service_map[service.lower()]
            else:
                # Create a generic service
                service = Service(
                    name=service, protocol=Protocol.tcp(), ports=[Port.named(service)]
                )
        self.services.append(service)
        return self

    def log(self, enabled: bool = True) -> "FirewallRule":
        """Enable or disable logging for this rule."""
        self.log_traffic = enabled
        return self

    def priority_high(self) -> "FirewallRule":
        """Set high priority (10)."""
        self.priority = 10
        return self

    def priority_low(self) -> "FirewallRule":
        """Set low priority (1000)."""
        self.priority = 1000
        return self

    def set_priority(self, priority: int) -> "FirewallRule":
        """Set custom priority."""
        self.priority = priority
        return self


class NATRule(BaseRule):
    """Represents a NAT (Network Address Translation) rule."""

    type: str  # "source", "destination", "static"
    original_ip: Union[IPAddress, IPRange]
    translated_ip: Union[IPAddress, IPRange]
    original_port: Optional[Port] = None
    translated_port: Optional[Port] = None
    protocol: Optional[Protocol] = None

    def source_nat(self) -> "NATRule":
        """Set as source NAT rule."""
        self.type = "source"
        return self

    def destination_nat(self) -> "NATRule":
        """Set as destination NAT rule."""
        self.type = "destination"
        return self

    def static_nat(self) -> "NATRule":
        """Set as static NAT rule."""
        self.type = "static"
        return self


class VPNRule(BaseRule):
    """Represents a VPN rule or policy."""

    tunnel_type: str  # "ipsec", "ssl", "l2tp", etc.
    local_networks: List[IPRange] = []
    remote_networks: List[IPRange] = []
    encryption: Optional[str] = None
    authentication: Optional[str] = None

    def ipsec(self) -> "VPNRule":
        """Set tunnel type to IPSec."""
        self.tunnel_type = "ipsec"
        return self

    def ssl_vpn(self) -> "VPNRule":
        """Set tunnel type to SSL VPN."""
        self.tunnel_type = "ssl"
        return self


class QoSRule(BaseRule):
    """Represents a Quality of Service rule."""

    traffic_class: str
    bandwidth_limit: Optional[str] = None  # e.g., "100Mbps"
    priority_level: int = 1
    dscp_marking: Optional[int] = None

    def set_bandwidth(self, limit: str) -> "QoSRule":
        """Set bandwidth limit."""
        self.bandwidth_limit = limit
        return self

    def set_dscp(self, dscp: int) -> "QoSRule":
        """Set DSCP marking."""
        self.dscp_marking = dscp
        return self
